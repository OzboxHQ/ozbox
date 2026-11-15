//! Structured results: a small JSON-schema checker, and extraction that follows the schema.
//!
//! The schema is the contract between the person and the agent. Supported keywords: `type` (a name or a list), `properties`,
//! `required`, `additionalProperties: false`, `items`, `enum`, `minLength`, `maxLength`, `minimum`, `maximum`, `minItems`,
//! `maxItems`, `pattern` is not supported (it is refused, not ignored). Extraction adds three keywords a person can write
//! beside them: `x-selector` (a CSS selector), `x-attr` (read an attribute instead of the text) and, on an array, the
//! selector of each row, with the row's properties selecting inside it.

use serde_json::{json, Map, Value};

use crate::mask;

const MAX_DEPTH: usize = 12;

pub fn check_schema(schema: &Value) -> Result<(), String> {
    fn walk(s: &Value, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("the schema is nested too deeply".into());
        }
        let Some(o) = s.as_object() else {
            return Err("a schema is an object".into());
        };
        for k in o.keys() {
            if !matches!(
                k.as_str(),
                "type"
                    | "properties"
                    | "required"
                    | "additionalProperties"
                    | "items"
                    | "enum"
                    | "minLength"
                    | "maxLength"
                    | "minimum"
                    | "maximum"
                    | "minItems"
                    | "maxItems"
                    | "description"
                    | "title"
                    | "x-selector"
                    | "x-attr"
                    | "default"
                    | "$schema"
            ) {
                return Err(format!("the schema keyword {k} is not supported"));
            }
        }
        if let Some(p) = o.get("properties") {
            for v in p.as_object().ok_or("properties is an object")?.values() {
                walk(v, depth + 1)?;
            }
        }
        if let Some(i) = o.get("items") {
            walk(i, depth + 1)?;
        }
        Ok(())
    }
    walk(schema, 0)
}

fn type_names(s: &Value) -> Vec<String> {
    match s.get("type") {
        Some(Value::String(t)) => vec![t.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

fn type_ok(t: &str, v: &Value) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64() || v.as_f64().is_some_and(|f| f.fract() == 0.0),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        _ => false,
    }
}

/// Every problem found, each with the path to it. Empty means the data fits.
pub fn validate(schema: &Value, data: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    check(schema, data, "$", &mut errs, 0);
    errs
}

fn check(s: &Value, d: &Value, path: &str, errs: &mut Vec<String>, depth: usize) {
    if depth > MAX_DEPTH {
        errs.push(format!("{path}: too deeply nested"));
        return;
    }
    let types = type_names(s);
    if !types.is_empty() && !types.iter().any(|t| type_ok(t, d)) {
        errs.push(format!("{path}: expected {}", types.join(" or ")));
        return;
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.contains(d) {
            errs.push(format!("{path}: not one of the allowed values"));
        }
    }
    if let Some(t) = d.as_str() {
        let n = t.chars().count() as u64;
        if s.get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n < m)
        {
            errs.push(format!("{path}: shorter than {}", s["minLength"]));
        }
        if s.get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n > m)
        {
            errs.push(format!("{path}: longer than {}", s["maxLength"]));
        }
    }
    if let Some(n) = d.as_f64() {
        if s.get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|m| n < m)
        {
            errs.push(format!("{path}: below {}", s["minimum"]));
        }
        if s.get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|m| n > m)
        {
            errs.push(format!("{path}: above {}", s["maximum"]));
        }
    }
    if let (Some(o), Some(props)) = (
        d.as_object(),
        s.get("properties").and_then(Value::as_object),
    ) {
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for r in req.iter().filter_map(Value::as_str) {
                if !o.contains_key(r) {
                    errs.push(format!("{path}.{r}: required"));
                }
            }
        }
        for (k, v) in o {
            match props.get(k) {
                Some(ps) => check(ps, v, &format!("{path}.{k}"), errs, depth + 1),
                None if s.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    errs.push(format!("{path}.{k}: not in the schema"));
                }
                None => {}
            }
        }
    }
    if let Some(a) = d.as_array() {
        if s.get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| (a.len() as u64) < m)
        {
            errs.push(format!("{path}: fewer than {} items", s["minItems"]));
        }
        if s.get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| (a.len() as u64) > m)
        {
            errs.push(format!("{path}: more than {} items", s["maxItems"]));
        }
        if let Some(is) = s.get("items") {
            for (i, v) in a.iter().enumerate() {
                check(is, v, &format!("{path}[{i}]"), errs, depth + 1);
            }
        }
    }
}

/// The selectors the page script should read, as the schema describes them, so the script is one generic function and the
/// schema is the only input. Returns the schema reduced to what the script needs.
pub fn extraction_plan(schema: &Value) -> Value {
    fn plan(s: &Value) -> Value {
        let mut o = Map::new();
        for k in ["x-selector", "x-attr"] {
            if let Some(v) = s.get(k) {
                o.insert(k.into(), v.clone());
            }
        }
        let t = type_names(s);
        o.insert("type".into(), json!(t.first().cloned().unwrap_or_default()));
        if let Some(p) = s.get("properties").and_then(Value::as_object) {
            o.insert(
                "properties".into(),
                Value::Object(p.iter().map(|(k, v)| (k.clone(), plan(v))).collect()),
            );
        }
        if let Some(i) = s.get("items") {
            o.insert("items".into(), plan(i));
        }
        Value::Object(o)
    }
    plan(schema)
}

/// Turn the page script's raw text into what the schema asks for, mask anything sensitive, then validate.
pub fn coerce(schema: &Value, raw: &Value) -> Value {
    let types = type_names(schema);
    let first = types.first().map(String::as_str).unwrap_or("");
    match (first, raw) {
        ("object", Value::Object(r)) => {
            let props = schema.get("properties").and_then(Value::as_object);
            let mut out = Map::new();
            if let Some(props) = props {
                for (k, ps) in props {
                    if let Some(v) = r.get(k) {
                        out.insert(k.clone(), coerce(ps, v));
                    }
                }
            }
            Value::Object(out)
        }
        ("array", Value::Array(a)) => {
            let item = schema.get("items").cloned().unwrap_or(Value::Null);
            Value::Array(a.iter().map(|v| coerce(&item, v)).collect())
        }
        ("integer", Value::String(t)) => number(t).map_or(Value::Null, |n| {
            if n.fract() == 0.0 {
                json!(n as i64)
            } else {
                Value::Null
            }
        }),
        ("number", Value::String(t)) => number(t).map_or(Value::Null, |n| json!(n)),
        ("boolean", Value::String(t)) => match t.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" | "on" | "checked" => json!(true),
            "false" | "no" | "0" | "off" | "" => json!(false),
            _ => Value::Null,
        },
        (_, Value::String(t)) => Value::String(mask::mask_text(t.trim())),
        _ => raw.clone(),
    }
}

/// "$1,234.50", "1 234,5 €" and "(12)" are numbers. Anything with letters left over is not.
pub fn number(t: &str) -> Option<f64> {
    let t = t.trim();
    let neg =
        t.starts_with('(') && t.ends_with(')') || t.starts_with('-') || t.starts_with('\u{2212}');
    let mut digits = String::new();
    let mut seen_digit = false;
    for c in t.chars() {
        match c {
            '0'..='9' => {
                digits.push(c);
                seen_digit = true;
            }
            '.' => digits.push('.'),
            ',' | ' ' | '\u{a0}' | '(' | ')' | '-' | '\u{2212}' | '+' => {}
            '$' | '€' | '£' | '¥' | '₦' | '₵' | '%' => {}
            _ if c.is_alphabetic() && !seen_digit => {}
            _ => return None,
        }
    }
    if digits.matches('.').count() > 1 {
        return None;
    }
    let n: f64 = digits.parse().ok()?;
    Some(if neg { -n } else { n })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn product_schema() -> Value {
        json!({
            "type": "object",
            "required": ["title", "price"],
            "additionalProperties": false,
            "properties": {
                "title": { "type": "string", "x-selector": "h1", "minLength": 1 },
                "price": { "type": "number", "x-selector": ".price", "minimum": 0 },
                "tags": { "type": "array", "x-selector": ".tag", "items": { "type": "string" } }
            }
        })
    }

    #[test]
    fn data_that_fits_the_schema_has_no_errors() {
        let d = json!({ "title": "Mug", "price": 12.5, "tags": ["a", "b"] });
        assert!(validate(&product_schema(), &d).is_empty());
    }

    #[test]
    fn every_kind_of_mismatch_is_reported_with_its_path() {
        let s = product_schema();
        assert_eq!(
            validate(&s, &json!({ "title": "x" })),
            vec!["$.price: required"]
        );
        assert_eq!(
            validate(&s, &json!({ "title": "x", "price": "12" })),
            vec!["$.price: expected number"]
        );
        assert_eq!(
            validate(&s, &json!({ "title": "", "price": 1 })),
            vec!["$.title: shorter than 1"]
        );
        assert_eq!(
            validate(&s, &json!({ "title": "x", "price": -1 })),
            vec!["$.price: below 0"]
        );
        assert_eq!(
            validate(&s, &json!({ "title": "x", "price": 1, "extra": 1 })),
            vec!["$.extra: not in the schema"]
        );
        assert_eq!(
            validate(&s, &json!({ "title": "x", "price": 1, "tags": [1] })),
            vec!["$.tags[0]: expected string"]
        );
        assert_eq!(
            validate(&json!({ "enum": ["a"] }), &json!("b")),
            vec!["$: not one of the allowed values"]
        );
        assert_eq!(
            validate(&json!({ "type": ["string", "null"] }), &Value::Null),
            Vec::<String>::new()
        );
        assert_eq!(
            validate(&json!({ "type": "integer" }), &json!(2.5)),
            vec!["$: expected integer"]
        );
        assert_eq!(
            validate(&json!({ "type": "array", "minItems": 2 }), &json!([1])),
            vec!["$: fewer than 2 items"]
        );
    }

    #[test]
    fn a_keyword_that_is_not_supported_is_refused_not_ignored() {
        assert!(check_schema(&product_schema()).is_ok());
        assert!(check_schema(&json!({ "type": "string", "pattern": "^a" })).is_err());
        assert!(check_schema(&json!("nope")).is_err());
        let mut deep = json!({ "type": "string" });
        for _ in 0..20 {
            deep = json!({ "type": "object", "properties": { "a": deep } });
        }
        assert!(check_schema(&deep).is_err());
    }

    #[test]
    fn numbers_are_read_from_prices_and_refused_when_they_are_not_numbers() {
        assert_eq!(number("$1,234.50"), Some(1234.5));
        assert_eq!(number("€ 12"), Some(12.0));
        assert_eq!(number("(12)"), Some(-12.0));
        assert_eq!(number("USD 3.99"), Some(3.99));
        assert_eq!(number("12 apples"), None);
        assert_eq!(number("1.2.3"), None);
        assert_eq!(number(""), None);
    }

    #[test]
    fn raw_page_text_becomes_typed_data_and_sensitive_text_is_masked() {
        let s = product_schema();
        let raw = json!({ "title": " Mug  ", "price": "$12.50", "tags": ["a", "b"] });
        let d = coerce(&s, &raw);
        assert_eq!(
            d,
            json!({ "title": "Mug", "price": 12.5, "tags": ["a", "b"] })
        );
        assert!(validate(&s, &d).is_empty());
        let raw = json!({ "title": "pay with 4111 1111 1111 1111", "price": "free" });
        let d = coerce(&s, &raw);
        assert_eq!(d["title"], json!(format!("pay with {}", mask::MASKED)));
        // a price that is not a number becomes null and then fails validation, rather than passing as text
        assert_eq!(d["price"], Value::Null);
        assert!(!validate(&s, &d).is_empty());
    }

    #[test]
    fn the_extraction_plan_keeps_only_selectors_and_types() {
        let p = extraction_plan(&product_schema());
        assert_eq!(p["properties"]["price"]["x-selector"], ".price");
        assert_eq!(p["properties"]["price"]["type"], "number");
        assert!(p["properties"]["price"].get("minimum").is_none());
    }
}
