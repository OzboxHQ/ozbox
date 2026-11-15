//! What the model may see of a page. A password or a field marked secret is never read at all, and text that
//! looks like a card number or a national ID is replaced before it can reach a snapshot, a recording or a result.

pub const MASKED: &str = "[masked]";

/// An input is secret when its type, name or autocomplete hint says so. The page's own markup decides: a site that calls its
/// field `password` or `cc-number` has told us what it is.
pub fn is_secret_field(
    input_type: &str,
    name: &str,
    autocomplete: &str,
    marked_secret: bool,
) -> bool {
    if marked_secret {
        return true;
    }
    let t = input_type.to_ascii_lowercase();
    if t == "password" {
        return true;
    }
    let ac = autocomplete.to_ascii_lowercase();
    if ac.contains("password")
        || ac.contains("one-time-code")
        || ac.starts_with("cc-")
        || ac.contains(" cc-")
    {
        return true;
    }
    let n = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "passcode",
        "secret",
        "token",
        "otp",
        "cvv",
        "cvc",
        "cardnumber",
        "card_number",
        "card-number",
        "ccnum",
        "cc_number",
        "ssn",
        "pin",
    ]
    .iter()
    .any(|k| {
        if *k == "pin" || *k == "otp" {
            // short words only count as a whole word, so `spinner` and `hotpath` are not secret
            n.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w == *k)
        } else {
            n.contains(k)
        }
    })
}

/// What to show for a field's value: the value, unless the field is secret or the value looks sensitive.
pub fn show_value(secret: bool, value: &str) -> String {
    if secret {
        if value.is_empty() {
            String::new()
        } else {
            MASKED.to_string()
        }
    } else {
        mask_text(value)
    }
}

fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = u32::from(*d - b'0');
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Replace card numbers (13 to 19 digits that pass the Luhn check, with single spaces or dashes between groups), dashed
/// US social security numbers, and the digits after a label such as "national id" or "bvn".
pub fn mask_text(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            // a run of digits, groups joined by one space or dash
            let mut j = i;
            let mut digits: Vec<u8> = Vec::new();
            let mut dashed = Vec::new();
            let mut group = 0usize;
            while j < b.len() {
                if b[j].is_ascii_digit() {
                    digits.push(b[j] as u8);
                    group += 1;
                    j += 1;
                } else if (b[j] == ' ' || b[j] == '-')
                    && group > 0
                    && b.get(j + 1).is_some_and(char::is_ascii_digit)
                {
                    dashed.push(group);
                    group = 0;
                    j += 1;
                } else {
                    break;
                }
            }
            dashed.push(group);
            let ends_clean = j == b.len() || !b[j].is_ascii_alphanumeric();
            let card = (13..=19).contains(&digits.len()) && luhn(&digits);
            let ssn = dashed == [3, 2, 4] && b[i..j].contains(&'-');
            if ends_clean && (card || ssn) {
                out.push_str(MASKED);
                i = j;
                continue;
            }
            // not sensitive: copy the run as written
            out.extend(&b[i..j]);
            i = j;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    mask_labelled_ids(&out)
}

fn mask_labelled_ids(text: &str) -> String {
    const LABELS: [&str; 6] = [
        "ssn",
        "national id",
        "national insurance",
        "nin",
        "bvn",
        "passport",
    ];
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    'outer: while i < bytes.len() {
        for l in LABELS {
            if lower[i..].starts_with(l)
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
                && !lower[i + l.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
            {
                // label, optional "number"/"no", then a separator, then a token of digits and letters
                let k = i + l.len();
                let rest = &lower[k..];
                let skip: usize = rest
                    .char_indices()
                    .find(|(_, c)| !(c.is_whitespace() || matches!(c, ':' | '#' | '=' | '.')))
                    .map_or(rest.len(), |(n, _)| n);
                let mut after = &text[k + skip..];
                for word in ["number", "no", "num"] {
                    if after.to_ascii_lowercase().starts_with(word) {
                        after = &after[word.len()..];
                        break;
                    }
                }
                let after = after.trim_start_matches(|c: char| {
                    c.is_whitespace() || matches!(c, ':' | '#' | '=' | '.')
                });
                let tok: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                if tok.len() >= 6 && tok.chars().any(|c| c.is_ascii_digit()) {
                    let consumed = text.len() - after.len() + tok.len();
                    out.push_str(&text[i..text.len() - after.len()]);
                    out.push_str(MASKED);
                    i = consumed;
                    continue 'outer;
                }
            }
        }
        let ch_len = text[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&text[i..i + ch_len]);
        i += ch_len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_fields_are_found_by_type_name_hint_or_mark() {
        assert!(is_secret_field("password", "x", "", false));
        assert!(is_secret_field("text", "user_password", "", false));
        assert!(is_secret_field("text", "x", "cc-number", false));
        assert!(is_secret_field("text", "x", "one-time-code", false));
        assert!(is_secret_field("text", "cvv", "", false));
        assert!(is_secret_field("text", "pin", "", false));
        assert!(is_secret_field("text", "anything", "", true));
        assert!(!is_secret_field("text", "spinner", "", false));
        assert!(!is_secret_field("text", "username", "username", false));
        assert!(!is_secret_field("email", "email", "email", false));
    }

    #[test]
    fn a_secret_value_is_never_shown() {
        assert_eq!(show_value(true, "SENTINEL-abc"), MASKED);
        assert_eq!(show_value(true, ""), "");
        assert_eq!(show_value(false, "hello"), "hello");
    }

    #[test]
    fn card_numbers_that_pass_luhn_are_masked_in_any_grouping() {
        for n in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "378282246310005",
        ] {
            let t = format!("card {n} on file");
            let m = mask_text(&t);
            assert_eq!(m, format!("card {MASKED} on file"), "{n}");
        }
    }

    #[test]
    fn ordinary_numbers_are_left_alone() {
        for t in [
            "order 1234567890123 shipped",
            "call 555 123 4567",
            "total 4111111111111112",
            "12 34 56",
            "ref A4111111111111111",
        ] {
            assert_eq!(mask_text(t), t, "{t}");
        }
    }

    #[test]
    fn dashed_social_security_numbers_and_labelled_ids_are_masked() {
        assert_eq!(mask_text("ssn 123-45-6789."), format!("ssn {MASKED}."));
        assert_eq!(mask_text("123-45-6789"), MASKED);
        assert_eq!(
            mask_text("National ID: AB123456C ok"),
            format!("National ID: {MASKED} ok")
        );
        assert_eq!(mask_text("BVN 22334455667"), format!("BVN {MASKED}"));
        assert_eq!(
            mask_text("NIN number: 12345678901"),
            format!("NIN number: {MASKED}")
        );
        // a label with nothing sensitive after it is not touched
        assert_eq!(
            mask_text("Passport photos accepted"),
            "Passport photos accepted"
        );
        assert_eq!(mask_text("running"), "running");
    }

    #[test]
    fn unicode_text_survives() {
        assert_eq!(
            mask_text("café – 4111111111111111 – ünïcode"),
            format!("café – {MASKED} – ünïcode")
        );
    }
}
