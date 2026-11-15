//! The access rules, generated from the fleet. Pure: the same fleet and settings give the same document, byte for byte.
//!
//! The shape: the person (the Headscale user) may open SSH (port 22, which a box forwards to its own loopback SSH server)
//! on every box. Boxes have no rule as a source unless the person declared one with `ozbox mesh allow`, so by default a
//! box cannot open a connection to any other box, or to the person's computers. Nothing in the output is a wildcard.

use serde_json::{json, Map, Value};

use super::{box_tag, MeshFile};

/// The port a person reaches a box on. A box forwards it to its own loopback SSH server.
pub const SSH_PORT: u16 = 22;

/// The owner as Headscale writes a user in a policy: `name@`.
pub fn owner(user: &str) -> String {
    if user.contains('@') {
        user.to_string()
    } else {
        format!("{user}@")
    }
}

fn ports(ports: &[u16]) -> String {
    let mut p: Vec<u16> = ports.to_vec();
    p.sort_unstable();
    p.dedup();
    p.iter().map(u16::to_string).collect::<Vec<_>>().join(",")
}

/// The policy for `boxes` (names; any order). An `allow` that names a box that does not exist is an error, never skipped.
pub fn generate(file: &MeshFile, boxes: &[String]) -> Result<Value, &'static str> {
    file.validate()?;
    let mut names: Vec<&str> = boxes.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    for a in &file.allow {
        if !names.contains(&a.from.as_str()) || !names.contains(&a.to.as_str()) {
            return Err("mesh.allow_unknown_box");
        }
    }
    let me = owner(&file.user);
    let mut tag_owners = Map::new();
    let mut acls: Vec<Value> = Vec::new();
    let dsts: Vec<String> = names
        .iter()
        .map(|n| format!("{}:{SSH_PORT}", box_tag(n)))
        .collect();
    for n in &names {
        tag_owners.insert(box_tag(n), json!([me]));
    }
    if !dsts.is_empty() {
        acls.push(json!({ "action": "accept", "src": [me], "dst": dsts }));
    }
    let mut allows: Vec<_> = file.allow.iter().collect();
    allows.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    for a in allows {
        acls.push(json!({
            "action": "accept",
            "src": [box_tag(&a.from)],
            "dst": [format!("{}:{}", box_tag(&a.to), ports(&a.ports))],
        }));
    }
    Ok(json!({ "tagOwners": Value::Object(tag_owners), "acls": acls }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::tests::sample;
    use super::super::Allow;
    use super::*;

    fn fleet() -> Vec<String> {
        vec!["work".into(), "build".into(), "dev".into()]
    }

    #[test]
    fn the_person_reaches_every_box_and_nothing_else_is_a_source() {
        let p = generate(&sample(), &fleet()).unwrap();
        let acls = p["acls"].as_array().unwrap();
        assert_eq!(acls.len(), 1);
        assert_eq!(acls[0]["src"], json!(["alice@"]));
        assert_eq!(
            acls[0]["dst"],
            json!([
                "tag:ozbox-build:22",
                "tag:ozbox-dev:22",
                "tag:ozbox-work:22"
            ])
        );
        assert_eq!(p["tagOwners"]["tag:ozbox-dev"], json!(["alice@"]));
    }

    #[test]
    fn no_box_is_a_source_unless_declared_and_there_is_no_wildcard() {
        let text = serde_json::to_string(&generate(&sample(), &fleet()).unwrap()).unwrap();
        assert!(!text.contains("\"*\""));
        assert!(!text.contains("autogroup"));
        assert!(!text.contains("\"src\":[\"tag:"));
        let mut f = sample();
        f.allow.push(Allow {
            from: "build".into(),
            to: "work".into(),
            ports: vec![5432, 22, 22],
        });
        let p = generate(&f, &fleet()).unwrap();
        let acls = p["acls"].as_array().unwrap();
        assert_eq!(acls.len(), 2);
        assert_eq!(acls[1]["src"], json!(["tag:ozbox-build"]));
        assert_eq!(acls[1]["dst"], json!(["tag:ozbox-work:22,5432"]));
        // and the reverse direction was not granted
        assert!(!serde_json::to_string(&p)
            .unwrap()
            .contains("\"src\":[\"tag:ozbox-work\"]"));
    }

    #[test]
    fn it_is_deterministic_whatever_the_order() {
        let mut f = sample();
        f.allow = vec![
            Allow {
                from: "work".into(),
                to: "dev".into(),
                ports: vec![80],
            },
            Allow {
                from: "build".into(),
                to: "dev".into(),
                ports: vec![80],
            },
        ];
        let a = generate(&f, &fleet()).unwrap();
        f.allow.reverse();
        let mut rev = fleet();
        rev.reverse();
        assert_eq!(a, generate(&f, &rev).unwrap());
    }

    #[test]
    fn an_allow_for_a_box_that_does_not_exist_is_an_error() {
        let mut f = sample();
        f.allow.push(Allow {
            from: "build".into(),
            to: "ghost".into(),
            ports: vec![22],
        });
        assert_eq!(generate(&f, &fleet()), Err("mesh.allow_unknown_box"));
    }

    #[test]
    fn an_empty_fleet_grants_nothing() {
        let p = generate(&sample(), &[]).unwrap();
        assert_eq!(p["acls"], json!([]));
    }

    #[test]
    fn a_user_that_is_an_email_is_kept_as_it_is() {
        assert_eq!(owner("a@example.com"), "a@example.com");
        assert_eq!(owner("alice"), "alice@");
    }
}
