//! A change window's session, as the owner's computer asks for it (ADR 0040 §2, Amendment 2).
//!
//! `obx-fleet-change` is a ceiling for every plan. A window is narrower: the laptop assumes the role for ONE plan and attaches an
//! inline **session policy** built from that plan. IAM grants a session only what the role AND the session policy both allow, so
//! the session can do what the approved plan does and nothing more: the one box (by its `ozbox-box` tag), the one machine type,
//! the one disk size, the one snapshot a clone reads. The same policy ends in an explicit deny after the window's expiry, which
//! is shorter than the session (STS never makes a session shorter than 15 minutes).
//!
//! This module only builds the request. It holds no credential, calls nothing and is pure, so a test can read the rendered
//! policy and evaluate it with the evaluator the role documents are tested with. The session itself is made by the laptop
//! (`aws sts assume-role`, with the owner's own sign-in) and delivered sealed to the box's credential holder; `main` is never in
//! the role's trust.

use ozbox_core::{Operation, Size};
use serde_json::{json, Value};

use crate::{fleet_policy, machine_choice};

/// What a session policy may weigh at most (IAM's inline session policy limit: 2,048 characters without whitespace).
pub const SESSION_POLICY_MAX: usize = 2048;
/// The shortest and longest a window may be. The role's maximum session is one hour; a window is opened for minutes.
pub const MIN_WINDOW_SECS: u32 = 60;
pub const MAX_WINDOW_SECS: u32 = 3600;
/// STS will not make a session shorter than this; the policy's own expiry is what ends a shorter window.
const STS_MIN_SECS: u32 = 900;

/// The session tag the guard compares a disk's box with (`aws:PrincipalTag/ozbox-window-box`, review finding L1).
pub const WINDOW_BOX_TAG: &str = "ozbox-window-box";

/// What the laptop knows when it opens a window for one plan.
#[derive(Debug, Clone)]
pub struct WindowRequest<'a> {
    pub operation: &'a Operation,
    pub account_id: &'a str,
    /// The plan id the dashboard issued (the session is named `plan-<id>`).
    pub plan_id: &'a str,
    /// The owner, for `SourceIdentity = ozbox-<person>`. The laptop sets it, so root on `main` cannot claim to be anyone.
    pub person: &'a str,
    /// Now, in Unix seconds, from the laptop's clock.
    pub now_secs: u64,
    /// How long the window stays open, between [`MIN_WINDOW_SECS`] and [`MAX_WINDOW_SECS`].
    pub window_secs: u32,
    /// The machine type a clone launches (the source box's), which the operation itself does not carry. Create and resize
    /// derive theirs from the size.
    pub machine_type: Option<&'a str>,
}

/// What to pass to `sts:AssumeRole`, and when the window ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowGrant {
    pub role_arn: String,
    pub role_session_name: String,
    pub source_identity: String,
    pub tags: Vec<(String, String)>,
    /// The inline session policy, as compact JSON.
    pub session_policy: String,
    pub duration_secs: u32,
    /// The window's end, in Unix seconds (the policy denies everything after it).
    pub expires_at_secs: u64,
}

fn plain(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A UTC time as `YYYY-MM-DDTHH:MM:SSZ` (the form IAM's date conditions and the tests compare).
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil from days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn tag_eq(key: &str, v: &str) -> Value {
    json!({ "StringEquals": { key: v } })
}

fn merge(mut a: Value, b: Value) -> Value {
    if let (Some(x), Some(y)) = (a.as_object_mut(), b.as_object()) {
        for (op, keys) in y {
            match x.get_mut(op).and_then(Value::as_object_mut) {
                Some(have) => {
                    if let Some(k) = keys.as_object() {
                        for (kk, vv) in k {
                            have.insert(kk.clone(), vv.clone());
                        }
                    }
                }
                None => {
                    x.insert(op.clone(), keys.clone());
                }
            }
        }
    }
    a
}

fn allow(action: &[&str], resource: Value, cond: Value) -> Value {
    json!({ "Effect": "Allow", "Action": action, "Resource": resource, "Condition": cond })
}

/// The session policy for one plan.
fn policy(
    op: &Operation,
    acct: &str,
    expires: u64,
    machine_type: Option<&str>,
) -> Result<(Value, String), String> {
    // The window's box is the session's own tag (`ozbox-window-box`, set by the laptop at assume-role), so a policy variable
    // names it: shorter, and the same word the guard compares a disk's box with.
    let bx = "${aws:PrincipalTag/ozbox-window-box}";
    let on = |b: &str| tag_eq("aws:ResourceTag/ozbox-box", b);
    let made = |b: &str| tag_eq("aws:RequestTag/ozbox-box", b);
    let inst = json!("arn:aws:ec2:*:*:instance/*");
    let vol = json!("arn:aws:ec2:*:*:volume/*");
    let snap = json!("arn:aws:ec2:*::snapshot/*");
    let state = |b: &str| {
        json!([
            format!("arn:aws:s3:::ozbox-tfstate-managed-{acct}/ozbox/boxes/{b}/*"),
            format!("arn:aws:s3:::ozbox-tfstate-managed-{acct}/ozbox/boxes/{b}.tfstate")
        ])
    };
    let mut s: Vec<Value> = vec![allow(
        &["ec2:Describe*", "sts:GetCallerIdentity"],
        json!("*"),
        json!({}),
    )];
    let tagged_at_birth = |b: &str, actions: &[&str]| {
        allow(
            &["ec2:CreateTags"],
            json!("*"),
            merge(
                made(b),
                json!({ "StringEquals": { "ec2:CreateAction": actions } }),
            ),
        )
    };
    let launch = |b: &str, ty: &str, disk: Option<u32>, from: Option<&str>| {
        let mut v = vec![
            allow(
                &["ec2:RunInstances"],
                inst.clone(),
                merge(
                    made(b),
                    json!({ "StringEquals": { "ec2:InstanceType": ty } }),
                ),
            ),
            allow(
                &["ec2:RunInstances"],
                json!([
                    "arn:aws:ec2:*::image/*",
                    "arn:aws:ec2:*:*:subnet/*",
                    "arn:aws:ec2:*:*:security-group/*",
                    "arn:aws:ec2:*:*:network-interface/*"
                ]),
                json!({}),
            ),
            // a create caps the /work disk it makes; the system disk RunInstances makes is bounded by the role's own limit
            match disk {
                Some(d) => allow(
                    &["ec2:CreateVolume"],
                    vol.clone(),
                    merge(
                        made(b),
                        json!({ "NumericLessThanEquals": { "ec2:VolumeSize": d.to_string() } }),
                    ),
                ),
                None => allow(
                    &["ec2:CreateVolume", "ec2:RunInstances"],
                    vol.clone(),
                    made(b),
                ),
            },
            tagged_at_birth(b, &["RunInstances", "CreateVolume"]),
            allow(&["ec2:AttachVolume"], json!("*"), on(b)),
            allow(
                &["iam:PassRole"],
                json!(format!("arn:aws:iam::{acct}:role/obx/obx-pool-*")),
                json!({}),
            ),
            allow(
                &["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                state(b),
                json!({}),
            ),
        ];
        if disk.is_some() {
            v.push(allow(&["ec2:RunInstances"], vol.clone(), made(b)));
        }
        if let Some(f) = from {
            v.push(allow(
                &["ec2:RunInstances", "ec2:CreateVolume"],
                snap.clone(),
                on(f),
            ));
        }
        v
    };
    let snapshot_of = |b: &str| {
        vec![
            allow(&["ec2:CreateSnapshot"], vol.clone(), on(b)),
            allow(&["ec2:CreateSnapshot"], snap.clone(), made(b)),
            tagged_at_birth(b, &["CreateSnapshot"]),
        ]
    };
    match op {
        Operation::Create { spec } => {
            let b = bx;
            let ty = machine_choice(spec.size).map_err(|e| e.to_string())?.machine_type;
            s.extend(launch(b, &ty, Some(spec.work_disk_gb), None));
        }
        Operation::Clone { from, .. } => {
            let ty = machine_type.ok_or("a clone's window needs the machine type of the box it copies")?;
            s.extend(launch(bx, ty, None, Some(from.as_str())));
        }
        Operation::Pause { .. } => {
            s.push(allow(&["ec2:StopInstances"], json!("*"), on(bx)));
        }
        Operation::Resume { .. } => {
            s.push(allow(&["ec2:StartInstances"], json!("*"), on(bx)));
        }
        Operation::Snapshot { .. } => s.extend(snapshot_of(bx)),
        Operation::Resize {
            size,
            work_disk_gb,
            ..
        } => {
            let b = bx;
            if size.is_none() && work_disk_gb.is_none() {
                return Err("that resize changes nothing".into());
            }
            if let Some(sz) = size {
                let ty = machine_choice(*sz).map_err(|e| e.to_string())?.machine_type;
                s.push(allow(
                    &["ec2:StopInstances", "ec2:StartInstances"],
                    inst.clone(),
                    on(b),
                ));
                s.push(allow(
                    &["ec2:ModifyInstanceAttribute"],
                    inst.clone(),
                    merge(on(b), json!({ "StringEquals": { "ec2:Attribute/InstanceType": ty } })),
                ));
            }
            if let Some(d) = work_disk_gb {
                s.push(allow(
                    &["ec2:ModifyVolume"],
                    vol.clone(),
                    merge(
                        on(b),
                        json!({ "NumericLessThanEquals": { "ec2:VolumeSize": d.to_string() } }),
                    ),
                ));
            }
            s.push(allow(
                &["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                state(b),
                json!({}),
            ));
        }
        Operation::Destroy {
            final_snapshot, ..
        } => {
            let b = bx;
            s.push(allow(
                &["ec2:TerminateInstances", "ec2:DeleteVolume", "ec2:DetachVolume"],
                json!("*"),
                on(b),
            ));
            if *final_snapshot {
                s.extend(snapshot_of(b));
            }
            s.push(allow(
                &["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                state(b),
                json!({}),
            ));
        }
        other => {
            return Err(format!(
                "a window is opened for create, resize, pause, resume, snapshot, clone and destroy, not for \"{}\"",
                other.verb()
            ))
        }
    }
    // after the window's expiry nothing is allowed, whatever the role or any statement above says
    s.push(json!({
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": { "DateGreaterThan": { "aws:CurrentTime": rfc3339(expires) } }
    }));
    let doc = json!({ "Version": "2012-10-17", "Statement": s });
    let compact =
        serde_json::to_string(&doc).map_err(|_| "the session policy cannot be written")?;
    let weight = compact.chars().filter(|c| !c.is_whitespace()).count();
    if weight > SESSION_POLICY_MAX {
        return Err(format!(
            "the session policy for this plan is {weight} characters; IAM allows {SESSION_POLICY_MAX}"
        ));
    }
    Ok((doc, compact))
}

/// The box a plan's window is tagged with: the box the plan's disks attach to (the new box for a create or a clone).
pub fn window_box(op: &Operation) -> &str {
    op.box_name().as_str()
}

/// Everything the laptop passes to `sts:AssumeRole` for one plan. Refuses an operation a box's dashboard may not make, and a
/// value that is not a plain name.
pub fn grant(r: &WindowRequest<'_>) -> Result<WindowGrant, String> {
    if r.account_id.len() != 12 || !r.account_id.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the account id is not 12 digits".into());
    }
    // `plan-` and the id are the session name: the role's trust accepts only `plan-*` and the guard reads `*:plan-*`
    if !plain(r.plan_id, 48) {
        return Err("the plan id is not a plain name".into());
    }
    if !plain(r.person, 48) {
        return Err("the person's name is not a plain name".into());
    }
    if !(MIN_WINDOW_SECS..=MAX_WINDOW_SECS).contains(&r.window_secs) {
        return Err(format!(
            "a window lasts between {MIN_WINDOW_SECS} seconds and {MAX_WINDOW_SECS} seconds"
        ));
    }
    if let Some(t) = r.machine_type {
        if !t.contains('.') || !plain(&t.replace('.', "-"), 32) {
            return Err("the machine type is not a plain name".into());
        }
    }
    let expires = r.now_secs + u64::from(r.window_secs);
    let (_, compact) = policy(r.operation, r.account_id, expires, r.machine_type)?;
    Ok(WindowGrant {
        role_arn: format!(
            "arn:aws:iam::{}:role{}{}",
            r.account_id,
            fleet_policy::RESERVED_PATH,
            fleet_policy::CHANGE_ROLE
        ),
        role_session_name: format!("plan-{}", r.plan_id),
        source_identity: format!("ozbox-{}", r.person),
        tags: vec![(
            WINDOW_BOX_TAG.to_string(),
            window_box(r.operation).to_string(),
        )],
        session_policy: compact,
        duration_secs: r.window_secs.max(STS_MIN_SECS),
        expires_at_secs: expires,
    })
}

/// The sizes a size-based plan resolves to, for a caller that wants to tell the person ("m7i.xlarge").
pub fn machine_type_of(size: Size) -> Result<String, String> {
    machine_choice(size)
        .map(|m| m.machine_type)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use ozbox_core::{BoxName, BoxSpec};

    fn req<'a>(op: &'a Operation) -> WindowRequest<'a> {
        WindowRequest {
            operation: op,
            account_id: "123456789012",
            plan_id: "p1",
            person: "owner",
            now_secs: 1_800_000_000,
            window_secs: 1800,
            machine_type: None,
        }
    }

    #[test]
    fn a_time_is_written_the_way_iam_reads_it() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_800_000_000), "2027-01-15T08:00:00Z");
        assert_eq!(rfc3339(951_827_696), "2000-02-29T12:34:56Z");
    }

    #[test]
    fn the_grant_names_the_role_the_session_the_person_and_the_box() {
        let op = Operation::Pause {
            name: BoxName::new("dev").unwrap(),
        };
        let g = grant(&req(&op)).unwrap();
        assert_eq!(
            g.role_arn,
            "arn:aws:iam::123456789012:role/obx/obx-fleet-change"
        );
        assert_eq!(g.role_session_name, "plan-p1");
        assert_eq!(g.source_identity, "ozbox-owner");
        assert_eq!(g.tags, vec![("ozbox-window-box".into(), "dev".into())]);
        assert_eq!(g.duration_secs, 1800);
        assert_eq!(g.expires_at_secs, 1_800_001_800);
    }

    #[test]
    fn a_short_window_is_still_a_session_sts_will_make_and_the_policy_ends_it() {
        let op = Operation::Pause {
            name: BoxName::new("dev").unwrap(),
        };
        let mut r = req(&op);
        r.window_secs = 300;
        let g = grant(&r).unwrap();
        assert_eq!(g.duration_secs, 900);
        assert!(g.session_policy.contains(&rfc3339(g.expires_at_secs)));
    }

    #[test]
    fn what_is_not_a_plain_value_or_not_a_dashboard_change_is_refused() {
        let op = Operation::Pause {
            name: BoxName::new("dev").unwrap(),
        };
        for bad in [
            WindowRequest {
                plan_id: "P1",
                ..req(&op)
            },
            WindowRequest {
                plan_id: "a\"b",
                ..req(&op)
            },
            WindowRequest {
                plan_id: "",
                ..req(&op)
            },
            WindowRequest {
                person: "Own er",
                ..req(&op)
            },
            WindowRequest {
                account_id: "123",
                ..req(&op)
            },
            WindowRequest {
                window_secs: 5,
                ..req(&op)
            },
            WindowRequest {
                window_secs: 7200,
                ..req(&op)
            },
            WindowRequest {
                machine_type: Some("m7i.xlarge\""),
                ..req(&op)
            },
        ] {
            assert!(grant(&bad).is_err(), "{bad:?}");
        }
        let up = Operation::Upgrade {
            name: BoxName::new("dev").unwrap(),
            image: "ami-0123456789abcdef0".into(),
            reprovision: false,
            keep_old_system_disk: false,
        };
        assert!(grant(&req(&up)).is_err());
        let clone = Operation::Clone {
            from: BoxName::new("a").unwrap(),
            to: BoxName::new("b").unwrap(),
            snapshot: None,
        };
        assert!(
            grant(&req(&clone)).is_err(),
            "a clone names its machine type"
        );
    }

    #[test]
    fn every_verbs_policy_fits_the_inline_limit() {
        let n = |s: &str| BoxName::new(s).unwrap();
        let long = "a".repeat(40);
        let ops = vec![
            Operation::Create {
                spec: BoxSpec::new(n(&long), Size::XXL),
            },
            Operation::Clone {
                from: n(&long),
                to: n(&long),
                snapshot: Some("snap-0123456789abcdef0".into()),
            },
            Operation::Resize {
                name: n(&long),
                size: Some(Size::XXL),
                work_disk_gb: Some(500),
            },
            Operation::Destroy {
                name: n(&long),
                final_snapshot: true,
                keep_old_system_disks: false,
            },
            Operation::Snapshot { name: n(&long) },
        ];
        for op in ops {
            let mut r = req(&op);
            r.machine_type = Some("m7i.8xlarge");
            let g = grant(&r).unwrap_or_else(|e| panic!("{}: {e}", op.verb()));
            let w = g
                .session_policy
                .chars()
                .filter(|c| !c.is_whitespace())
                .count();
            assert!(w <= SESSION_POLICY_MAX, "{}: {w}", op.verb());
        }
    }
}
