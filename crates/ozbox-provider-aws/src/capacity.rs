//! The vCPU quota check. EC2 refuses to start an instance that would take the account past its per-family
//! "Running On-Demand ... instances" vCPU quota, and by then a resize has already stopped the box. So while planning,
//! read the quota and the vCPUs in use and refuse early with the numbers, before anything stops.

use std::collections::{BTreeMap, BTreeSet};

use ozbox_core::{CapacityRequest, Error, Result};
use serde::Deserialize;

use crate::{AwsBackend, PROVIDER_ID};

/// An instance family group that shares one vCPU quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaFamily {
    pub code: &'static str,
    pub label: &'static str,
}

pub const STANDARD: QuotaFamily = QuotaFamily {
    code: "L-1216C47A",
    label: "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances",
};
pub const G_VT: QuotaFamily = QuotaFamily {
    code: "L-DB2E81BA",
    label: "Running On-Demand G and VT instances",
};
pub const P: QuotaFamily = QuotaFamily {
    code: "L-417A185B",
    label: "Running On-Demand P instances",
};
pub const X: QuotaFamily = QuotaFamily {
    code: "L-7295265B",
    label: "Running On-Demand X instances",
};

/// The quota an instance type counts against, from its family letters (`m7i.xlarge` -> `m`). `None` for a family
/// without a mapping here: the plan then says it did not check, never guesses.
pub fn family_of(machine_type: &str) -> Option<QuotaFamily> {
    let name = machine_type.split('.').next()?;
    let letters: String = name
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect::<String>()
        .to_ascii_lowercase();
    match letters.as_str() {
        "a" | "c" | "d" | "h" | "i" | "m" | "r" | "t" | "z" => Some(STANDARD),
        "g" | "vt" => Some(G_VT),
        "p" => Some(P),
        "x" => Some(X),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct QuotaDoc {
    quota: QuotaBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct QuotaBody {
    value: f64,
}

pub fn parse_quota(json: &str) -> Option<f64> {
    serde_json::from_str::<QuotaDoc>(json)
        .ok()
        .map(|d| d.quota.value)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Running {
    #[serde(default)]
    reservations: Vec<Reservation>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Reservation {
    #[serde(default)]
    instances: Vec<RunningInstance>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RunningInstance {
    instance_type: String,
    #[serde(default)]
    state: Option<StateName>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StateName {
    name: String,
}

/// Instance counts per machine type for instances that hold vCPUs (pending or running).
pub fn parse_running_types(json: &str) -> Option<BTreeMap<String, u32>> {
    let doc: Running = serde_json::from_str(json).ok()?;
    let mut out = BTreeMap::new();
    for i in doc.reservations.into_iter().flat_map(|r| r.instances) {
        let counts = i
            .state
            .as_ref()
            .is_none_or(|s| matches!(s.name.as_str(), "pending" | "running"));
        if counts {
            *out.entry(i.instance_type).or_insert(0) += 1;
        }
    }
    Some(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Types {
    #[serde(default)]
    instance_types: Vec<TypeInfo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TypeInfo {
    instance_type: String,
    v_cpu_info: VCpuInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VCpuInfo {
    default_v_cpus: u32,
}

pub fn parse_vcpus(json: &str) -> Option<BTreeMap<String, u32>> {
    let doc: Types = serde_json::from_str(json).ok()?;
    Some(
        doc.instance_types
            .into_iter()
            .map(|t| (t.instance_type, t.v_cpu_info.default_v_cpus))
            .collect(),
    )
}

/// The numbers a decision is made from.
#[derive(Debug, Clone, PartialEq)]
pub struct Figures {
    pub quota: f64,
    /// vCPUs in use by instances in the same quota family.
    pub used: u32,
    /// vCPUs the plan frees by stopping this box first.
    pub freed: u32,
    /// vCPUs the box needs to start.
    pub needed: u32,
}

/// Does it fit? `Err(message)` is the refusal, naming every number and how to raise the quota.
pub fn decide(
    fam: QuotaFamily,
    machine_type: &str,
    region: Option<&str>,
    f: &Figures,
) -> std::result::Result<(), String> {
    let in_use_after = f64::from(f.used.saturating_sub(f.freed)) + f64::from(f.needed);
    if in_use_after <= f.quota {
        return Ok(());
    }
    let short = in_use_after - f.quota;
    let region_flag = region.map(|r| format!(" --region {r}")).unwrap_or_default();
    let freed = if f.freed > 0 {
        format!(", {} of them freed by stopping this box first", f.freed)
    } else {
        String::new()
    };
    Err(format!(
        "the quota \"{label}\"{where_} is {quota} vCPUs and {used} are in use{freed}; {machine_type} needs {needed} \
         vCPUs, which is {short} over. Nothing was stopped. Raise the quota first: `aws service-quotas \
         request-service-quota-increase --service-code ec2 --quota-code {code} --desired-value {want}{region_flag}` \
         (or Service Quotas in the console), or stop another box, or pick a smaller size.",
        label = fam.label,
        where_ = region.map(|r| format!(" in {r}")).unwrap_or_default(),
        quota = f.quota,
        used = f.used,
        needed = f.needed,
        short = short,
        code = fam.code,
        want = in_use_after.ceil(),
    ))
}

impl AwsBackend {
    /// The plan-time capacity check. Refuses with `Error::Unsupported` when the box would not fit; when the quota or
    /// the usage cannot be read (a permission the operator lacks, say) it returns a note instead of failing.
    pub(crate) fn vcpu_capacity(&self, req: &CapacityRequest) -> Result<Vec<String>> {
        let Some(fam) = family_of(&req.machine_type) else {
            return Ok(vec![format!(
                "The vCPU quota for {} was not checked (no quota mapping for that family).",
                req.machine_type
            )]);
        };
        let region = req.region.as_deref().or(self.cfg.region.as_deref());
        let unchecked = |why: &str| {
            Ok(vec![format!(
                "Could not check the vCPU quota ({why}). If the start is refused with VcpuLimitExceeded, \
                 the box stays stopped and `ozbox resume` finishes it once the quota is raised."
            )])
        };
        let s = self.at(region);

        let quota = match s
            .run(&[
                "service-quotas",
                "get-service-quota",
                "--service-code",
                "ec2",
                "--quota-code",
                fam.code,
            ])
            .ok()
            .and_then(|o| parse_quota(&o.stdout))
        {
            Some(q) => q,
            None => return unchecked("the Service Quotas read was denied or failed"),
        };
        let running = match s
            .run(&[
                "ec2",
                "describe-instances",
                "--filters",
                "Name=instance-state-name,Values=pending,running",
            ])
            .ok()
            .and_then(|o| parse_running_types(&o.stdout))
        {
            Some(r) => r,
            None => return unchecked("the running instances could not be listed"),
        };

        let mut wanted: BTreeSet<String> = running.keys().cloned().collect();
        wanted.insert(req.machine_type.clone());
        if let Some(f) = &req.freed_machine_type {
            wanted.insert(f.clone());
        }
        let mut vcpus = BTreeMap::new();
        let all: Vec<String> = wanted.into_iter().collect();
        for chunk in all.chunks(50) {
            let mut args = vec!["ec2", "describe-instance-types", "--instance-types"];
            args.extend(chunk.iter().map(String::as_str));
            match s.run(&args).ok().and_then(|o| parse_vcpus(&o.stdout)) {
                Some(m) => vcpus.extend(m),
                None => return unchecked("instance type sizes could not be read"),
            }
        }
        let count = |t: &str| vcpus.get(t).copied();
        let Some(needed) = count(&req.machine_type) else {
            return unchecked("the machine type's vCPU count is unknown");
        };
        let mut used = 0u32;
        for (t, n) in &running {
            if family_of(t) == Some(fam) {
                let Some(v) = count(t) else {
                    return unchecked("instance type sizes could not be read");
                };
                used = used.saturating_add(v.saturating_mul(*n));
            }
        }
        let freed = req
            .freed_machine_type
            .as_deref()
            .filter(|t| family_of(t) == Some(fam))
            .and_then(count)
            .unwrap_or(0);
        let figures = Figures {
            quota,
            used,
            freed,
            needed,
        };
        decide(fam, &req.machine_type, region, &figures).map_err(|why| Error::Unsupported {
            provider: PROVIDER_ID.into(),
            what: format!("start a {} box ({needed} vCPUs)", req.machine_type),
            why,
        })?;
        Ok(Vec::new())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::AwsConfig;
    use ozbox_core::{Output, RecordingRunner};
    use std::sync::Arc;

    fn out(s: &str) -> Output {
        Output {
            status: Some(0),
            stdout: s.into(),
            stderr: String::new(),
        }
    }

    fn denied() -> Output {
        Output {
            status: Some(254),
            stdout: String::new(),
            stderr: "AccessDeniedException".into(),
        }
    }

    fn backend(r: &Arc<RecordingRunner>) -> AwsBackend {
        AwsBackend::with_env_none(
            r.clone(),
            AwsConfig {
                region: Some("us-east-1".into()),
                ..AwsConfig::default()
            },
        )
    }

    fn quota(v: f64) -> Output {
        out(&format!(
            r#"{{"Quota":{{"QuotaCode":"L-1216C47A","Value":{v}}}}}"#
        ))
    }

    fn instances(types: &[(&str, &str)]) -> Output {
        let list: Vec<String> = types
            .iter()
            .map(|(t, s)| format!(r#"{{"InstanceType":"{t}","State":{{"Name":"{s}"}}}}"#))
            .collect();
        out(&format!(
            r#"{{"Reservations":[{{"Instances":[{}]}}]}}"#,
            list.join(",")
        ))
    }

    fn types(list: &[(&str, u32)]) -> Output {
        let items: Vec<String> = list
            .iter()
            .map(|(t, v)| format!(r#"{{"InstanceType":"{t}","VCpuInfo":{{"DefaultVCpus":{v}}}}}"#))
            .collect();
        out(&format!(r#"{{"InstanceTypes":[{}]}}"#, items.join(",")))
    }

    fn req(target: &str, freed: Option<&str>) -> CapacityRequest {
        CapacityRequest {
            machine_type: target.into(),
            freed_machine_type: freed.map(String::from),
            region: Some("us-east-1".into()),
        }
    }

    #[test]
    fn families_map_to_their_quota_codes() {
        assert_eq!(family_of("m7i.xlarge"), Some(STANDARD));
        assert_eq!(family_of("r7i.2xlarge"), Some(STANDARD));
        assert_eq!(family_of("t3.micro"), Some(STANDARD));
        assert_eq!(family_of("g6.2xlarge"), Some(G_VT));
        assert_eq!(family_of("vt1.3xlarge"), Some(G_VT));
        assert_eq!(family_of("p5.48xlarge"), Some(P));
        assert_eq!(family_of("x2idn.16xlarge"), Some(X));
        assert_eq!(family_of("inf2.xlarge"), None);
        assert_eq!(STANDARD.code, "L-1216C47A");
        assert_eq!(G_VT.code, "L-DB2E81BA");
    }

    #[test]
    fn only_pending_and_running_instances_count() {
        let m = parse_running_types(
            &instances(&[
                ("m7i.xlarge", "running"),
                ("m7i.xlarge", "stopped"),
                ("g6.2xlarge", "pending"),
            ])
            .stdout,
        )
        .unwrap();
        assert_eq!(m.get("m7i.xlarge"), Some(&1));
        assert_eq!(m.get("g6.2xlarge"), Some(&1));
    }

    #[test]
    fn a_resize_that_does_not_fit_is_refused_with_the_numbers_before_anything_stops() {
        // quota 8, 4 in use by this very box (m7i.xlarge) and 4 by another; S -> M needs 8
        let r = Arc::new(RecordingRunner::new());
        r.reply(quota(8.0));
        r.reply(instances(&[
            ("m7i.xlarge", "running"),
            ("m7i.xlarge", "running"),
        ]));
        r.reply(types(&[("m7i.xlarge", 4), ("m7i.2xlarge", 8)]));
        let err = backend(&r)
            .vcpu_capacity(&req("m7i.2xlarge", Some("m7i.xlarge")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("quota"), "{err}");
        assert!(
            err.contains("8 vCPUs") && err.contains("8 are in use"),
            "{err}"
        );
        assert!(err.contains("4 of them freed"), "{err}");
        assert!(err.contains("which is 4 over"), "{err}");
        assert!(
            err.contains("L-1216C47A") && err.contains("request-service-quota-increase"),
            "{err}"
        );
        assert!(err.contains("Nothing was stopped"));
        // only reads ran
        assert!(r.calls().iter().all(|c| matches!(
            c.args.get(1).map(String::as_str),
            Some("get-service-quota" | "describe-instances" | "describe-instance-types")
        )));
    }

    #[test]
    fn a_resize_that_fits_once_the_box_is_stopped_passes() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(quota(8.0));
        r.reply(instances(&[("m7i.xlarge", "running")]));
        r.reply(types(&[("m7i.xlarge", 4), ("m7i.2xlarge", 8)]));
        let notes = backend(&r)
            .vcpu_capacity(&req("m7i.2xlarge", Some("m7i.xlarge")))
            .unwrap();
        assert!(notes.is_empty());
        let calls = r.calls();
        assert_eq!(
            calls[0].args,
            [
                "service-quotas",
                "get-service-quota",
                "--service-code",
                "ec2",
                "--quota-code",
                "L-1216C47A",
                "--output",
                "json",
                "--region",
                "us-east-1"
            ]
        );
        assert!(calls[2]
            .args
            .contains(&"describe-instance-types".to_string()));
    }

    #[test]
    fn create_and_resume_count_nothing_freed() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(quota(8.0));
        r.reply(instances(&[("m7i.xlarge", "running")]));
        r.reply(types(&[("m7i.xlarge", 4), ("m7i.2xlarge", 8)]));
        assert!(backend(&r)
            .vcpu_capacity(&req("m7i.2xlarge", None))
            .is_err());
    }

    #[test]
    fn other_families_do_not_count_against_the_standard_quota() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(quota(8.0));
        r.reply(instances(&[
            ("g6.2xlarge", "running"),
            ("g6.2xlarge", "running"),
        ]));
        r.reply(types(&[("g6.2xlarge", 8), ("m7i.2xlarge", 8)]));
        assert!(backend(&r).vcpu_capacity(&req("m7i.2xlarge", None)).is_ok());
    }

    #[test]
    fn gpu_boxes_check_the_gpu_quota() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(quota(4.0));
        r.reply(instances(&[]));
        r.reply(types(&[("g6.2xlarge", 8)]));
        let err = backend(&r)
            .vcpu_capacity(&req("g6.2xlarge", None))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("L-DB2E81BA") && err.contains("G and VT"),
            "{err}"
        );
        assert!(r.calls()[0].args.contains(&"L-DB2E81BA".to_string()));
    }

    #[test]
    fn a_denied_quota_read_is_a_note_not_a_failure() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(denied());
        let notes = backend(&r)
            .vcpu_capacity(&req("m7i.2xlarge", None))
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with("Could not check the vCPU quota"),
            "{notes:?}"
        );
        assert!(!notes[0].contains("AccessDenied"));
        // a family with no mapping says so too
        let r = Arc::new(RecordingRunner::new());
        let notes = backend(&r)
            .vcpu_capacity(&req("inf2.xlarge", None))
            .unwrap();
        assert!(notes[0].contains("was not checked"));
        assert!(r.calls().is_empty());
    }

    #[test]
    fn unreadable_usage_is_also_a_note() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(quota(8.0));
        r.reply(denied());
        let notes = backend(&r)
            .vcpu_capacity(&req("m7i.2xlarge", None))
            .unwrap();
        assert!(notes[0].contains("could not be listed"));
    }
}
