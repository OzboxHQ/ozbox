//! `ozbox adopt <box>`: rebuild a box's OpenTofu state from the cloud resources it already has, when the state is missing
//! (a deleted worktree, a new computer). It reads the cloud, imports into the box's state, corrects the known import
//! artefacts, and then plans: it finishes only if that plan is a no-op or tags only, and otherwise takes what it imported
//! back out. It never creates, changes or deletes a cloud resource; the only thing it writes is the state, which is
//! backed up before and after.

use ozbox_core::adopt::adopt_apply;
pub use ozbox_core::adopt::{AdoptItem, AdoptPlan, AdoptReport};
use ozbox_core::tofu::fix_import_artefacts;
use ozbox_core::{BoxName, BoxRecord, Error, Result};
use serde_json::Value;

use super::{AwsBackend, Scoped};

const MODULE_ORDER_NOTE: &str = "imported in dependency order";

fn tag(name: &str, value: &str) -> String {
    format!("Name=tag:{name},Values={value}")
}

fn s<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_str()
}

/// `arn:aws:iam::123:instance-profile/path/name` to `name`.
pub(crate) fn profile_name(arn: &str) -> Option<&str> {
    arn.rsplit('/')
        .next()
        .filter(|n| !n.is_empty() && arn.contains(":instance-profile/"))
}

impl AwsBackend {
    /// What adopting `name` would import. Read-only. Refuses a box that already has state here, and anything that does
    /// not find exactly the one machine and one `/work` volume the module made.
    pub fn adopt_plan(&self, name: &BoxName) -> Result<AdoptPlan> {
        let rec = self.find_record(name)?;
        let sc = self.at_rec(&rec);
        if self.tofu.has_workspace(name)? && !self.tofu.state_list(name)?.is_empty() {
            return Err(Error::Provider(format!(
                "{name} already has OpenTofu state on this computer, so there is nothing to adopt. `ozbox upgrade {name}` uses it."
            )));
        }
        let (items, image) = self.discover(&sc, name)?;
        let vars = self.upgrade_vars(&rec, &image)?;
        Ok(AdoptPlan::new(name, items, vars))
    }

    /// The module's own copy of the OpenTofu runner, for the commands that act on the state itself.
    pub fn tofu_module(&self) -> ozbox_core::TofuModule {
        self.tofu.clone()
    }

    /// The module variables for a box as it is now (the image its machine runs), so a plan after its state is copied can
    /// be checked to change nothing. A box whose machine is gone is refused: finish its upgrade first.
    pub fn state_vars(&self, name: &BoxName) -> Result<ozbox_core::ModuleVars> {
        let rec = self.find_record(name)?;
        if rec.state == ozbox_core::BoxState::InstanceMissing {
            return Err(Error::Provider(format!(
                "{name} has no machine at the moment (an upgrade was interrupted); finish it with `ozbox upgrade {name}` before moving its state"
            )));
        }
        let id = Self::instance_id(&rec)?;
        let v: Value =
            self.at_rec(&rec)
                .run_json(&["ec2", "describe-instances", "--instance-ids", id])?;
        let image = s(&v["Reservations"][0]["Instances"][0], &["ImageId"])
            .ok_or_else(|| Error::Provider("the machine has no image id".into()))?
            .to_string();
        self.upgrade_vars(&rec, &image)
    }

    fn find_record(&self, name: &BoxName) -> Result<BoxRecord> {
        use ozbox_core::Backend;
        self.list()?
            .into_iter()
            .find(|r| &r.spec.name == name)
            .ok_or_else(|| Error::NotFound(name.to_string()))
    }

    fn discover(&self, sc: &Scoped<'_>, name: &BoxName) -> Result<(Vec<AdoptItem>, String)> {
        let n = name.as_str();
        let inst: Value = sc.run_json(&[
            "ec2",
            "describe-instances",
            "--filters",
            &tag("ozbox-box", n),
            &tag("ozbox-managed", "true"),
            "Name=instance-state-name,Values=pending,running,stopping,stopped",
        ])?;
        let instances: Vec<&Value> = inst["Reservations"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|r| r["Instances"].as_array().into_iter().flatten())
            .collect();
        let [i] = instances.as_slice() else {
            return Err(Error::Provider(format!(
                "found {} machines tagged for {n}; adopting needs exactly one",
                instances.len()
            )));
        };
        let instance_id =
            s(i, &["InstanceId"]).ok_or_else(|| Error::Provider("the machine has no id".into()))?;
        let image = s(i, &["ImageId"]).unwrap_or_default().to_string();
        let prefix = format!("ozbox-{n}-");
        let sg = i["SecurityGroups"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|g| s(g, &["GroupName"]).is_some_and(|x| x.starts_with(&prefix)))
            .and_then(|g| s(g, &["GroupId"]))
            .ok_or_else(|| {
                Error::Provider(format!("the machine has no security group named {prefix}*"))
            })?;
        let prof = s(i, &["IamInstanceProfile", "Arn"])
            .and_then(profile_name)
            .ok_or_else(|| Error::Provider("the machine has no instance profile".into()))?;
        let p: Value = sc.run_json(&[
            "iam",
            "get-instance-profile",
            "--instance-profile-name",
            prof,
        ])?;
        let role = s(&p["InstanceProfile"]["Roles"][0], &["RoleName"])
            .ok_or_else(|| Error::Provider(format!("instance profile {prof} has no role")))?
            .to_string();
        let attached: Value =
            sc.run_json(&["iam", "list-attached-role-policies", "--role-name", &role])?;
        let vols: Value = sc.run_json(&[
            "ec2",
            "describe-volumes",
            "--filters",
            &tag("ozbox-box", n),
            &tag("ozbox-role", "work"),
        ])?;
        let volumes: Vec<&Value> = vols["Volumes"].as_array().into_iter().flatten().collect();
        let [v] = volumes.as_slice() else {
            return Err(Error::Provider(format!(
                "found {} /work volumes tagged for {n}; adopting needs exactly one",
                volumes.len()
            )));
        };
        let vol_id =
            s(v, &["VolumeId"]).ok_or_else(|| Error::Provider("the volume has no id".into()))?;
        let mut items = vec![
            AdoptItem {
                address: "aws_security_group.box".into(),
                id: sg.into(),
                what: "the machine's security group".into(),
            },
            AdoptItem {
                address: "aws_iam_role.box".into(),
                id: role.clone(),
                what: "the machine's IAM role".into(),
            },
        ];
        // every managed policy the role carries that the module attaches: AWS's Session Manager policy (a box made before ADR 0029
        // Amendment 9) or the account's own `ozbox-box-*` ones. An inline role policy (made by someone with rights the operator
        // lacks) is not the module's any more and is left alone, unmanaged.
        for arn in attached["AttachedPolicies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| s(a, &["PolicyArn"]))
        {
            let address = if arn == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                || arn.ends_with(":policy/ozbox-box-session-manager")
            {
                "aws_iam_role_policy_attachment.ssm_core"
            } else if arn.ends_with(":policy/ozbox-box-parameters") {
                "aws_iam_role_policy_attachment.parameters[0]"
            } else if arn.ends_with(":policy/ozbox-box-parameters-key") {
                "aws_iam_role_policy_attachment.parameters_key[0]"
            } else if arn.ends_with(":policy/ozbox-box-session-logs") {
                "aws_iam_role_policy_attachment.session_logs[0]"
            } else if arn.contains(":policy/ozbox-box-fleet-key-") {
                "aws_iam_role_policy_attachment.fleet_key[0]"
            } else {
                continue;
            };
            items.push(AdoptItem {
                address: address.into(),
                id: format!("{role}/{arn}"),
                what: "a policy the role carries".into(),
            });
        }
        items.push(AdoptItem {
            address: "aws_iam_instance_profile.box".into(),
            id: prof.into(),
            what: "the machine's instance profile".into(),
        });
        items.push(AdoptItem {
            address: "aws_ebs_volume.work".into(),
            id: vol_id.into(),
            what: "the /work volume (kept: never created or deleted)".into(),
        });
        items.push(AdoptItem {
            address: "aws_instance.box".into(),
            id: instance_id.into(),
            what: "the machine".into(),
        });
        let attached_here = v["Attachments"].as_array().into_iter().flatten().any(|a| {
            s(a, &["InstanceId"]) == Some(instance_id) && s(a, &["Device"]) == Some("/dev/sdf")
        });
        if attached_here {
            items.push(AdoptItem {
                address: "aws_volume_attachment.work".into(),
                id: format!("/dev/sdf:{vol_id}:{instance_id}"),
                what: "the /work volume's attachment".into(),
            });
        }
        let _ = MODULE_ORDER_NOTE;
        Ok((items, image))
    }

    /// Import, correct, verify; see [`ozbox_core::adopt::adopt_apply`]. Any refusal takes the imported resources back out
    /// of the state again (state only).
    pub fn adopt_apply(&self, plan: &AdoptPlan) -> Result<AdoptReport> {
        adopt_apply(&self.tofu, plan, fix_import_artefacts)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_name_is_the_last_part_of_its_arn_and_only_of_a_profile() {
        assert_eq!(
            profile_name("arn:aws:iam::123456789012:instance-profile/ozbox-main-2026"),
            Some("ozbox-main-2026")
        );
        assert_eq!(
            profile_name("arn:aws:iam::123456789012:instance-profile/a/b/c"),
            Some("c")
        );
        assert_eq!(profile_name("arn:aws:iam::123456789012:role/x"), None);
    }

    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ozbox_core::{CommandRunner, CommandSpec, ModuleVars, Output};

    /// Answers by the words of the command (`state pull`, `iam get-instance-profile`, ...) and records every call.
    #[derive(Default)]
    struct Script {
        answers: Mutex<BTreeMap<String, Output>>,
        calls: Mutex<Vec<CommandSpec>>,
    }

    impl Script {
        fn say(&self, key: &str, stdout: &str) {
            self.answers.lock().unwrap().insert(
                key.to_string(),
                Output {
                    status: Some(0),
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            );
        }
        fn fail(&self, key: &str) {
            self.answers.lock().unwrap().insert(
                key.to_string(),
                Output {
                    status: Some(1),
                    stdout: String::new(),
                    stderr: "boom".into(),
                },
            );
        }
        fn calls(&self) -> Vec<CommandSpec> {
            self.calls.lock().unwrap().clone()
        }
        fn keys(&self) -> Vec<String> {
            self.calls().iter().map(key_of).collect()
        }
    }

    fn key_of(c: &CommandSpec) -> String {
        let a: Vec<&str> = c
            .args
            .iter()
            .filter(|a| !a.starts_with("-chdir"))
            .map(String::as_str)
            .collect();
        a.iter().take(2).copied().collect::<Vec<_>>().join(" ")
    }

    impl CommandRunner for Script {
        fn run(&self, cmd: &CommandSpec) -> ozbox_core::Result<Output> {
            self.calls.lock().unwrap().push(cmd.clone());
            Ok(self
                .answers
                .lock()
                .unwrap()
                .get(&key_of(cmd))
                .cloned()
                .unwrap_or(Output {
                    status: Some(0),
                    ..Output::default()
                }))
        }
    }

    fn backend(script: Arc<Script>) -> AwsBackend {
        AwsBackend::with_env_none(script, crate::AwsConfig::default())
    }

    const INSTANCES: &str = r#"{"Reservations":[{"Instances":[{"InstanceId":"i-0aaa","ImageId":"ami-1",
      "SecurityGroups":[{"GroupId":"sg-0z","GroupName":"default"},{"GroupId":"sg-0b","GroupName":"ozbox-main-20261109"}],
      "IamInstanceProfile":{"Arn":"arn:aws:iam::123456789012:instance-profile/ozbox-main-2026"}}]}]}"#;

    fn account(s: &Script) {
        s.say("ec2 describe-instances", INSTANCES);
        s.say(
            "iam get-instance-profile",
            r#"{"InstanceProfile":{"Roles":[{"RoleName":"ozbox-main-role"}]}}"#,
        );
        s.say("iam list-attached-role-policies", r#"{"AttachedPolicies":[{"PolicyArn":"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"}]}"#);
        s.say("ec2 describe-volumes", r#"{"Volumes":[{"VolumeId":"vol-0w","Attachments":[{"InstanceId":"i-0aaa","Device":"/dev/sdf"}]}]}"#);
    }

    #[test]
    fn discovery_finds_every_resource_by_its_tags_and_names_in_dependency_order_and_only_reads() {
        let s = Arc::new(Script::default());
        account(&s);
        let b = backend(s.clone());
        let sc = b.at(Some("us-east-1"));
        let (items, image) = b.discover(&sc, &BoxName::new("main").unwrap()).unwrap();
        assert_eq!(image, "ami-1");
        let got: Vec<(&str, &str)> = items
            .iter()
            .map(|i| (i.address.as_str(), i.id.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("aws_security_group.box", "sg-0b"),
                ("aws_iam_role.box", "ozbox-main-role"),
                (
                    "aws_iam_role_policy_attachment.ssm_core",
                    "ozbox-main-role/arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                ),
                ("aws_iam_instance_profile.box", "ozbox-main-2026"),
                ("aws_ebs_volume.work", "vol-0w"),
                ("aws_instance.box", "i-0aaa"),
                ("aws_volume_attachment.work", "/dev/sdf:vol-0w:i-0aaa"),
            ]
        );
        // discovery asks the cloud only to describe or list: never a create, modify, delete or tag call
        for c in s.calls() {
            let verb = c.args.get(1).map(String::as_str).unwrap_or("");
            assert!(
                verb.starts_with("describe-")
                    || verb.starts_with("get-")
                    || verb.starts_with("list-"),
                "{:?}",
                c.args
            );
        }
        // two machines tagged for one box: refused, not guessed
        let two = r#"{"Reservations":[{"Instances":[{"InstanceId":"i-1"},{"InstanceId":"i-2"}]}]}"#;
        s.say("ec2 describe-instances", two);
        assert!(b.discover(&sc, &BoxName::new("main").unwrap()).is_err());
    }

    fn plan_of(b: &AwsBackend) -> AdoptPlan {
        let vars = ModuleVars {
            box_name: BoxName::new("main").unwrap(),
            machine_type: "m7i.xlarge".into(),
            work_disk_gb: 200,
            image_id: "ami-1".into(),
            region: Some("us-east-1".into()),
            labels: BTreeMap::new(),
            work_snapshot_id: None,
            extra: BTreeMap::new(),
        };
        let _ = b;
        AdoptPlan::new(
            &BoxName::new("main").unwrap(),
            vec![
                AdoptItem {
                    address: "aws_ebs_volume.work".into(),
                    id: "vol-0w".into(),
                    what: "v".into(),
                },
                AdoptItem {
                    address: "aws_instance.box".into(),
                    id: "i-0aaa".into(),
                    what: "i".into(),
                },
                AdoptItem {
                    address: "aws_volume_attachment.work".into(),
                    id: "/dev/sdf:vol-0w:i-0aaa".into(),
                    what: "a".into(),
                },
            ],
            vars,
        )
    }

    const IMPORTED: &str = r#"{"version":4,"serial":5,"resources":[
      {"type":"aws_instance","name":"box","instances":[{"attributes":{"user_data":"h","user_data_replace_on_change":false}}]},
      {"type":"aws_volume_attachment","name":"work","instances":[{"attributes":{}}]}]}"#;

    #[test]
    fn a_clean_adoption_imports_corrects_the_artefacts_pushes_a_higher_serial_and_never_calls_the_cloud(
    ) {
        let s = Arc::new(Script::default());
        s.say("state list", "");
        s.say("state pull", IMPORTED);
        s.say("show -json", r#"{"resource_changes":[{"address":"aws_instance.box","change":{"actions":["no-op"]}}]}"#);
        let b = backend(s.clone());
        let r = b.adopt_apply(&plan_of(&b)).unwrap();
        assert_eq!(r.imported.len(), 3);
        assert_eq!(r.corrected.len(), 3);
        let calls = s.calls();
        assert!(
            calls.iter().all(|c| c.program == "tofu"),
            "adopt never runs aws"
        );
        let imports = s
            .keys()
            .iter()
            .filter(|k| *k == "import -input=false")
            .count();
        assert_eq!(imports, 3);
        let push = calls
            .iter()
            .find(|c| c.args.contains(&"push".to_string()))
            .expect("pushed");
        let pushed: serde_json::Value =
            serde_json::from_slice(push.stdin.as_ref().unwrap()).unwrap();
        assert_eq!(pushed["serial"], 6);
        assert!(
            !s.keys().iter().any(|k| k == "state rm"),
            "nothing taken back"
        );
        assert!(!s
            .keys()
            .iter()
            .any(|k| k.starts_with("apply") || k.starts_with("destroy")));
    }

    #[test]
    fn a_plan_that_would_change_more_than_tags_is_refused_and_the_imports_are_taken_back() {
        let s = Arc::new(Script::default());
        s.say("state list", "");
        s.say("state pull", IMPORTED);
        s.say("show -json", r#"{"resource_changes":[{"address":"aws_instance.box","change":{"actions":["delete","create"]}}]}"#);
        let b = backend(s.clone());
        let e = b.adopt_apply(&plan_of(&b)).unwrap_err().to_string();
        assert!(
            e.contains("aws_instance.box would delete and create"),
            "{e}"
        );
        let rm = s
            .calls()
            .into_iter()
            .find(|c| c.args.contains(&"rm".to_string()))
            .expect("took back");
        assert!(
            rm.args.contains(&"aws_instance.box".to_string())
                && rm.args.contains(&"aws_ebs_volume.work".to_string())
        );
    }

    #[test]
    fn a_failed_import_takes_back_what_came_before_it() {
        let s = Arc::new(Script::default());
        s.say("state list", "");
        s.fail("import -input=false");
        let b = backend(s.clone());
        let e = b.adopt_apply(&plan_of(&b)).unwrap_err().to_string();
        assert!(
            e.contains("aws_ebs_volume.work") && e.contains("nothing in the cloud changed"),
            "{e}"
        );
    }
}
