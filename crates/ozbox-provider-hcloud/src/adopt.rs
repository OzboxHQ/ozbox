//! `ozbox adopt <box>` on Hetzner: rebuild a box's OpenTofu state from the resources it already has. The same contract as
//! the AWS adoption (see [`ozbox_core::adopt`]): read-only calls find the box's server, `/work` volume and firewall by
//! their `ozbox-*` labels, they are imported in dependency order, the import artefacts are corrected, and the result is
//! kept only if the plan changes nothing or labels only. Nothing in the cloud is created, changed or deleted, and the
//! state is backed up before and after, whichever backend holds it.
//!
//! The private network is not a resource of the module: the server carries it as an attachment, so it is found on the
//! server and passed to the module as `network_id`, not imported.

use ozbox_core::adopt::{adopt_apply, AdoptItem, AdoptPlan, AdoptReport};
use ozbox_core::tofu::fix_import_artefacts_hcloud;
use ozbox_core::{BoxName, BoxRecord, Error, ModuleVars, Result, TofuModule};

use super::{ApiServer, HcloudBackend, LABEL_BOX};

const LABEL_ROLE: &str = "ozbox-role";

fn one<'a, T>(found: Vec<&'a T>, what: &str, name: &BoxName) -> Result<&'a T> {
    match found.as_slice() {
        [x] => Ok(x),
        other => Err(Error::Provider(format!(
            "found {} {what} labelled for {name}; adopting needs exactly one",
            other.len()
        ))),
    }
}

impl HcloudBackend {
    /// What adopting `name` would import. Read-only. Refuses a box that already has state, and anything that does not
    /// find exactly the one server, `/work` volume and firewall the module made, attached to each other.
    pub fn adopt_plan(&self, name: &BoxName) -> Result<AdoptPlan> {
        use ozbox_core::Backend;
        let rec: BoxRecord = self
            .list()?
            .into_iter()
            .find(|r| &r.spec.name == name)
            .ok_or_else(|| Error::NotFound(name.to_string()))?;
        if self.tofu.has_workspace(name)? && !self.tofu.state_list(name)?.is_empty() {
            return Err(Error::Provider(format!(
                "{name} already has OpenTofu state, so there is nothing to adopt. `ozbox upgrade {name}` uses it."
            )));
        }
        let is_ours = |l: &std::collections::BTreeMap<String, String>| {
            l.get(LABEL_BOX).map(String::as_str) == Some(name.as_str())
        };
        let servers = self.api.list_servers()?;
        let server = one(
            servers.iter().filter(|s| is_ours(&s.labels)).collect(),
            "servers",
            name,
        )?;
        let volumes = self.api.list_volumes()?;
        let volume = one(
            volumes
                .iter()
                .filter(|v| {
                    is_ours(&v.labels)
                        && v.labels.get(LABEL_ROLE).map(String::as_str) == Some("work")
                })
                .collect(),
            "/work volumes",
            name,
        )?;
        let firewalls = self.api.list_firewalls()?;
        let firewall = one(
            firewalls.iter().filter(|f| is_ours(&f.labels)).collect(),
            "firewalls",
            name,
        )?;
        if !server.firewall_ids.contains(&firewall.id) {
            return Err(Error::Provider(format!(
                "the firewall labelled for {name} is not the one applied to its server, so this is not a box the module made; nothing was changed"
            )));
        }
        if volume.server.is_some_and(|s| s != server.id) {
            return Err(Error::Provider(format!(
                "the /work volume labelled for {name} is attached to a different server; nothing was changed"
            )));
        }
        if server.network_ids.len() > 1 {
            return Err(Error::Provider(format!(
                "the server of {name} is on {} private networks; the module attaches one, so adopting would not match",
                server.network_ids.len()
            )));
        }
        let mut items = vec![
            AdoptItem {
                address: "hcloud_firewall.box".into(),
                id: firewall.id.to_string(),
                what: "the machine's firewall (no inbound rules)".into(),
            },
            AdoptItem {
                address: "hcloud_volume.work".into(),
                id: volume.id.to_string(),
                what: "the /work volume (kept: never created or deleted)".into(),
            },
            AdoptItem {
                address: "hcloud_server.box".into(),
                id: server.id.to_string(),
                what: "the machine".into(),
            },
        ];
        if volume.server == Some(server.id) {
            items.push(AdoptItem {
                address: "hcloud_volume_attachment.work".into(),
                // the provider imports an attachment by its volume
                id: volume.id.to_string(),
                what: "the /work volume's attachment".into(),
            });
        }
        let vars = self.vars_for(&rec, server, volume.size_gb)?;
        Ok(AdoptPlan::new(name, items, vars))
    }

    /// The module variables that describe the live box as it is: its server type, disk, location and private network.
    fn vars_for(
        &self,
        rec: &BoxRecord,
        server: &ApiServer,
        work_disk_gb: u32,
    ) -> Result<ModuleVars> {
        let machine_type = rec.machine_type.clone().ok_or_else(|| {
            Error::Provider(format!(
                "{} has no server type to describe it with",
                rec.spec.name
            ))
        })?;
        let mut spec = rec.spec.clone();
        spec.work_disk_gb = work_disk_gb;
        let mut vars = self.vars(&spec, &machine_type);
        if vars.region.is_none() {
            return Err(Error::Config(
                "this needs the location the box runs in: set `region` in the [hcloud] section of the configuration".into(),
            ));
        }
        if let Some(net) = server.network_ids.first() {
            vars.extra.insert("network_id".into(), net.to_string());
        }
        Ok(vars)
    }

    /// The module's own copy of the OpenTofu runner, for the commands that act on the state itself.
    pub fn tofu_module(&self) -> TofuModule {
        self.tofu.clone()
    }

    /// The module variables for a box as it is now, so a plan after its state is copied can be checked to change nothing.
    pub fn state_vars(&self, name: &BoxName) -> Result<ModuleVars> {
        use ozbox_core::Backend;
        let rec = self
            .list()?
            .into_iter()
            .find(|r| &r.spec.name == name)
            .ok_or_else(|| Error::NotFound(name.to_string()))?;
        let server = self.api.get_server(Self::server_id(&rec)?)?;
        let disk = rec.spec.work_disk_gb;
        self.vars_for(&rec, &server, disk)
    }

    /// Import, correct, verify; see [`ozbox_core::adopt::adopt_apply`]. Any refusal takes the imported resources back out
    /// of the state again (state only).
    pub fn adopt_apply(&self, plan: &AdoptPlan) -> Result<AdoptReport> {
        adopt_apply(&self.tofu, plan, fix_import_artefacts_hcloud)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ozbox_core::{CommandRunner, CommandSpec, Output};

    use super::*;
    use crate::testing::Sim;
    use crate::{HcloudBackend, HcloudConfig};

    /// Answers by the words of the command (`state pull`, `show -json`, ...) and records every call.
    #[derive(Default)]
    struct Script {
        answers: Mutex<BTreeMap<String, Output>>,
        calls: Mutex<Vec<CommandSpec>>,
    }

    fn key_of(c: &CommandSpec) -> String {
        c.args
            .iter()
            .filter(|a| !a.starts_with("-chdir"))
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    }

    impl Script {
        fn say(&self, key: &str, stdout: &str) {
            self.answers.lock().unwrap().insert(
                key.into(),
                Output {
                    status: Some(0),
                    stdout: stdout.into(),
                    stderr: String::new(),
                },
            );
        }
        fn keys(&self) -> Vec<String> {
            self.calls.lock().unwrap().iter().map(key_of).collect()
        }
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

    fn backend(sim: &Arc<Sim>, script: &Arc<Script>, region: Option<&str>) -> HcloudBackend {
        HcloudBackend::new(
            sim.clone(),
            script.clone(),
            HcloudConfig {
                region: region.map(str::to_string),
                image: Some("img-1".into()),
                ..HcloudConfig::default()
            },
        )
    }

    fn name() -> BoxName {
        BoxName::new("main").unwrap()
    }

    #[test]
    fn discovery_finds_the_servers_volume_and_firewall_by_label_in_dependency_order_and_only_reads()
    {
        let sim = Arc::new(Sim::new());
        let (sid, vid, fw) = sim.add_box_resources("main", "ccx33");
        sim.add_box_resources("other", "ccx33");
        let script = Arc::new(Script::default());
        let b = backend(&sim, &script, Some("fsn1"));
        let plan = b.adopt_plan(&name()).unwrap();
        let got: Vec<(String, String)> = plan
            .items
            .iter()
            .map(|i| (i.address.clone(), i.id.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("hcloud_firewall.box".to_string(), fw.to_string()),
                ("hcloud_volume.work".into(), vid.to_string()),
                ("hcloud_server.box".into(), sid.to_string()),
                ("hcloud_volume_attachment.work".into(), vid.to_string()),
            ]
        );
        // the cloud was only listed or read
        for l in sim.api_log() {
            assert!(l.starts_with("list_") || l.starts_with("get_"), "{l}");
        }
    }

    #[test]
    fn a_private_network_on_the_server_becomes_the_modules_network_id_and_is_not_imported() {
        let sim = Arc::new(Sim::new());
        let (sid, _, _) = sim.add_box_resources("main", "ccx33");
        sim.attach_network(sid, 4242);
        let b = backend(&sim, &Arc::new(Script::default()), Some("fsn1"));
        let plan = b.adopt_plan(&name()).unwrap();
        assert!(!plan.items.iter().any(|i| i.address.contains("network")));
        let two = {
            sim.attach_network(sid, 4343);
            b.adopt_plan(&name()).unwrap_err().to_string()
        };
        assert!(two.contains("2 private networks"), "{two}");
    }

    #[test]
    fn a_box_that_is_not_what_the_module_made_is_refused_not_guessed() {
        // two servers carry the box's label
        let sim = Arc::new(Sim::new());
        sim.add_box_resources("main", "ccx33");
        sim.add_server("main", "ccx33", "running");
        let b = backend(&sim, &Arc::new(Script::default()), Some("fsn1"));
        let e = b.adopt_plan(&name()).unwrap_err().to_string();
        assert!(e.contains("2 servers") && e.contains("exactly one"), "{e}");
        // no location anywhere to build the module's variables with: the configuration has none and the box's volume does not
        // say where it is
        let sim = Arc::new(Sim::new());
        let (_, volume, _) = sim.add_box_resources("main", "ccx33");
        sim.forget_volume_location(volume);
        let b = backend(&sim, &Arc::new(Script::default()), None);
        assert!(b
            .adopt_plan(&name())
            .unwrap_err()
            .to_string()
            .contains("region"));
        // ... but a box whose volume says where it is needs no location in the configuration
        let sim = Arc::new(Sim::new());
        sim.add_box_resources("main", "ccx33");
        let b = backend(&sim, &Arc::new(Script::default()), None);
        assert!(b.adopt_plan(&name()).is_ok());
        // a box that has state already
        let sim = Arc::new(Sim::new());
        sim.add_box_resources("main", "ccx33");
        let script = Arc::new(Script::default());
        script.say("workspace list", "* default\n  main\n");
        script.say("state list", "hcloud_server.box\n");
        let b = backend(&sim, &script, Some("fsn1"));
        assert!(b
            .adopt_plan(&name())
            .unwrap_err()
            .to_string()
            .contains("nothing to adopt"));
    }

    const IMPORTED: &str = r#"{"version":4,"serial":5,"resources":[
      {"type":"hcloud_server","name":"box","instances":[{"attributes":{}}]},
      {"type":"hcloud_volume_attachment","name":"work","instances":[{"attributes":{}}]}]}"#;

    #[test]
    fn a_clean_adoption_imports_corrects_the_artefacts_and_never_calls_the_cloud() {
        let sim = Arc::new(Sim::new());
        sim.add_box_resources("main", "ccx33");
        let script = Arc::new(Script::default());
        script.say("state list", "");
        script.say("state pull", IMPORTED);
        script.say(
            "show -json",
            r#"{"resource_changes":[{"address":"hcloud_server.box","change":{"actions":["no-op"]}}]}"#,
        );
        let b = backend(&sim, &script, Some("fsn1"));
        let plan = b.adopt_plan(&name()).unwrap();
        sim.clear_api_log();
        let r = b.adopt_apply(&plan).unwrap();
        assert_eq!(r.imported.len(), 4);
        assert_eq!(r.corrected.len(), 2);
        assert!(
            sim.api_log().is_empty(),
            "adopt applies nothing through the API"
        );
        let imports = script
            .keys()
            .iter()
            .filter(|k| *k == "import -input=false")
            .count();
        assert_eq!(imports, 4);
        // the volume's attachment is imported by its volume id
        let calls = script.calls.lock().unwrap().clone();
        let att = calls
            .iter()
            .find(|c| {
                c.args
                    .contains(&"hcloud_volume_attachment.work".to_string())
            })
            .unwrap();
        assert!(att.args.last().unwrap().chars().all(|c| c.is_ascii_digit()));
        let push = calls
            .iter()
            .find(|c| c.args.contains(&"push".to_string()))
            .unwrap();
        let pushed: serde_json::Value =
            serde_json::from_slice(push.stdin.as_ref().unwrap()).unwrap();
        assert_eq!(pushed["serial"], 6);
        assert!(!script
            .keys()
            .iter()
            .any(|k| k.starts_with("apply") || k.starts_with("destroy") || k == "state rm"));
    }

    #[test]
    fn a_plan_that_would_replace_the_server_is_refused_and_the_imports_taken_back() {
        let sim = Arc::new(Sim::new());
        sim.add_box_resources("main", "ccx33");
        let script = Arc::new(Script::default());
        script.say("state list", "");
        script.say("state pull", IMPORTED);
        script.say(
            "show -json",
            r#"{"resource_changes":[{"address":"hcloud_server.box","change":{"actions":["delete","create"]}}]}"#,
        );
        let b = backend(&sim, &script, Some("fsn1"));
        let plan = b.adopt_plan(&name()).unwrap();
        let e = b.adopt_apply(&plan).unwrap_err().to_string();
        assert!(
            e.contains("hcloud_server.box would delete and create"),
            "{e}"
        );
        assert!(script.keys().iter().any(|k| k == "state rm"));
    }
}
