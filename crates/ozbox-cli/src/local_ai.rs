//! Local AI on a GPU box: Ollama or vLLM serving an open-weight model that lives on the box's `/work` disk.
//!
//! The server is bound to the box's loopback address and is reached only from that box (and the fleet's private
//! network through a private address the person marks as local) - never a public port (ADR 0005). Pulling a model is
//! plan-then-apply: the plan shows the download size and the disk it will take before anything is fetched, and an
//! apply with a stale plan is refused. A pulled model is registered as a local endpoint in Settings -> Models.
//!
//! Sizes are about-figures from the model publishers' own listings, shown as "about".

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use ozbox_core::BoxRecord;
use serde::Serialize;
use serde_json::{json, Value};

use crate::settings::{ModelKind, ModelProvider};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Runtime {
    Ollama,
    Vllm,
}

impl Runtime {
    pub fn parse(s: &str) -> Option<Runtime> {
        match s {
            "ollama" => Some(Runtime::Ollama),
            "vllm" => Some(Runtime::Vllm),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Runtime::Ollama => "ollama",
            Runtime::Vllm => "vllm",
        }
    }

    /// The Tools catalog entry that installs it.
    pub fn tool_id(self) -> &'static str {
        self.id()
    }

    pub fn port(self) -> u16 {
        match self {
            Runtime::Ollama => 11434,
            Runtime::Vllm => 8000,
        }
    }

    /// The OpenAI-compatible base address, on the box's own loopback.
    pub fn endpoint(self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port())
    }
}

pub struct LocalModel {
    pub runtime: Runtime,
    /// The name the runtime pulls: an Ollama tag or a Hugging Face model id.
    pub id: &'static str,
    pub label: &'static str,
    /// About how much is downloaded and stored, in GB.
    pub download_gb: f64,
    /// About the GPU memory it needs, in GB.
    pub gpu_gb: u32,
    /// About the memory it needs to run on a box without a GPU (Ollama only; slow but it works), in GB.
    pub ram_gb: u32,
}

const fn m(
    runtime: Runtime,
    id: &'static str,
    label: &'static str,
    download_gb: f64,
    gpu_gb: u32,
    ram_gb: u32,
) -> LocalModel {
    LocalModel {
        runtime,
        id,
        label,
        download_gb,
        gpu_gb,
        ram_gb,
    }
}

pub const MODELS: &[LocalModel] = &[
    m(
        Runtime::Ollama,
        "qwen2.5-coder:1.5b",
        "Qwen2.5 Coder 1.5B",
        1.0,
        4,
        4,
    ),
    m(Runtime::Ollama, "llama3.2:3b", "Llama 3.2 3B", 2.0, 6, 6),
    m(
        Runtime::Ollama,
        "qwen2.5-coder:7b",
        "Qwen2.5 Coder 7B",
        4.7,
        8,
        10,
    ),
    m(Runtime::Ollama, "llama3.1:8b", "Llama 3.1 8B", 4.9, 8, 10),
    m(Runtime::Ollama, "gpt-oss:20b", "gpt-oss 20B", 14.0, 16, 24),
    m(
        Runtime::Ollama,
        "qwen2.5-coder:32b",
        "Qwen2.5 Coder 32B",
        20.0,
        24,
        40,
    ),
    m(
        Runtime::Ollama,
        "llama3.3:70b",
        "Llama 3.3 70B",
        43.0,
        48,
        80,
    ),
    m(
        Runtime::Vllm,
        "Qwen/Qwen2.5-Coder-7B-Instruct",
        "Qwen2.5 Coder 7B",
        15.2,
        20,
        0,
    ),
    m(
        Runtime::Vllm,
        "mistralai/Mistral-7B-Instruct-v0.3",
        "Mistral 7B Instruct",
        14.5,
        20,
        0,
    ),
    m(
        Runtime::Vllm,
        "Qwen/Qwen2.5-Coder-32B-Instruct",
        "Qwen2.5 Coder 32B",
        65.5,
        80,
        0,
    ),
];

pub fn model(runtime: Runtime, id: &str) -> Option<&'static LocalModel> {
    MODELS.iter().find(|x| x.runtime == runtime && x.id == id)
}

/// A free disk that is kept back so a pull never fills `/work`, in GB.
const HEADROOM_GB: f64 = 5.0;
/// Memory kept back on a CPU box so a model never starves the box's own work, in GB.
const CPU_HEADROOM_GB: u32 = 4;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Plan {
    pub box_name: String,
    pub runtime: &'static str,
    pub model: String,
    pub label: &'static str,
    pub download_gb: f64,
    pub gpu_gb_needed: u32,
    pub gpu_gb_available: u32,
    /// `gpu`, or `cpu` on a box without a GPU (Ollama only: slower, and the model must fit in the box's memory).
    pub compute: &'static str,
    /// The memory the model needs on this kind of box (GPU memory on a GPU box, RAM on a CPU box), and what the box has.
    pub memory_gb_needed: u32,
    pub memory_gb_available: u32,
    pub work_disk_gb: u64,
    /// Free space measured on the box, if it answered.
    pub disk_free_gb: Option<f64>,
    pub fits_disk: bool,
    pub fits_gpu: bool,
    pub runtime_installed: bool,
    /// The Tools catalog entry to install first when the runtime is missing.
    pub install_tool: Option<&'static str>,
    /// Whether the plan can be applied now.
    /// The only thing in the way is that the runtime is not installed yet (one click installs it, then pulls).
    pub install_only: bool,
    pub can_apply: bool,
    /// Why not, in a sentence.
    pub blocked: Option<String>,
    pub endpoint: String,
    pub provider_id: String,
    pub estimate: bool,
    pub hash: String,
}

/// The provider id a box's runtime is registered under: letters, digits and dashes, 24 at most.
pub fn provider_id(box_name: &str, runtime: Runtime) -> String {
    let mut id = format!("{}-{box_name}", runtime.id());
    id.truncate(24);
    id.trim_end_matches('-').to_string()
}

/// What pulling `model_id` with `runtime` onto this box would do. Pure: the facts about the box come in.
pub fn plan(
    rec: &BoxRecord,
    runtime: Runtime,
    model_id: &str,
    runtime_installed: bool,
    disk_free_gb: Option<f64>,
) -> Result<Plan, String> {
    let m = model(runtime, model_id).ok_or("that model is not in the list of local models")?;
    let spec = rec.spec.size.spec();
    let cpu = spec.gpus == 0;
    if cpu && runtime == Runtime::Vllm {
        return Err(
            "vLLM needs a GPU box. On a box without a GPU you can run Ollama with a small model."
                .into(),
        );
    }
    let (needed, available) = if cpu {
        // Leave room for the box's own work: a model never gets the last 4 GB.
        (m.ram_gb + CPU_HEADROOM_GB, spec.memory_gb)
    } else {
        (m.gpu_gb, spec.gpu_memory_gb)
    };
    let work = u64::from(rec.spec.work_disk_gb);
    let free = disk_free_gb.unwrap_or(work as f64);
    let fits_disk = m.download_gb + HEADROOM_GB <= free;
    let fits_gpu = needed <= available;
    let mem_block = if cpu {
        format!(
            "This model needs about {} GB of memory to run on a box without a GPU; this box has {} GB.",
            needed, available
        )
    } else {
        format!(
            "This model needs about {} GB of GPU memory; this box has {} GB.",
            m.gpu_gb, spec.gpu_memory_gb
        )
    };
    let disk_block = format!(
        "The download is about {:.1} GB and the box has about {:.1} GB free.",
        m.download_gb, free
    );
    let hard_block = if !fits_gpu {
        Some(mem_block)
    } else if !fits_disk {
        Some(disk_block)
    } else {
        None
    };
    let install_only = !runtime_installed && hard_block.is_none();
    let blocked = if !runtime_installed && hard_block.is_none() {
        Some(format!(
            "Install {} on this box first (Tools).",
            runtime.id()
        ))
    } else {
        hard_block
    };
    let name = rec.spec.name.to_string();
    let mut p = Plan {
        box_name: name.clone(),
        runtime: runtime.id(),
        model: model_id.to_string(),
        label: m.label,
        download_gb: m.download_gb,
        gpu_gb_needed: m.gpu_gb,
        gpu_gb_available: spec.gpu_memory_gb,
        compute: if cpu { "cpu" } else { "gpu" },
        memory_gb_needed: needed,
        memory_gb_available: available,
        work_disk_gb: work,
        disk_free_gb,
        fits_disk,
        fits_gpu,
        runtime_installed,
        install_tool: (!runtime_installed).then(|| runtime.tool_id()),
        install_only,
        can_apply: blocked.is_none(),
        blocked,
        endpoint: runtime.endpoint(),
        provider_id: provider_id(&name, runtime),
        estimate: true,
        hash: String::new(),
    };
    p.hash = plan_hash(&p);
    Ok(p)
}

/// The model to offer first on this box: the largest Ollama model that fits its memory (GPU memory, or RAM without a GPU)
/// and its free disk. A bigger download is a better model, and the list is ordered that way. `None` when nothing fits.
pub fn recommend(rec: &BoxRecord, disk_free_gb: Option<f64>) -> Option<&'static LocalModel> {
    MODELS
        .iter()
        .filter(|m| m.runtime == Runtime::Ollama)
        .filter(|m| {
            plan(rec, Runtime::Ollama, m.id, true, disk_free_gb)
                .map(|p| p.fits_gpu && p.fits_disk)
                .unwrap_or(false)
        })
        .max_by(|a, b| a.download_gb.total_cmp(&b.download_gb))
}

fn plan_hash(p: &Plan) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (
        &p.box_name,
        p.runtime,
        &p.model,
        p.can_apply,
        p.fits_disk,
        p.fits_gpu,
        p.runtime_installed,
    )
        .hash(&mut h);
    p.work_disk_gb.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// The provider entry a pulled model is registered under.
pub fn provider_for(p: &Plan, runtime: Runtime) -> ModelProvider {
    ModelProvider {
        id: p.provider_id.clone(),
        kind: ModelKind::OpenaiCompatible,
        label: format!("{} on {}", runtime.id(), p.box_name)
            .chars()
            .take(40)
            .collect(),
        base_url: Some(runtime.endpoint()),
        local_endpoint: true,
        monthly_cap_usd: None,
        region: None,
        resource: None,
        hosted_on: Some(p.box_name.clone()),
    }
}

/// The curated models as the dashboard shows them.
pub fn catalog_json() -> Value {
    json!({
        "estimate": true,
        "runtimes": [
            { "id": "ollama", "tool_id": "ollama", "port": 11434 },
            { "id": "vllm", "tool_id": "vllm", "port": 8000 },
        ],
        "models": MODELS.iter().map(|x| json!({
            "runtime": x.runtime.id(), "id": x.id, "label": x.label,
            "download_gb": x.download_gb, "gpu_gb": x.gpu_gb, "ram_gb": x.ram_gb,
        })).collect::<Vec<_>>(),
    })
}

/// The demo box's local-AI state: what a real box's daemon would keep on `/work`.
#[derive(Default)]
pub struct SimLocal {
    models: BTreeMap<String, BTreeSet<String>>,
}

impl SimLocal {
    /// The box's answer to a local-AI request (`action`: `list` or `pull`).
    pub fn call(&mut self, request: &Value) -> Value {
        let runtime = request["runtime"].as_str().unwrap_or_default().to_string();
        match request["action"].as_str() {
            Some("pull") => {
                let model = request["model"].as_str().unwrap_or_default();
                if Runtime::parse(&runtime)
                    .and_then(|r| self::model(r, model))
                    .is_none()
                {
                    return json!({ "ok": false, "message": "that model is not in the list of local models" });
                }
                self.models
                    .entry(runtime)
                    .or_default()
                    .insert(model.to_string());
                json!({ "ok": true })
            }
            Some("list") => {
                let list: Vec<&String> = self
                    .models
                    .get(&runtime)
                    .map(|s| s.iter().collect())
                    .unwrap_or_default();
                json!({ "ok": true, "models": list })
            }
            _ => json!({ "ok": false, "message": "unknown request" }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{BoxName, BoxRecord, BoxSpec, BoxState, GpuKind, Size};

    fn rec(size: Size, disk: u32) -> BoxRecord {
        let mut spec = BoxSpec::new(BoxName::new("gpu-1").unwrap(), size);
        spec.work_disk_gb = disk;
        BoxRecord {
            spec,
            state: BoxState::Running,
            provider: "fake".into(),
            provider_id: None,
            machine_type: None,
            snapshots: Vec::new(),
            created_at: None,
            last_activity_at: None,
        }
    }

    #[test]
    fn a_plan_shows_the_download_and_the_disk_before_anything_is_fetched() {
        let r = rec(Size::Gpu(GpuKind::Small), 200);
        let p = plan(&r, Runtime::Ollama, "qwen2.5-coder:7b", true, Some(120.0)).unwrap();
        assert!(p.can_apply && p.fits_disk && p.fits_gpu && p.estimate);
        assert_eq!(p.download_gb, 4.7);
        assert_eq!(p.endpoint, "http://127.0.0.1:11434/v1");
        assert_eq!(p.provider_id, "ollama-gpu-1");
        assert_eq!(p.disk_free_gb, Some(120.0));
    }

    #[test]
    fn it_refuses_vllm_without_a_gpu_a_missing_runtime_too_big_a_model_and_a_full_disk() {
        let cpu = rec(Size::M, 200);
        assert!(plan(
            &cpu,
            Runtime::Vllm,
            "Qwen/Qwen2.5-Coder-7B-Instruct",
            true,
            None
        )
        .unwrap_err()
        .contains("GPU"));
        let g = rec(Size::Gpu(GpuKind::Small), 200);
        let missing = plan(
            &g,
            Runtime::Vllm,
            "Qwen/Qwen2.5-Coder-7B-Instruct",
            false,
            None,
        )
        .unwrap();
        assert!(!missing.can_apply && missing.install_tool == Some("vllm"));
        let big = plan(&g, Runtime::Ollama, "llama3.3:70b", true, None).unwrap();
        assert!(!big.fits_gpu && !big.can_apply && big.blocked.unwrap().contains("GPU memory"));
        let full = plan(&g, Runtime::Ollama, "qwen2.5-coder:32b", true, Some(10.0)).unwrap();
        assert!(!full.fits_disk && full.blocked.unwrap().contains("free"));
        assert!(plan(&g, Runtime::Ollama, "nonsense", true, None).is_err());
    }

    #[test]
    fn a_box_without_a_gpu_runs_ollama_with_a_model_that_fits_its_memory() {
        // S has 16 GB: a 3B model (6 GB + 4 kept back) fits, a 7B (10 + 4) does too, a 20B (24 + 4) does not.
        let s = rec(Size::S, 200);
        let ok = plan(&s, Runtime::Ollama, "llama3.2:3b", true, Some(100.0)).unwrap();
        assert!(ok.can_apply && ok.compute == "cpu");
        assert_eq!((ok.memory_gb_needed, ok.memory_gb_available), (10, 16));
        let seven = plan(&s, Runtime::Ollama, "qwen2.5-coder:7b", true, Some(100.0)).unwrap();
        assert!(seven.can_apply);
        let big = plan(&s, Runtime::Ollama, "gpt-oss:20b", true, Some(100.0)).unwrap();
        assert!(!big.can_apply && big.blocked.unwrap().contains("without a GPU"));
        // the recommendation is the largest that fits, and respects a nearly full disk
        assert_eq!(recommend(&s, Some(100.0)).unwrap().id, "llama3.1:8b");
        assert_eq!(recommend(&s, Some(7.5)).unwrap().id, "llama3.2:3b");
        assert!(recommend(&s, Some(2.0)).is_none());
        let m = rec(Size::M, 200); // 32 GB
        assert_eq!(recommend(&m, Some(100.0)).unwrap().id, "gpt-oss:20b");
        // a GPU box is sized by GPU memory
        let g = rec(Size::Gpu(GpuKind::Small), 200);
        assert_eq!(
            plan(&g, Runtime::Ollama, "llama3.1:8b", true, None)
                .unwrap()
                .compute,
            "gpu"
        );
    }

    #[test]
    fn a_missing_runtime_is_the_only_blocker_when_it_can_be_installed_first() {
        let s = rec(Size::S, 200);
        let p = plan(&s, Runtime::Ollama, "llama3.2:3b", false, Some(100.0)).unwrap();
        assert!(!p.can_apply && p.install_only && p.install_tool == Some("ollama"));
        let too_big = plan(&s, Runtime::Ollama, "gpt-oss:20b", false, Some(100.0)).unwrap();
        assert!(!too_big.install_only, "installing would not help");
    }

    #[test]
    fn the_hash_changes_when_the_facts_do_and_the_provider_is_a_private_local_endpoint() {
        let g = rec(Size::Gpu(GpuKind::Small), 200);
        let a = plan(&g, Runtime::Ollama, "llama3.1:8b", true, Some(100.0)).unwrap();
        let b = plan(&g, Runtime::Ollama, "llama3.1:8b", false, Some(100.0)).unwrap();
        assert_ne!(a.hash, b.hash);
        assert_eq!(
            a.hash,
            plan(&g, Runtime::Ollama, "llama3.1:8b", true, Some(100.0))
                .unwrap()
                .hash
        );
        let p = provider_for(&a, Runtime::Ollama);
        assert!(p.local_endpoint && p.hosted_on.as_deref() == Some("gpu-1"));
        assert!(crate::netguard::check_url(
            crate::netguard::Guard::Private,
            p.base_url.as_deref().unwrap()
        )
        .is_ok());
        assert!(crate::netguard::check_url(
            crate::netguard::Guard::Public,
            p.base_url.as_deref().unwrap()
        )
        .is_err());
    }

    #[test]
    fn the_demo_box_keeps_what_was_pulled() {
        let mut s = SimLocal::default();
        assert!(s.call(&json!({"action":"pull","runtime":"ollama","model":"nope"}))["ok"] == false);
        assert!(
            s.call(&json!({"action":"pull","runtime":"ollama","model":"llama3.1:8b"}))["ok"]
                == true
        );
        assert_eq!(
            s.call(&json!({"action":"list","runtime":"ollama"}))["models"][0],
            "llama3.1:8b"
        );
        assert!(s.call(&json!({"action":"list","runtime":"vllm"}))["models"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
