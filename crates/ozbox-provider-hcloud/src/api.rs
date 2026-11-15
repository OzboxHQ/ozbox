//! The slice of the Hetzner Cloud REST API Oz Box uses, behind a trait so tests never touch the network.
//!
//! The real implementation ([`UreqApi`]) reads the token from the environment at the moment of each call and
//! never stores, logs, serializes or reports it. Errors carry the HTTP status and Hetzner's own message only.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ozbox_core::{Error, Result};
use serde::Deserialize;

pub const BASE_URL: &str = "https://api.hetzner.cloud/v1";
pub const TOKEN_ENV: &str = "HCLOUD_TOKEN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiServer {
    pub id: u64,
    pub name: String,
    /// `initializing`, `starting`, `running`, `stopping`, `off`, `deleting`, `migrating`, `rebuilding`, `unknown`.
    pub status: String,
    pub server_type: String,
    pub labels: BTreeMap<String, String>,
    pub created: Option<String>,
    /// The image the server was built from: its name when it has one (system images), else its id (snapshots).
    pub image: Option<String>,
    /// The cloud firewalls applied to the server's public interface.
    pub firewall_ids: Vec<u64>,
    /// The private networks the server is attached to.
    pub network_ids: Vec<u64>,
}

/// What is known about an image a server could be rebuilt from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiImageInfo {
    pub id: String,
    /// `x86` or `arm`.
    pub architecture: String,
    /// `available`, `creating` or `unavailable`.
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiVolume {
    pub id: u64,
    pub size_gb: u32,
    pub labels: BTreeMap<String, String>,
    /// The server the volume is attached to, when it is attached.
    pub server: Option<u64>,
    /// The location it is in (`fsn1`), which is also its server's: a volume is attached only inside its location.
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiFirewall {
    pub id: u64,
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiImage {
    pub id: u64,
    pub created: Option<String>,
    pub labels: BTreeMap<String, String>,
    /// `available`, `creating` or `unavailable`.
    pub status: String,
    /// The size of the image in GB, when Hetzner has computed it (a snapshot of the root disk, not of `/work`).
    pub image_size_gb: Option<f64>,
}

/// Every call that changes something returns only once Hetzner reports the action finished.
pub trait HcloudApi: Send + Sync {
    /// Servers labelled `ozbox-managed=true`.
    fn list_servers(&self) -> Result<Vec<ApiServer>>;
    fn get_server(&self, id: u64) -> Result<ApiServer>;
    /// Volumes labelled `ozbox-managed=true`.
    fn list_volumes(&self) -> Result<Vec<ApiVolume>>;
    /// Firewalls labelled `ozbox-managed=true`. Read-only; used to find a box's firewall when adopting it.
    fn list_firewalls(&self) -> Result<Vec<ApiFirewall>>;
    /// Snapshot images labelled `ozbox-managed=true`.
    fn list_snapshots(&self) -> Result<Vec<ApiImage>>;
    /// `shutdown` (graceful, returns when accepted), `poweroff` (hard) or `poweron`.
    fn server_action(&self, id: u64, action: &str) -> Result<()>;
    /// Change the server type. The root disk is not upgraded, so the change stays reversible.
    fn change_type(&self, id: u64, server_type: &str) -> Result<()>;
    fn set_server_labels(&self, id: u64, labels: &BTreeMap<String, String>) -> Result<()>;
    /// Replace a volume's labels. An upgrade marks the `/work` volume (the server it marks is replaced).
    fn set_volume_labels(&self, id: u64, labels: &BTreeMap<String, String>) -> Result<()>;
    /// Delete a volume. Only for the `/work` volume of a box whose server is gone and whose destruction a person confirmed.
    fn delete_volume(&self, id: u64) -> Result<()>;
    /// An image by id or name, or `None` when there is no such image.
    fn get_image(&self, image: &str) -> Result<Option<ApiImageInfo>>;
    fn resize_volume(&self, id: u64, size_gb: u32) -> Result<()>;
    /// Create a snapshot image of the server and return its id.
    fn create_snapshot(
        &self,
        server_id: u64,
        description: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<u64>;
    /// Delete a snapshot image. The caller has checked it is one Oz Box made.
    fn delete_image(&self, id: u64) -> Result<()>;
}

type TokenSource = Box<dyn Fn() -> Option<String> + Send + Sync>;

/// The real API over `ureq`.
pub struct UreqApi {
    base_url: String,
    token: TokenSource,
    poll_every: Duration,
    give_up_after: Duration,
}

impl UreqApi {
    /// Token from `HCLOUD_TOKEN`, read at each call.
    pub fn from_env() -> Self {
        Self::with_token_source(BASE_URL, Box::new(|| std::env::var(TOKEN_ENV).ok()))
    }

    pub fn with_token_source(base_url: impl Into<String>, token: TokenSource) -> Self {
        Self {
            base_url: base_url.into(),
            token,
            poll_every: Duration::from_secs(2),
            give_up_after: Duration::from_secs(600),
        }
    }

    fn bearer(&self) -> Result<String> {
        match (self.token)() {
            Some(t) if !t.trim().is_empty() => Ok(format!("Bearer {}", t.trim())),
            _ => Err(Error::Config(format!(
                "{TOKEN_ENV} is not set: export a Hetzner Cloud API token with read & write access"
            ))),
        }
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = ureq::request(method, &url)
            .set("Authorization", &self.bearer()?)
            .timeout(Duration::from_secs(60));
        req = req.set("Accept", "application/json");
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match resp {
            Ok(r) => {
                // A delete answers with no body at all.
                let text = r.into_string().map_err(|e| {
                    Error::Provider(format!(
                        "Hetzner API {method} {path}: unreadable response ({})",
                        e.kind()
                    ))
                })?;
                if text.trim().is_empty() {
                    return Ok(serde_json::Value::Null);
                }
                serde_json::from_str(&text).map_err(|_| {
                    Error::Provider(format!("Hetzner API {method} {path}: unreadable response"))
                })
            }
            Err(ureq::Error::Status(code, r)) => {
                let msg = r
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
                    .unwrap_or_default();
                Err(Error::Provider(format!(
                    "Hetzner API {method} {path}: HTTP {code}{}",
                    if msg.is_empty() {
                        String::new()
                    } else {
                        format!(": {msg}")
                    }
                )))
            }
            // Only the kind: a transport error's text can repeat the URL.
            Err(ureq::Error::Transport(t)) => Err(Error::Provider(format!(
                "Hetzner API {method} {path}: could not connect ({})",
                t.kind()
            ))),
        }
    }

    /// GET every page of a collection, returning the items under `key`.
    fn get_all(&self, path_with_query: &str, key: &str) -> Result<Vec<serde_json::Value>> {
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let sep = if path_with_query.contains('?') {
                '&'
            } else {
                '?'
            };
            let v = self.send(
                "GET",
                &format!("{path_with_query}{sep}per_page=50&page={page}"),
                None,
            )?;
            if let Some(items) = v[key].as_array() {
                out.extend(items.iter().cloned());
            }
            match v["meta"]["pagination"]["next_page"].as_u64() {
                Some(next) if next as u32 > page => page = next as u32,
                _ => break,
            }
        }
        Ok(out)
    }

    /// Wait for an action to finish. `action` is the object Hetzner returned from the POST.
    fn wait(&self, response: &serde_json::Value) -> Result<()> {
        let Some(id) = response["action"]["id"].as_u64() else {
            return Ok(());
        };
        let started = Instant::now();
        loop {
            let v = self.send("GET", &format!("/actions/{id}"), None)?;
            match v["action"]["status"].as_str() {
                Some("success") => return Ok(()),
                Some("error") => {
                    let m = v["action"]["error"]["message"]
                        .as_str()
                        .unwrap_or("the action failed");
                    return Err(Error::Provider(format!("Hetzner action {id} failed: {m}")));
                }
                _ => {}
            }
            if started.elapsed() > self.give_up_after {
                return Err(Error::Provider(format!(
                    "Hetzner action {id} did not finish in time"
                )));
            }
            std::thread::sleep(self.poll_every);
        }
    }
}

#[derive(Deserialize)]
struct RawServer {
    id: u64,
    name: String,
    status: String,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    server_type: RawType,
    #[serde(default)]
    image: Option<RawImageRef>,
    #[serde(default)]
    public_net: Option<RawPublicNet>,
    #[serde(default)]
    private_net: Vec<RawPrivateNet>,
}

#[derive(Deserialize)]
struct RawPublicNet {
    #[serde(default)]
    firewalls: Vec<RawFirewallRef>,
}

#[derive(Deserialize)]
struct RawFirewallRef {
    id: u64,
}

#[derive(Deserialize)]
struct RawPrivateNet {
    network: u64,
}

#[derive(Deserialize)]
struct RawFirewall {
    id: u64,
    name: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RawImageRef {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct RawImageInfo {
    id: u64,
    #[serde(default)]
    architecture: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct RawType {
    name: String,
}

#[derive(Deserialize)]
struct RawVolume {
    id: u64,
    size: u32,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    server: Option<u64>,
    #[serde(default)]
    location: Option<RawLocation>,
}

#[derive(Deserialize)]
struct RawLocation {
    name: String,
}

#[derive(Deserialize)]
struct RawImage {
    id: u64,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    image_size: Option<f64>,
}

fn convert<T: for<'de> Deserialize<'de>>(items: Vec<serde_json::Value>) -> Result<Vec<T>> {
    items
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(Error::from))
        .collect()
}

impl From<RawServer> for ApiServer {
    fn from(r: RawServer) -> Self {
        Self {
            id: r.id,
            name: r.name,
            status: r.status,
            server_type: r.server_type.name,
            labels: r.labels,
            created: r.created,
            image: r.image.and_then(|i| {
                i.name
                    .filter(|n| !n.is_empty())
                    .or(i.id.map(|id| id.to_string()))
            }),
            firewall_ids: r
                .public_net
                .map(|p| p.firewalls.into_iter().map(|f| f.id).collect())
                .unwrap_or_default(),
            network_ids: r.private_net.into_iter().map(|n| n.network).collect(),
        }
    }
}

const SELECTOR: &str = "label_selector=ozbox-managed%3Dtrue";

impl HcloudApi for UreqApi {
    fn list_servers(&self) -> Result<Vec<ApiServer>> {
        let raw: Vec<RawServer> =
            convert(self.get_all(&format!("/servers?{SELECTOR}"), "servers")?)?;
        Ok(raw.into_iter().map(Into::into).collect())
    }

    fn get_server(&self, id: u64) -> Result<ApiServer> {
        let v = self.send("GET", &format!("/servers/{id}"), None)?;
        let raw: RawServer = serde_json::from_value(v["server"].clone())?;
        Ok(raw.into())
    }

    fn list_volumes(&self) -> Result<Vec<ApiVolume>> {
        let raw: Vec<RawVolume> =
            convert(self.get_all(&format!("/volumes?{SELECTOR}"), "volumes")?)?;
        Ok(raw
            .into_iter()
            .map(|v| ApiVolume {
                id: v.id,
                size_gb: v.size,
                labels: v.labels,
                server: v.server,
                location: v.location.map(|l| l.name),
            })
            .collect())
    }

    fn list_firewalls(&self) -> Result<Vec<ApiFirewall>> {
        let raw: Vec<RawFirewall> =
            convert(self.get_all(&format!("/firewalls?{SELECTOR}"), "firewalls")?)?;
        Ok(raw
            .into_iter()
            .map(|f| ApiFirewall {
                id: f.id,
                name: f.name,
                labels: f.labels,
            })
            .collect())
    }

    fn list_snapshots(&self) -> Result<Vec<ApiImage>> {
        let raw: Vec<RawImage> =
            convert(self.get_all(&format!("/images?type=snapshot&{SELECTOR}"), "images")?)?;
        Ok(raw
            .into_iter()
            .map(|i| ApiImage {
                id: i.id,
                created: i.created,
                labels: i.labels,
                status: i.status.unwrap_or_else(|| "available".into()),
                image_size_gb: i.image_size,
            })
            .collect())
    }

    fn server_action(&self, id: u64, action: &str) -> Result<()> {
        let v = self.send(
            "POST",
            &format!("/servers/{id}/actions/{action}"),
            Some(serde_json::json!({})),
        )?;
        self.wait(&v)
    }

    fn change_type(&self, id: u64, server_type: &str) -> Result<()> {
        let v = self.send(
            "POST",
            &format!("/servers/{id}/actions/change_type"),
            Some(serde_json::json!({ "server_type": server_type, "upgrade_disk": false })),
        )?;
        self.wait(&v)
    }

    fn get_image(&self, image: &str) -> Result<Option<ApiImageInfo>> {
        let raw: Option<RawImageInfo> =
            if image.chars().all(|c| c.is_ascii_digit()) && !image.is_empty() {
                match self.send("GET", &format!("/images/{image}"), None) {
                    Ok(v) => serde_json::from_value(v["image"].clone()).ok(),
                    Err(Error::Provider(m)) if m.contains("HTTP 404") => None,
                    Err(e) => return Err(e),
                }
            } else {
                let encoded: String = image
                    .bytes()
                    .map(|b| match b {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                            (b as char).to_string()
                        }
                        other => format!("%{other:02X}"),
                    })
                    .collect();
                let v = self.send(
                    "GET",
                    &format!("/images?name={encoded}&include_deprecated=true"),
                    None,
                )?;
                v["images"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|i| serde_json::from_value(i.clone()).ok())
            };
        Ok(raw.map(|i| ApiImageInfo {
            id: i.id.to_string(),
            architecture: i.architecture.unwrap_or_else(|| "x86".into()),
            status: i.status.unwrap_or_else(|| "available".into()),
        }))
    }

    fn set_server_labels(&self, id: u64, labels: &BTreeMap<String, String>) -> Result<()> {
        self.send(
            "PUT",
            &format!("/servers/{id}"),
            Some(serde_json::json!({ "labels": labels })),
        )?;
        Ok(())
    }

    fn set_volume_labels(&self, id: u64, labels: &BTreeMap<String, String>) -> Result<()> {
        self.send(
            "PUT",
            &format!("/volumes/{id}"),
            Some(serde_json::json!({ "labels": labels })),
        )?;
        Ok(())
    }

    fn delete_volume(&self, id: u64) -> Result<()> {
        self.send("DELETE", &format!("/volumes/{id}"), None)?;
        Ok(())
    }

    fn resize_volume(&self, id: u64, size_gb: u32) -> Result<()> {
        let v = self.send(
            "POST",
            &format!("/volumes/{id}/actions/resize"),
            Some(serde_json::json!({ "size": size_gb })),
        )?;
        self.wait(&v)
    }

    fn create_snapshot(
        &self,
        server_id: u64,
        description: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<u64> {
        let v = self.send(
            "POST",
            &format!("/servers/{server_id}/actions/create_image"),
            Some(serde_json::json!({ "type": "snapshot", "description": description, "labels": labels })),
        )?;
        let id = v["image"]["id"]
            .as_u64()
            .ok_or_else(|| Error::Provider("Hetzner did not return a snapshot id".into()))?;
        self.wait(&v)?;
        Ok(id)
    }

    fn delete_image(&self, id: u64) -> Result<()> {
        self.send("DELETE", &format!("/images/{id}"), None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_token_is_a_config_error_that_names_the_variable_only() {
        let api = UreqApi::with_token_source("http://127.0.0.1:1", Box::new(|| None));
        match api.list_servers() {
            Err(Error::Config(m)) => assert!(m.contains("HCLOUD_TOKEN")),
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    #[test]
    fn the_token_never_appears_in_a_transport_error() {
        let sentinel = "hc-s3ntinel-token-0123456789";
        let api = UreqApi::with_token_source(
            "http://127.0.0.1:1",
            Box::new(move || Some(sentinel.to_string())),
        );
        let err = match api.list_servers() {
            Err(e) => e,
            Ok(_) => panic!("nothing listens on port 1"),
        };
        assert!(!err.to_string().contains(sentinel));
        assert!(!format!("{err:?}").contains(sentinel));
    }
}
