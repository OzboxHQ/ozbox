//! Budgets and box defaults: a small file next to the CLI config (`settings.json`, or `OZBOX_SETTINGS`), validated on
//! every read and write and enforced when a plan is made. It is never kept in a browser.
//!
//! What is enforced is only what can be checked locally: the cap on running boxes, and the monthly budget measured
//! against the price table the owner entered. With no price for a size the budget cannot be checked, and the plan says
//! so instead of guessing.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ozbox_core::{BoxRecord, BoxState, Error, Operation, Result, Size};
use serde::{Deserialize, Serialize};

pub const MAX_PRICE: f64 = 1_000_000.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Budget {
    /// Monthly compute budget in US dollars. `None` = no budget.
    pub monthly_usd: Option<f64>,
    /// Alert thresholds (50, 80, 100 percent).
    pub alert_50: bool,
    pub alert_80: bool,
    pub alert_100: bool,
    /// `HH:MM`, in the person's time zone (`locale.time_zone`; with none set, the fixed `utc_offset_minutes`). During these hours only urgent alerts are sent.
    pub quiet_from: String,
    pub quiet_to: String,
    /// The owner's offset from UTC in minutes (a fixed offset: there is no time-zone database here, so a change of
    /// daylight-saving time is not followed and the offset is edited by hand).
    pub utc_offset_minutes: i32,
    /// Superseded by Settings > Apps. Old files that still carry it are read and the value is ignored.
    #[serde(skip_serializing)]
    pub email: bool,
    pub in_app: bool,
    /// The most boxes that may run at once. `None` = no cap.
    pub max_running_boxes: Option<u32>,
    /// Monthly price in US dollars of each size, entered from the provider's public price list. Sizes left out are
    /// unknown: no saving is shown for them and the budget is not checked against them.
    pub size_prices_usd: BTreeMap<String, f64>,
    /// A day whose real bill and estimate differ by at least this share of the larger figure is flagged (and alerted)...
    pub drift_alert_pct: f64,
    /// ...when they also differ by at least this much money (in the bill's currency).
    pub drift_alert_min_usd: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            monthly_usd: None,
            alert_50: true,
            alert_80: true,
            alert_100: true,
            quiet_from: "23:00".into(),
            quiet_to: "07:00".into(),
            utc_offset_minutes: 0,
            email: true,
            in_app: true,
            max_running_boxes: None,
            size_prices_usd: BTreeMap::new(),
            drift_alert_pct: crate::bill::DEFAULT_DRIFT_PCT,
            drift_alert_min_usd: crate::bill::DEFAULT_DRIFT_MIN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageChannel {
    Stable,
    Next,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Defaults {
    pub size: Size,
    pub work_disk_gb: u32,
    pub auto_pause_minutes: u32,
    pub always_on: bool,
    pub image_channel: ImageChannel,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            size: Size::M,
            work_disk_gb: 200,
            auto_pause_minutes: 90,
            always_on: false,
            image_channel: ImageChannel::Stable,
        }
    }
}

/// Where alerts go. The secrets of each channel (API key, bot token, webhook address and signing secret) are not here:
/// they live in the secret store and are never returned.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AppsConfig {
    pub email: EmailConfig,
    pub telegram: ToggleConfig,
    pub slack: ToggleConfig,
    pub webhooks: Vec<WebhookConfig>,
    pub sms: crate::notify_config::SmsConfig,
    pub whatsapp: crate::notify_config::WhatsappConfig,
    pub discord: ToggleConfig,
    pub teams: ToggleConfig,
    pub push: ToggleConfig,
    /// Chat with coding agents from Slack and WhatsApp (Telegram's switch is `telegram`).
    pub chat: crate::chat::ChatConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub from: String,
    pub to: Vec<String>,
    /// Which sending service delivers the mail. Resend unless chosen otherwise.
    pub provider: crate::notify_config::EmailProviderKind,
    pub reply_to: String,
    /// Amazon SES only: the region to send from (blank: the profile's own).
    pub region: Option<String>,
    pub smtp: crate::notify_config::SmtpConfig,
    /// Addresses that asked not to be mailed: never sent to, whatever a route says.
    pub unsubscribed: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ToggleConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub id: String,
    pub label: String,
    pub enabled: bool,
    /// The host the webhook posts to, for display. The full address is a secret.
    pub host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    Anthropic,
    Openai,
    OpenaiCompatible,
    Google,
    Bedrock,
    AzureOpenai,
    Vertex,
    Openrouter,
    Mistral,
    Groq,
    Together,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProvider {
    pub id: String,
    pub kind: ModelKind,
    pub label: String,
    /// Only for `openai_compatible`: the endpoint's base address (it ends before `/chat/completions`).
    pub base_url: Option<String>,
    /// An endpoint on this computer (for example a local open-weight server) is allowed.
    pub local_endpoint: bool,
    /// Most this provider may cost in a month, in US dollars.
    pub monthly_cap_usd: Option<f64>,
    /// Bedrock: the AWS region of the person's own account (for example `us-east-1`).
    #[serde(default)]
    pub region: Option<String>,
    /// Azure OpenAI: the name of the person's own resource (the first part of `<name>.openai.azure.com`).
    #[serde(default)]
    pub resource: Option<String>,
    /// A local endpoint that runs on one box (Ollama or vLLM installed from the Tools catalog): the box's name. It is
    /// reached from that box and from the fleet's private network, never from the internet.
    #[serde(default)]
    pub hosted_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelChoice {
    pub provider_id: String,
    pub model: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModelDefaults {
    pub coding: Option<ModelChoice>,
    pub chat: Option<ModelChoice>,
    pub review: Option<ModelChoice>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModelsConfig {
    pub providers: Vec<ModelProvider>,
    pub defaults: ModelDefaults,
    /// Which provider and model each agent engine uses (`claude-code`, `codex`, ...), with a fallback.
    pub engines: std::collections::BTreeMap<String, EngineModel>,
    /// The same, for one box: box name -> engine -> choice. A box's own choice wins over the fleet's.
    pub box_overrides:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, EngineModel>>,
    /// Prices the person entered, in US dollars per million tokens, by `<provider id>/<model>`. They win over the
    /// built-in estimates.
    pub prices: std::collections::BTreeMap<String, ModelPriceOverride>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineModel {
    pub provider_id: String,
    pub model: String,
    #[serde(default)]
    pub fallback: Option<ModelChoice>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPriceOverride {
    pub input_per_mtok_usd: f64,
    pub output_per_mtok_usd: f64,
}

/// Where the person is: the country (ISO 3166-1 alpha-2) and the IANA time zone. Quiet hours, scheduled tasks and
/// the times shown for them follow the time zone, daylight saving included. Unset means UTC and no country.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Locale {
    pub country_code: Option<String>,
    pub time_zone: Option<String>,
}

impl Locale {
    /// The zone times are read in: the person's, else UTC.
    pub fn zone(&self) -> &str {
        self.time_zone.as_deref().unwrap_or("UTC")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub locale: Locale,
    pub budget: Budget,
    pub defaults: Defaults,
    pub apps: AppsConfig,
    pub models: ModelsConfig,
    pub routing: crate::notify_config::RoutingConfig,
    /// Settings → Backups. Additive: an older file has none and gets the defaults (schedule off).
    pub backups: crate::backups::Backups,
}

/// A short id: lower-case letters, digits and dashes.
pub fn valid_id(id: &str, max: usize) -> bool {
    !id.is_empty()
        && id.len() <= max
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(crate) fn plain_text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}

pub(crate) fn email_ok(a: &str) -> bool {
    a.len() <= 254
        && !a.contains(char::is_whitespace)
        && !a.contains(['<', '>', ',', ';', '"'])
        && a.split_once('@').is_some_and(|(l, d)| {
            !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.')
        })
}

fn model_name_ok(m: &str) -> bool {
    !m.is_empty()
        && m.len() <= 100
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

pub(crate) fn bad(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

pub(crate) fn hhmm(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 5
        && b[2] == b':'
        && s[..2].parse::<u32>().is_ok_and(|h| h < 24)
        && s[3..].parse::<u32>().is_ok_and(|m| m < 60)
}

impl Settings {
    /// Whether replacing `self` with `new` lets a model provider spend MORE than before: a monthly cap removed or raised,
    /// or a provider that had one dropped (a provider re-added under another id has no cap, so that is the same raise).
    /// Such a change needs a fresh second factor, like the fleet and per-person limits (ADR 0041).
    #[must_use]
    pub fn model_caps_loosen(&self, new: &Settings) -> bool {
        self.models.providers.iter().any(|old| {
            let Some(was) = old.monthly_cap_usd else {
                return false;
            };
            match new.models.providers.iter().find(|p| p.id == old.id) {
                None => true,
                Some(p) => match p.monthly_cap_usd {
                    None => true,
                    Some(now) => now > was,
                },
            }
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.backups.validate()?;
        let b = &self.budget;
        if let Some(m) = b.monthly_usd {
            if !m.is_finite() || m <= 0.0 || m > MAX_PRICE {
                return Err(bad(
                    "the monthly budget must be more than 0 and at most 1000000",
                ));
            }
        }
        if b.max_running_boxes == Some(0) || b.max_running_boxes.is_some_and(|n| n > 1000) {
            return Err(bad("the running-box cap must be between 1 and 1000"));
        }
        if !b.drift_alert_pct.is_finite()
            || !(1.0..=1000.0).contains(&b.drift_alert_pct)
            || !b.drift_alert_min_usd.is_finite()
            || !(0.0..=MAX_PRICE).contains(&b.drift_alert_min_usd)
        {
            return Err(bad(
                "the bill drift alert needs a share between 1 and 1000 percent and an amount of 0 or more",
            ));
        }
        if !hhmm(&b.quiet_from) || !hhmm(&b.quiet_to) {
            return Err(bad("quiet hours must look like 22:00"));
        }
        for (k, v) in &b.size_prices_usd {
            if k.parse::<Size>().map(|z| z.to_string()).ok().as_deref() != Some(k.as_str()) {
                return Err(bad(format!(
                    "{k:?} is not a size (XS, S, M, L, XL, XXL, GPU-S, GPU-L)"
                )));
            }
            if !v.is_finite() || *v <= 0.0 || *v > MAX_PRICE {
                return Err(bad(format!(
                    "the price for {k} must be more than 0 and at most 1000000"
                )));
            }
        }
        if !(-840..=840).contains(&b.utc_offset_minutes) {
            return Err(bad("the UTC offset must be between -840 and 840 minutes"));
        }
        if let Some(c) = &self.locale.country_code {
            if !crate::timezone::valid_country(c) {
                return Err(bad(
                    "the country must be a two-letter ISO code such as NG or US",
                ));
            }
        }
        if let Some(z) = &self.locale.time_zone {
            if !crate::timezone::valid_zone(z) {
                return Err(bad(
                    "the time zone must be a name such as Africa/Lagos or America/New_York",
                ));
            }
        }
        self.validate_apps()?;
        crate::notify_config::validate(self)?;
        self.validate_models()?;
        let d = &self.defaults;
        if d.work_disk_gb < ozbox_core::BoxSpec::MIN_WORK_DISK_GB || d.work_disk_gb > 65_536 {
            return Err(bad("the default work disk must be between 20 and 65536 GB"));
        }
        if !(5..=1440).contains(&d.auto_pause_minutes) {
            return Err(bad("auto-pause must be between 5 and 1440 minutes"));
        }
        Ok(())
    }

    fn validate_apps(&self) -> Result<()> {
        let a = &self.apps;
        if !a.email.from.is_empty() && !email_ok(&a.email.from) {
            return Err(bad("the email sender address is not a valid address"));
        }
        if a.email.to.len() > 5 || a.email.to.iter().any(|t| !email_ok(t)) {
            return Err(bad("email alerts go to at most 5 valid addresses"));
        }
        if a.email.enabled && (a.email.from.is_empty() || a.email.to.is_empty()) {
            return Err(bad("email alerts need a sender and at least one recipient"));
        }
        if a.webhooks.len() > 10 {
            return Err(bad("at most 10 webhooks"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for w in &a.webhooks {
            if !valid_id(&w.id, 24) || !seen.insert(w.id.as_str()) {
                return Err(bad(
                    "a webhook id must be unique and use lower-case letters, digits and dashes",
                ));
            }
            if !plain_text(&w.label, 40) {
                return Err(bad("a webhook needs a label of up to 40 characters"));
            }
        }
        Ok(())
    }

    fn validate_models(&self) -> Result<()> {
        let m = &self.models;
        if m.providers.len() > 10 {
            return Err(bad("at most 10 model providers"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for p in &m.providers {
            if !valid_id(&p.id, 24) || !seen.insert(p.id.as_str()) {
                return Err(bad("a model provider id must be unique and use lower-case letters, digits and dashes"));
            }
            if !plain_text(&p.label, 40) {
                return Err(bad("a model provider needs a label of up to 40 characters"));
            }
            match (p.kind, &p.base_url) {
                (ModelKind::OpenaiCompatible, Some(u)) => {
                    let guard = if p.local_endpoint {
                        crate::netguard::Guard::Private
                    } else {
                        crate::netguard::Guard::Public
                    };
                    crate::netguard::check_url(guard, u)
                        .map_err(|e| bad(format!("the endpoint address: {e}")))?;
                    if u.len() > 300 {
                        return Err(bad("the endpoint address is too long"));
                    }
                }
                (ModelKind::OpenaiCompatible, None) => {
                    return Err(bad(
                        "an OpenAI-compatible provider needs an endpoint address",
                    ));
                }
                (_, Some(_)) => {
                    return Err(bad(
                        "only an OpenAI-compatible provider has its own endpoint address",
                    ));
                }
                (_, None) => {}
            }
            if p.local_endpoint && p.kind != ModelKind::OpenaiCompatible {
                return Err(bad(
                    "only an OpenAI-compatible provider can be a local endpoint",
                ));
            }
            if let Some(c) = p.monthly_cap_usd {
                if !c.is_finite() || c <= 0.0 || c > MAX_PRICE {
                    return Err(bad(
                        "a monthly spend cap must be more than 0 and at most 1000000",
                    ));
                }
            }
            crate::model_providers::validate_extras(p).map_err(bad)?;
        }
        for (job, choice) in [
            ("coding", &m.defaults.coding),
            ("chat", &m.defaults.chat),
            ("review", &m.defaults.review),
        ] {
            if let Some(c) = choice {
                if !seen.contains(c.provider_id.as_str()) {
                    return Err(bad(format!(
                        "the {job} default names a provider that is not set up"
                    )));
                }
                if !model_name_ok(&c.model) {
                    return Err(bad(format!(
                        "the {job} default model name has characters that are not allowed"
                    )));
                }
            }
        }
        let check = |who: &str, e: &EngineModel| -> Result<()> {
            for (p, m) in std::iter::once((&e.provider_id, &e.model))
                .chain(e.fallback.iter().map(|f| (&f.provider_id, &f.model)))
            {
                if !seen.contains(p.as_str()) {
                    return Err(bad(format!("{who} names a provider that is not set up")));
                }
                if !model_name_ok(m) {
                    return Err(bad(format!(
                        "{who} has a model name with characters that are not allowed"
                    )));
                }
            }
            Ok(())
        };
        if m.engines.len() > 20 || m.box_overrides.len() > 200 {
            return Err(bad("too many engine model choices"));
        }
        for (eng, e) in &m.engines {
            if !crate::model_engines::known(eng) {
                return Err(bad(format!("{eng} is not an agent engine Oz Box knows")));
            }
            check(&format!("the {eng} engine"), e)?;
        }
        for (b, engines) in &m.box_overrides {
            if ozbox_core::BoxName::new(b).is_err() || engines.len() > 20 {
                return Err(bad("a per-box model choice names a box that is not valid"));
            }
            for (eng, e) in engines {
                if !crate::model_engines::known(eng) {
                    return Err(bad(format!("{eng} is not an agent engine Oz Box knows")));
                }
                check(&format!("the {eng} engine on {b}"), e)?;
            }
        }
        if m.prices.len() > 200 {
            return Err(bad("too many model prices"));
        }
        for (k, pr) in &m.prices {
            let ok_key = k
                .split_once('/')
                .is_some_and(|(p, md)| seen.contains(p) && model_name_ok(md));
            let ok_price = |v: f64| v.is_finite() && (0.0..=MAX_PRICE).contains(&v);
            if !ok_key || !ok_price(pr.input_per_mtok_usd) || !ok_price(pr.output_per_mtok_usd) {
                return Err(bad("a model price needs a provider that is set up, a model name and prices from 0 to 1000000"));
            }
        }
        Ok(())
    }

    /// Monthly price of a size, if the owner entered one.
    pub fn price(&self, size: Size) -> Option<f64> {
        self.budget.size_prices_usd.get(&size.to_string()).copied()
    }

    pub fn path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("OZBOX_SETTINGS") {
            return Some(PathBuf::from(p));
        }
        crate::config::Config::path().map(|p| p.with_file_name("settings.json"))
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(t) => {
                let s: Settings = serde_json::from_str(&t)
                    .map_err(|e| bad(format!("{}: {e}", path.display())))?;
                s.validate()?;
                Ok(s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Validate, then replace the file atomically (a crash leaves the old file).
    pub fn save_to(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// The fleet as it would be after `op`, as `(size, running)` per box name.
fn project(existing: &[BoxRecord], op: &Operation) -> BTreeMap<String, (Size, bool)> {
    let mut m: BTreeMap<String, (Size, bool)> = existing
        .iter()
        .map(|r| {
            let running = !matches!(
                r.state,
                BoxState::Paused | BoxState::Destroying | BoxState::InstanceMissing
            );
            (r.spec.name.to_string(), (r.spec.size, running))
        })
        .collect();
    match op {
        Operation::Create { spec } => {
            m.insert(spec.name.to_string(), (spec.size, true));
        }
        Operation::Clone { from, to, .. } => {
            if let Some((size, _)) = m.get(from.as_str()).copied() {
                m.insert(to.to_string(), (size, true));
            }
        }
        Operation::Resume { name } => {
            if let Some(e) = m.get_mut(name.as_str()) {
                e.1 = true;
            }
        }
        Operation::Resize {
            name,
            size: Some(s),
            ..
        } => {
            if let Some(e) = m.get_mut(name.as_str()) {
                e.0 = *s;
            }
        }
        _ => {}
    }
    m
}

fn running_count(f: &BTreeMap<String, (Size, bool)>) -> usize {
    f.values().filter(|(_, r)| *r).count()
}

/// Monthly compute cost of the running boxes, or `None` when any running size has no price.
fn running_cost(settings: &Settings, f: &BTreeMap<String, (Size, bool)>) -> Option<f64> {
    f.values()
        .filter(|(_, r)| *r)
        .map(|(s, _)| settings.price(*s))
        .sum::<Option<f64>>()
}

/// Refuse an operation that would break the cap or the budget. Only operations that add load are checked: pausing,
/// snapshotting or destroying is never blocked, even when the fleet is already over.
pub fn check(settings: &Settings, existing: &[BoxRecord], op: &Operation) -> Result<()> {
    let adds_load = match op {
        Operation::Create { .. } | Operation::Clone { .. } | Operation::Resume { .. } => true,
        Operation::Resize { size, .. } => size.is_some(),
        _ => false,
    };
    if !adds_load {
        return Ok(());
    }
    let before = project(
        existing,
        &Operation::Snapshot {
            name: op.box_name().clone(),
        },
    );
    let after = project(existing, op);
    let b = &settings.budget;
    if let Some(cap) = b.max_running_boxes {
        let (n, was) = (running_count(&after), running_count(&before));
        if n > cap as usize && n > was {
            return Err(bad(format!(
                "the fleet cap is {cap} running boxes and this would make {n}; pause a box or raise the cap in Settings"
            )));
        }
    }
    if let Some(budget) = b.monthly_usd {
        if let (Some(new), Some(old)) = (
            running_cost(settings, &after),
            running_cost(settings, &before),
        ) {
            if new > budget && new > old {
                return Err(bad(format!(
                    "this would raise the estimated monthly compute cost to {new:.2} USD, over the {budget:.2} USD budget; pause a box or raise the budget in Settings"
                )));
            }
        }
    }
    Ok(())
}

/// Fill what a create request left out from the box defaults. Anything the request sets is kept.
pub fn fill_create_defaults(settings: &Settings, body: &mut serde_json::Value) {
    let Some(spec) = body
        .get_mut("operation")
        .filter(|o| o.get("op").and_then(|v| v.as_str()) == Some("create"))
        .and_then(|o| o.get_mut("spec"))
        .and_then(|s| s.as_object_mut())
    else {
        return;
    };
    let unset = |spec: &serde_json::Map<String, serde_json::Value>, k: &str| {
        spec.get(k).is_none_or(serde_json::Value::is_null)
    };
    if unset(spec, "size") {
        if let Ok(v) = serde_json::to_value(settings.defaults.size) {
            spec.insert("size".into(), v);
        }
    }
    if unset(spec, "work_disk_gb") {
        spec.insert("work_disk_gb".into(), settings.defaults.work_disk_gb.into());
    }
    for k in ["image", "region", "from_snapshot"] {
        spec.entry(k).or_insert(serde_json::Value::Null);
    }
    spec.entry("labels")
        .or_insert_with(|| serde_json::json!({}));
}

/// [`check`] against what the provider says exists. Skipped (no cloud call) when nothing is configured to enforce.
pub fn enforce(
    settings: &Settings,
    provider: &dyn ozbox_core::Provider,
    op: &Operation,
) -> Result<()> {
    let b = &settings.budget;
    if b.max_running_boxes.is_none() && b.monthly_usd.is_none() {
        return Ok(());
    }
    check(settings, &provider.list()?, op)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{BoxName, BoxSpec};

    type R = std::result::Result<(), Box<dyn std::error::Error>>;

    fn rec(name: &str, size: Size, state: BoxState) -> std::result::Result<BoxRecord, Error> {
        Ok(BoxRecord {
            spec: BoxSpec::new(BoxName::new(name)?, size),
            state,
            provider: "fake".into(),
            provider_id: None,
            machine_type: None,
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        })
    }

    fn create(name: &str, size: Size) -> std::result::Result<Operation, Error> {
        Ok(Operation::Create {
            spec: BoxSpec::new(BoxName::new(name)?, size),
        })
    }

    fn priced() -> Settings {
        let mut s = Settings::default();
        for (k, v) in [("S", 100.0), ("M", 200.0), ("L", 300.0)] {
            s.budget.size_prices_usd.insert(k.into(), v);
        }
        s
    }

    #[test]
    fn defaults_are_valid_and_bad_values_are_refused() {
        assert!(Settings::default().validate().is_ok());
        let mut s = Settings::default();
        s.budget.monthly_usd = Some(-1.0);
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.budget.max_running_boxes = Some(0);
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.budget.quiet_from = "25:00".into();
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.budget.size_prices_usd.insert("HUGE".into(), 1.0);
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.defaults.work_disk_gb = 5;
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.defaults.auto_pause_minutes = 1;
        assert!(s.validate().is_err());
    }

    #[test]
    fn a_file_round_trips_and_a_bad_file_is_an_error() -> R {
        let d = tempfile::tempdir()?;
        let p = d.path().join("nested/settings.json");
        assert_eq!(Settings::load_from(&p)?, Settings::default());
        let mut s = priced();
        s.budget.monthly_usd = Some(500.0);
        s.save_to(&p)?;
        assert_eq!(Settings::load_from(&p)?, s);
        fs::write(&p, "{\"budget\":{\"colour\":1}}")?;
        assert!(Settings::load_from(&p).is_err());
        fs::write(&p, "{\"budget\":{\"monthly_usd\":-5}}")?;
        assert!(Settings::load_from(&p).is_err());
        let mut invalid = Settings::default();
        invalid.defaults.auto_pause_minutes = 0;
        assert!(invalid.save_to(&p).is_err());
        Ok(())
    }

    #[test]
    fn create_defaults_fill_only_what_is_unset() -> R {
        let mut s = Settings::default();
        s.defaults.size = Size::L;
        s.defaults.work_disk_gb = 300;
        let mut v = serde_json::json!({"operation": {"op": "create", "spec": {"name": "a"}}});
        fill_create_defaults(&s, &mut v);
        assert_eq!(v["operation"]["spec"]["size"], "L");
        assert_eq!(v["operation"]["spec"]["work_disk_gb"], 300);
        let op: Operation = serde_json::from_value(v["operation"].clone())?;
        assert!(matches!(op, Operation::Create { .. }));
        let mut set = serde_json::json!({"operation": {"op": "create", "spec": {"name": "a", "size": "S", "work_disk_gb": 50}}});
        fill_create_defaults(&s, &mut set);
        assert_eq!(set["operation"]["spec"]["size"], "S");
        assert_eq!(set["operation"]["spec"]["work_disk_gb"], 50);
        let mut other = serde_json::json!({"operation": {"op": "pause", "name": "a"}});
        let before = other.clone();
        fill_create_defaults(&s, &mut other);
        assert_eq!(other, before);
        Ok(())
    }

    #[test]
    fn the_running_cap_refuses_a_create_that_would_exceed_it() -> R {
        let mut s = Settings::default();
        s.budget.max_running_boxes = Some(2);
        let fleet = vec![
            rec("a", Size::S, BoxState::Running)?,
            rec("b", Size::S, BoxState::Running)?,
            rec("c", Size::S, BoxState::Paused)?,
        ];
        let e = check(&s, &fleet, &create("d", Size::S)?)
            .err()
            .ok_or("allowed")?;
        assert!(matches!(e, Error::Config(_)));
        assert!(e.to_string().contains("cap is 2"));
        // resuming a third is refused too; pausing and destroying never are
        assert!(check(
            &s,
            &fleet,
            &Operation::Resume {
                name: BoxName::new("c")?
            }
        )
        .is_err());
        assert!(check(
            &s,
            &fleet,
            &Operation::Pause {
                name: BoxName::new("a")?
            }
        )
        .is_ok());
        assert!(check(
            &s,
            &fleet,
            &Operation::Destroy {
                name: BoxName::new("a")?,
                final_snapshot: true,
                keep_old_system_disks: false
            }
        )
        .is_ok());
        // under the cap is fine
        assert!(check(&s, &fleet[..1], &create("d", Size::S)?).is_ok());
        Ok(())
    }

    #[test]
    fn an_already_over_fleet_can_still_resume_nothing_new_but_not_grow() -> R {
        let mut s = Settings::default();
        s.budget.max_running_boxes = Some(1);
        let fleet = vec![
            rec("a", Size::S, BoxState::Running)?,
            rec("b", Size::S, BoxState::Running)?,
        ];
        // resuming a box that already runs adds nothing
        assert!(check(
            &s,
            &fleet,
            &Operation::Resume {
                name: BoxName::new("a")?
            }
        )
        .is_ok());
        assert!(check(&s, &fleet, &create("c", Size::S)?).is_err());
        Ok(())
    }

    #[test]
    fn the_budget_is_checked_only_against_known_prices() -> R {
        let mut s = priced();
        s.budget.monthly_usd = Some(450.0);
        let fleet = vec![
            rec("a", Size::M, BoxState::Running)?,
            rec("p", Size::L, BoxState::Paused)?,
        ];
        // 200 + 100 = 300 <= 450
        assert!(check(&s, &fleet, &create("b", Size::S)?).is_ok());
        // 200 + 300 = 500 > 450
        let e = check(&s, &fleet, &create("b", Size::L)?)
            .err()
            .ok_or("allowed")?;
        assert!(e.to_string().contains("500.00"));
        // resizing up counts, resizing down does not
        let up = Operation::Resize {
            name: BoxName::new("a")?,
            size: Some(Size::XL),
            work_disk_gb: None,
        };
        assert!(
            check(&s, &fleet, &up).is_ok(),
            "XL has no price, so it cannot be checked"
        );
        let up = Operation::Resize {
            name: BoxName::new("a")?,
            size: Some(Size::L),
            work_disk_gb: None,
        };
        assert!(check(&s, &fleet, &up).is_ok(), "300 is under 450");
        s.budget.monthly_usd = Some(250.0);
        assert!(check(&s, &fleet, &up).is_err());
        let down = Operation::Resize {
            name: BoxName::new("a")?,
            size: Some(Size::S),
            work_disk_gb: None,
        };
        assert!(check(&s, &fleet, &down).is_ok());
        // an unknown running size makes the whole sum unknown
        let fleet2 = vec![rec("a", Size::XXL, BoxState::Running)?];
        assert!(check(&s, &fleet2, &create("b", Size::L)?).is_ok());
        Ok(())
    }

    fn prov(id: &str, kind: ModelKind) -> ModelProvider {
        ModelProvider {
            id: id.into(),
            kind,
            label: id.into(),
            base_url: None,
            local_endpoint: false,
            monthly_cap_usd: None,
            region: (kind == ModelKind::Bedrock).then(|| "us-east-1".into()),
            resource: (kind == ModelKind::AzureOpenai).then(|| "res".into()),
            hosted_on: None,
        }
    }

    #[test]
    fn every_provider_kind_validates_with_exactly_the_fields_it_needs() {
        let mut s = Settings::default();
        for (i, k) in crate::model_providers::ALL.into_iter().enumerate() {
            let mut p = prov(&format!("p{i}"), k);
            if k == ModelKind::OpenaiCompatible {
                p.base_url = Some("https://models.example.com/v1".into());
            }
            s.models.providers.push(p);
        }
        s.models.providers.truncate(10);
        assert!(s.validate().is_ok(), "{:?}", s.validate());
        let mut bad = Settings::default();
        let mut b = prov("b", ModelKind::Bedrock);
        b.region = None;
        bad.models.providers.push(b);
        assert!(bad.validate().is_err(), "bedrock without a region");
        let mut bad = Settings::default();
        let mut o = prov("o", ModelKind::Openai);
        o.resource = Some("x".into());
        bad.models.providers.push(o);
        assert!(bad.validate().is_err(), "a resource only belongs to Azure");
    }

    #[test]
    fn a_local_endpoint_may_be_private_but_never_a_link_local_or_public_http_address() {
        let local = |url: &str, local: bool| {
            let mut s = Settings::default();
            let mut p = prov("l", ModelKind::OpenaiCompatible);
            p.base_url = Some(url.into());
            p.local_endpoint = local;
            s.models.providers.push(p);
            s.validate().is_ok()
        };
        assert!(local("http://10.0.0.5:11434/v1", true));
        assert!(local("http://127.0.0.1:8000/v1", true));
        assert!(local("http://192.168.1.2/v1", true));
        assert!(
            !local("http://10.0.0.5:11434/v1", false),
            "not marked as local"
        );
        assert!(
            !local("http://169.254.169.254/v1", true),
            "the metadata address"
        );
        assert!(
            !local("http://example.com/v1", true),
            "a public address needs https"
        );
        assert!(local("https://models.example.com/v1", false));
    }

    #[test]
    fn engine_choices_and_prices_must_name_a_provider_that_is_set_up() {
        let mut s = Settings::default();
        s.models.providers.push(prov("a", ModelKind::Anthropic));
        let choice = |p: &str| EngineModel {
            provider_id: p.into(),
            model: "m".into(),
            fallback: None,
        };
        s.models.engines.insert("claude-code".into(), choice("a"));
        assert!(s.validate().is_ok());
        s.models
            .engines
            .insert("claude-code".into(), choice("gone"));
        assert!(s.validate().is_err());
        s.models.engines.insert("claude-code".into(), choice("a"));
        s.models.engines.insert("not-an-engine".into(), choice("a"));
        assert!(s.validate().is_err());
        s.models.engines.remove("not-an-engine");
        s.models
            .box_overrides
            .entry("dev".into())
            .or_default()
            .insert("codex".into(), choice("a"));
        assert!(s.validate().is_ok());
        s.models
            .box_overrides
            .entry("Bad Box".into())
            .or_default()
            .insert("codex".into(), choice("a"));
        assert!(s.validate().is_err());
        s.models.box_overrides.remove("Bad Box");
        s.models.prices.insert(
            "a/m".into(),
            ModelPriceOverride {
                input_per_mtok_usd: 1.0,
                output_per_mtok_usd: 2.0,
            },
        );
        assert!(s.validate().is_ok());
        s.models.prices.insert(
            "zzz/m".into(),
            ModelPriceOverride {
                input_per_mtok_usd: 1.0,
                output_per_mtok_usd: 2.0,
            },
        );
        assert!(s.validate().is_err());
    }

    #[test]
    fn a_model_cap_removed_raised_or_dropped_with_its_provider_loosens() {
        let mut old = Settings::default();
        let mut a = prov("a", ModelKind::Openai);
        a.monthly_cap_usd = Some(50.0);
        old.models.providers = vec![a.clone()];
        let with = |cap: Option<f64>| {
            let mut n = old.clone();
            n.models.providers[0].monthly_cap_usd = cap;
            n
        };
        assert!(old.model_caps_loosen(&with(None)), "removed");
        assert!(old.model_caps_loosen(&with(Some(80.0))), "raised");
        assert!(!old.model_caps_loosen(&with(Some(20.0))), "lowered");
        assert!(!old.model_caps_loosen(&with(Some(50.0))), "same");
        let mut gone = old.clone();
        gone.models.providers.clear();
        assert!(old.model_caps_loosen(&gone), "provider with a cap dropped");
        // a provider with no cap can gain one, be dropped, or be added
        let mut free = old.clone();
        free.models.providers[0].monthly_cap_usd = None;
        assert!(!free.model_caps_loosen(&with(Some(5.0))));
        assert!(!free.model_caps_loosen(&gone));
    }

    #[test]
    fn an_older_settings_file_without_the_new_fields_still_loads() {
        let old = r#"{"models":{"providers":[{"id":"a","kind":"openai","label":"A","base_url":null,"local_endpoint":false,"monthly_cap_usd":null}],"defaults":{}}}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert!(s.validate().is_ok());
        assert!(s.models.engines.is_empty() && s.models.providers[0].region.is_none());
    }
}
