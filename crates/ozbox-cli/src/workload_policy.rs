//! What a project declares about its commands: which secret names each named command may receive, which environment
//! variables carry them, the program the command must start with, and where it runs. The declaration is stored in the
//! encrypted store under `workload-policy.<project>` as a structured record (the compact JSON, up to [`MAX_DECLARATION_BYTES`]; an
//! earlier version kept it as hex of JSON, which is still read) and is what `ozbox env run --named NAME` follows. A caller's own `--allow` list is not consulted once a policy exists:
//! an agent does not get to widen what its command may receive by asking for more.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::secrets::{SecretError, SecretStore};
use crate::secrets_enc::workload_name;

/// A secret name a command receives in its environment: under its own name, or under another (`"as"`). Written in a
/// declaration as `"NAME"` or `{"name":"NAME","as":"OTHER"}`; a plain name serializes back to a plain string, so a
/// declaration made before renames keeps its bytes (and the digest an approval covers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    pub name: String,
    pub rename: Option<String>,
}

impl EnvEntry {
    #[cfg(test)]
    pub fn plain(name: &str) -> EnvEntry {
        EnvEntry {
            name: name.to_string(),
            rename: None,
        }
    }
    /// The variable the command sees.
    pub fn target(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenamedRepr {
    name: String,
    #[serde(rename = "as")]
    rename: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EnvEntryRepr {
    Plain(String),
    Renamed(RenamedRepr),
}

impl<'de> Deserialize<'de> for EnvEntry {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match EnvEntryRepr::deserialize(d)? {
            EnvEntryRepr::Plain(name) => EnvEntry { name, rename: None },
            EnvEntryRepr::Renamed(r) => EnvEntry {
                name: r.name,
                rename: Some(r.rename),
            },
        })
    }
}

impl Serialize for EnvEntry {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match &self.rename {
            None => s.serialize_str(&self.name),
            Some(r) => {
                let mut m = s.serialize_map(Some(2))?;
                m.serialize_entry("name", &self.name)?;
                m.serialize_entry("as", r)?;
                m.end()
            }
        }
    }
}

/// A file the owner approved by its content: relative to the project folder, with the SHA-256 of its bytes. At every run
/// the launcher checks it and runs the verified copy (see `runner_pins`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub file: String,
    pub sha256: String,
}

/// A folder the owner approved by its content (`node_modules/some-package`): relative to the project folder, with the digest of
/// every file under it (`runner_setup::tree_digest`, printed by `ozbox env policy pin --tree`). At every run the launcher checks
/// it and runs a root-owned copy bound over the folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreePin {
    pub path: String,
    pub sha256: String,
}

/// A catalog tool the project's commands may run, with, optionally, the digest of the installed tree the owner approved.
/// Written as `"node"` or `{"name":"node","sha256":"..."}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRef {
    pub name: String,
    pub sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedToolRepr {
    name: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ToolRefRepr {
    Plain(String),
    Pinned(PinnedToolRepr),
}

impl<'de> Deserialize<'de> for ToolRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match ToolRefRepr::deserialize(d)? {
            ToolRefRepr::Plain(name) => ToolRef { name, sha256: None },
            ToolRefRepr::Pinned(t) => ToolRef {
                name: t.name,
                sha256: Some(t.sha256),
            },
        })
    }
}

impl Serialize for ToolRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match &self.sha256 {
            None => s.serialize_str(&self.name),
            Some(h) => {
                let mut m = s.serialize_map(Some(2))?;
                m.serialize_entry("name", &self.name)?;
                m.serialize_entry("sha256", h)?;
                m.end()
            }
        }
    }
}

/// Browsers a project may ask for (Playwright's names).
pub const BROWSERS: [&str; 3] = ["chromium", "firefox", "webkit"];
/// The most a plain variable's value may hold.
pub const MAX_VAR_VALUE: usize = 512;
/// The most a stored declaration may be, as the compact JSON the box keeps. A real application's declaration (a service, a few
/// file pins, a folder pin for every package its build traced) is several KB; this is the limit of the RECORD, not of a secret.
/// Every other limit of a declaration is a count: commands ([`MAX_COMMANDS`]), pinned files ([`MAX_PINS`]) and folders
/// ([`MAX_TREE_PINS`]) per command, plain variables ([`MAX_VAR_VALUE`] each), tools and browsers.
pub const MAX_DECLARATION_BYTES: usize = crate::secrets::MAX_RECORD_VALUE;
/// The most commands one declaration names.
pub const MAX_COMMANDS: usize = 64;
/// The most files one command may pin.
pub const MAX_PINS: usize = 16;
/// The most folders one command may pin (a package and the packages it needs).
pub const MAX_TREE_PINS: usize = 64;

/// `chromium-1169`, `chromium_headless_shell-1169`, `ffmpeg-1011`, `firefox-1488`, `webkit-2140`: a Playwright browser directory.
pub fn browser_dir_ok(d: &str) -> bool {
    let Some((kind, rev)) = d.rsplit_once('-') else {
        return false;
    };
    [
        "chromium",
        "chromium_headless_shell",
        "ffmpeg",
        "firefox",
        "webkit",
    ]
    .contains(&kind)
        && !rev.is_empty()
        && rev.len() <= 12
        && rev.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicy {
    /// The names this command may receive.
    pub allow: Vec<String>,
    /// Of those, the ones put in the command's environment, under their own name or a rename.
    #[serde(default)]
    pub env: Vec<EnvEntry>,
    /// The program and arguments the command must start with. Empty: any program. A command with `pin` takes exactly this
    /// and nothing more.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Plain (never secret) variables with fixed values, set for every run of this command.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// The environments (`staging`) this command may take its secrets from. Required for a command that receives a secret: the caller
    /// names the environment on every run, and must not be able to steer a key at a value it chose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envs: Vec<String>,
    /// Plain variable names the caller may supply (`ozbox env run --pass NAME=value`). Checked like a fixed value, and
    /// never a way to receive a secret.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pass: Vec<String>,
    /// Files whose content the owner approved with this declaration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin: Vec<Pin>,
    /// Folders whose content the owner approved (a package under `node_modules`): what a pinned script loads. Each is run from a
    /// verified copy, like a pinned file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin_tree: Vec<TreePin>,
    /// The command drives a browser: it is told where the project's browsers are. Never for a command that receives a secret.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub browser: bool,
    /// A long-running program (see `runner`): started and stopped with `--start` / `--stop`, listening on loopback `port`.
    /// It may receive secrets (`allow` / `env`) as systemd credentials, under every rule a secret command meets (ADR 0029
    /// Amendment 12).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub service: bool,
    /// A service that receives secrets and expects them as environment variables: the launcher starts it through
    /// `ozbox secrets exec-cred`, which sets each credential as a variable of the same name. Without it the program reads
    /// `$CREDENTIALS_DIRECTORY/NAME` itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub credential_env: bool,
    /// Names of stored values that were marked PUBLIC at import (`ozbox secrets import --public NAME`): a public URL, a Supabase
    /// anonymous key. Delivered as plain environment, never as a secret. Naming one here does not make it public: the stored
    /// entry must carry the mark, and the caller's environment must be one of `envs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The path a health check asks for on `port` (default `/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
}

impl CommandPolicy {
    /// Whether this command is given a secret. A command that is gets a runner user of its own (`runner::runner_user_for`) and
    /// the strictest rules: pinned tools, no browser, nothing that loads code from a folder an agent can write.
    pub fn bears_secrets(&self) -> bool {
        !self.allow.is_empty() || !self.env.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The project's folder on /work, where its commands run.
    #[serde(default)]
    pub dir: String,
    /// Folders under `dir` a command may write (build output). Everything else stays read-only.
    #[serde(default)]
    pub writable: Vec<String>,
    /// Where the project's commands may send data: host names (`api.example.com`, `*.example.com`, optionally `:port`,
    /// 443 by default). Empty: nowhere but this machine's own loopback. Declared once for the project; see `egress`.
    #[serde(default)]
    pub egress: Vec<String>,
    /// Raw TCP destinations for wire protocols (a database, a cache, mail submission): each gets a loopback listener for the
    /// length of a command, and the command is told its port in the environment. See `egress`.
    #[serde(default)]
    pub tcp: Vec<crate::egress::TcpDest>,
    /// Catalog tools the commands run (`node`): a root-owned read-only copy is put on their PATH (see `runner_setup`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolRef>,
    /// Browsers the commands need (`chromium`): a root-owned read-only cache, `PLAYWRIGHT_BROWSERS_PATH`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub browsers: Vec<String>,
    /// For each browser directory the commands may use (`chromium-1169`), the digest of the installed tree the owner approved.
    /// A browser directory with no entry here is never copied for a runner.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub browser_digests: BTreeMap<String, String>,
    /// Identifiers of PRODUCTION for this project that the owner lists: a Supabase project ref, a Stripe account, a host. A value a
    /// command would receive (a stored key, or one passed by hand) that contains one, or whose JWT payload does, is refused at launch,
    /// whatever environment it was stored under.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub production_ids: Vec<String>,
    pub commands: BTreeMap<String, CommandPolicy>,
}

fn err(m: &str) -> SecretError {
    SecretError(m.to_string())
}

pub fn secret_name(project: &str) -> Result<String, SecretError> {
    // a project name is checked the way a workload secret's is
    workload_name(project, "x", "X")?;
    Ok(format!("workload-policy.{project}"))
}

fn seg_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn var_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.as_bytes()[0].is_ascii_digit()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// The Playwright cache directories a declared browser needs: its own, the headless shell for chromium, and ffmpeg for recordings.
pub fn implied_kinds(browser: &str) -> Vec<&'static str> {
    match browser {
        "chromium" => vec!["chromium", "chromium_headless_shell", "ffmpeg"],
        "firefox" => vec!["firefox", "ffmpeg"],
        "webkit" => vec!["webkit", "ffmpeg"],
        _ => Vec::new(),
    }
}

/// A pinned secret command runs `node FILE` and nothing else (G5 fifth round, NV4-H1). The import check and the writable-folder rules
/// model Node's lookup; another program puts the script's own folder, or the working folder, on ITS lookup path (Python's
/// `sys.path[0]`, `python -m`), so a writable `helper` beside a pinned `helper.py` would be imported in place of it, with the key in
/// the environment. Python and the rest need a design of their own, so they are refused rather than half covered.
fn node_only(name: &str, c: &CommandPolicy) -> Result<(), SecretError> {
    match c.argv.first() {
        Some(first) if first == "node" => match c.argv.get(1) {
            // G5 sixth round, NV5-H1: the word after `node` is the script, and nothing may come before it. `node tests/mint`
            // (no extension), `-e`, `-p`, `--import=`, `--require` and `--loader` all name code by a route the closure check does
            // not follow. Words after the script belong to the script; Node does not read them as options.
            Some(entry) if !entry.starts_with('-') && crate::runner_imports::is_script(entry) => Ok(()),
            Some(entry) => Err(SecretError(format!(
                "the command {name} receives a secret, so its words must be `node FILE`, where FILE is a pinned script ending in .js, .mjs, .cjs, .ts, .mts or .cts, and no option may come before it: {entry} is not that (an option like -e, -p, --import or --require, or a script named without its extension, loads code the pin does not cover)"
            ))),
            None => Err(SecretError(format!(
                "the command {name} receives a secret, so its words must be `node FILE`, where FILE is a pinned script: it names no script"
            ))),
        },
        Some(first) => Err(SecretError(format!(
            "the command {name} receives a secret, so its program must be `node`: only Node scripts can be pinned today, and {first} is not (a program of another kind looks for the code it imports in folders an agent can write). Mint the secret in a Node script"
        ))),
        None => Ok(()),
    }
}

fn path_ok(s: &str) -> bool {
    s.len() <= 200
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

fn pin_path_ok(s: &str) -> bool {
    // a package scope (`node_modules/@scope/name`) has an `@`
    !s.is_empty()
        && !s.starts_with('/')
        && !s.ends_with('/')
        && (path_ok(s) || path_ok(&s.replace('@', "_")))
        && s.split('/').all(|seg| !seg.is_empty() && seg != ".")
}

fn sha_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Names a declaration may not set for a command, however they are set: the ones that choose which program runs, where it
/// looks for code, or where it sends traffic. The owner approves the declaration, but a typo here would hand the command a
/// way to load code the agent wrote, so it is refused rather than trusted.
pub fn reserved_name(name: &str, tcp: &[crate::egress::TcpDest]) -> Option<&'static str> {
    let up = name.to_ascii_uppercase();
    const EXACT: [&str; 27] = [
        // systemd's own names for a unit: set by the manager, and read by the credential shim and by programs that trust them
        "CREDENTIALS_DIRECTORY",
        "RUNTIME_DIRECTORY",
        "STATE_DIRECTORY",
        "CACHE_DIRECTORY",
        "LOGS_DIRECTORY",
        "CONFIGURATION_DIRECTORY",
        "INVOCATION_ID",
        "NOTIFY_SOCKET",
        "MAINPID",
        "JOURNAL_STREAM",
        "WATCHDOG_USEC",
        "WATCHDOG_PID",
        "TRIGGER_UNIT",
        "PATH",
        "HOME",
        "SHELL",
        "IFS",
        "ENV",
        "BASH_ENV",
        "USER",
        "LOGNAME",
        "PWD",
        "TMPDIR",
        "NODE_OPTIONS",
        "NODE_PATH",
        "TERM",
        "LANG",
    ];
    if EXACT.contains(&up.as_str()) {
        return Some("it decides how the command starts or where it looks for programs");
    }
    const PREFIX: [&str; 18] = [
        "LISTEN_",
        "SYSTEMD_",
        "MONITOR_",
        "EXIT_",
        "SERVICE_RESULT",
        "LD_",
        "DYLD_",
        "NODE_",
        "NPM_CONFIG_",
        "PYTHON",
        "PERL",
        "RUBY",
        "JAVA_TOOL",
        "_JAVA",
        "GIT_",
        "PLAYWRIGHT_",
        "OZBOX_",
        "BUN_",
    ];
    if PREFIX.iter().any(|p| up.starts_with(p)) {
        return Some("it can load code the agent wrote, or is set by Oz Box");
    }
    if up.ends_with("_PROXY")
        || up == "NO_PROXY"
        || up.starts_with("SSL_CERT")
        || up.starts_with("NODE_EXTRA")
    {
        return Some("it is set by the egress proxy or decides what the command trusts");
    }
    for d in tcp {
        let e = d.env.to_ascii_uppercase();
        if ["HOST", "PORT", "ADDR", "REMOTE_HOST"]
            .iter()
            .any(|k| up == format!("{e}_{k}"))
        {
            return Some("it is set for a declared tcp destination");
        }
    }
    None
}

/// A name that says what it holds is a secret, whatever its value looks like.
pub fn name_says_secret(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    [
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "PRIVATE",
        "CREDENTIAL",
    ]
    .iter()
    .any(|w| up.contains(w))
}

/// A Supabase service-role key is named for its role, not with a word `name_says_secret` knows.
pub fn name_says_service_role(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    up.contains("SERVICE_ROLE") || up.contains("SERVICEROLE")
}

/// What a plain variable's value may be: short, made of characters that need no quoting anywhere, and nothing that looks
/// like a key. `Err` is a sentence that continues "the value of NAME ...".
pub fn plain_value_ok(name: &str, v: &str) -> Result<(), String> {
    if v.is_empty() || v.len() > MAX_VAR_VALUE {
        return Err(format!("must be 1 to {MAX_VAR_VALUE} characters"));
    }
    if !v.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b',' | b'=' | b'-'
            )
    }) {
        return Err("may hold only letters, digits and . _ : / @ + , = -".into());
    }
    if let Some(w) = crate::workload::live_reason(name, v, "") {
        return Err(format!("looks like a production value ({w})"));
    }
    if looks_like_secret(v) {
        return Err("looks like a key or token: store it as a secret and declare its name".into());
    }
    Ok(())
}

/// The most characters of a public value (a JWT-shaped anonymous key is a few hundred).
pub const MAX_PUBLIC_VALUE: usize = 2048;

/// What a value marked public may be: plain text that needs no quoting wherever it travels (a unit property, a JSON line).
/// Unlike [`plain_value_ok`] it may look like a key: the person marked it public at import, and `public_mark_refusal` has
/// already refused the kinds that are only ever secret. `Err` is a sentence.
pub fn public_value_ok(v: &str) -> Result<(), String> {
    if v.is_empty() || v.len() > MAX_PUBLIC_VALUE {
        return Err(format!("must be 1 to {MAX_PUBLIC_VALUE} characters"));
    }
    if !v.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b',' | b'=' | b'-'
            )
    }) {
        return Err("may hold only letters, digits and . _ : / @ + , = -".into());
    }
    Ok(())
}

/// Kinds of value that are only ever secret, whatever name they are stored under: provider keys, tokens and private keys.
const SECRET_PREFIXES: [&str; 20] = [
    "sk_",
    "sk-",
    "rk_",
    "whsec_",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xox",
    "xai-",
    "AKIA",
    "ASIA",
    "sb_secret_",
    "sbp_",
    "npm_",
    "SG.",
    "re_",
    "hf_",
    "-----BEGIN",
];

/// Kinds of value that are meant to be shipped to a browser: they may be marked public although they look like keys.
const PUBLIC_PREFIXES: [&str; 4] = ["pk_test_", "pk_live_", "sb_publishable_", "phc_"];

/// Variable-name prefixes of the frameworks that ship a value to the browser on purpose (ADR 0041 section 9). A name with one of
/// these says "this is configuration the page carries", so the commit barrier does not hold such a value for being a stored one.
/// It never makes a key public: [`public_kind_value_ok`] still applies every rule of [`public_mark_refusal`] to the value.
/// The bare `PUBLIC_` prefix is **not** here: SvelteKit's and Astro's `PUBLIC_*` are browser values by their own rule, but servers
/// and shells use the same prefix for values that never leave the box. Such a project marks its values public at import.
pub const PUBLIC_NAME_PREFIXES: [&str; 6] = [
    "NEXT_PUBLIC_",
    "VITE_",
    "EXPO_PUBLIC_",
    "NUXT_PUBLIC_",
    "REACT_APP_",
    "GATSBY_",
];

/// Whether `name` is of a known public kind. Only the variable's own name counts (`workload.app.staging.NEXT_PUBLIC_X` is read as
/// `NEXT_PUBLIC_X`), and only at its start.
pub fn is_public_kind_name(name: &str) -> bool {
    let var = name.rsplit('.').next().unwrap_or(name);
    PUBLIC_NAME_PREFIXES.iter().any(|p| var.starts_with(p))
}

/// Addresses that are themselves a credential: whoever holds the address can post as the owner or open the document. They are
/// never public, whatever name they sit under (ADR 0041 section 9).
const SECRET_ADDRESS_MARKS: [&str; 6] = [
    "hooks.slack.com/services/",
    "discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
    ".webhook.office.com/",
    "outlook.office.com/webhook",
    "script.google.com/macros/s/",
];

/// Why an address cannot be public, if it cannot: it carries user info (`scheme://user:password@host`, or `scheme:user@host`), or
/// it is a kind of address that is itself a credential (a chat webhook, an Apps Script link). It stands in front of both ways a
/// value becomes public (a person's mark, and a name of a public kind), because both end in [`public_mark_refusal`].
/// A value that is not an address (no scheme and a colon, as in an e-mail address) is not judged here.
fn address_refusal(value: &str) -> Option<&'static str> {
    let low = value.to_ascii_lowercase();
    if SECRET_ADDRESS_MARKS.iter().any(|m| low.contains(m)) {
        return Some("it is an address that is itself a credential (a webhook or a private link)");
    }
    let (scheme, rest) = value.split_once(':')?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphabetic() || matches!(b, b'+' | b'.' | b'-'))
        || scheme.eq_ignore_ascii_case("mailto")
    {
        return None;
    }
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    authority
        .contains('@')
        .then_some("it is an address with a user name or password in it")
}

/// A value shaped like a JWT: three dot-separated base64url parts, the first of which decodes to a JSON object (so a host name
/// such as `api.example.com` is not one). Returns the decoded payload when it is JSON, `None` inside `Some` when it is not.
fn jwt_shape(value: &str) -> Option<Option<serde_json::Value>> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let b64 = |p: &str| {
        p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
    };
    if !parts.iter().all(|p| b64(p)) {
        return None;
    }
    let json = |p: &str| {
        crate::serve::auth::b64::decode_url(p)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
    };
    let head = json(parts[0]);
    if !(value.starts_with("eyJ") || head.as_ref().is_some_and(|h| h.is_object())) {
        return None;
    }
    Some(json(parts[1]))
}

/// Why a value cannot be marked public, if it cannot. A mark is a person's word, but only for a value that is known to be public:
/// a JWT whose payload says `role: anon` (parsed, never searched for text); a value with a known public prefix; or plain text
/// that [`looks_like_secret`] does not flag. Everything else is refused, including the always-secret prefixes, a JWT of any other
/// role or one that cannot be read, a production-looking value and a name that says it is secret. It is run at import AND again
/// when the value is handed out, so a rule added later also covers values stored earlier.
pub fn public_mark_refusal(name: &str, value: &str, live: bool) -> Option<&'static str> {
    if name_says_secret(name) || name_says_service_role(name) {
        return Some("its name says it is secret");
    }
    if live {
        return Some("it looks like a production value");
    }
    if let Some(why) = address_refusal(value) {
        return Some(why);
    }
    if let Err(_why) = public_value_ok(value) {
        return Some("a public value is plain text (letters, digits and . _ : / @ + , = -, up to 2048 characters)");
    }
    if SECRET_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return Some("it is a kind of key that is only ever secret");
    }
    if value.to_ascii_lowercase().contains("service_role") {
        return Some("it is a service-role key, which can read everything");
    }
    if let Some(payload) = jwt_shape(value) {
        return match payload {
            Some(p) if p.get("role").and_then(|r| r.as_str()) == Some("anon") => None,
            Some(_) => Some("it is a token that is not an anonymous (client-side) key"),
            None => Some("it looks like a token whose contents cannot be read"),
        };
    }
    if PUBLIC_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return None;
    }
    if looks_like_secret(value) {
        return Some("it looks like a key or token, and is not a kind that is known to be public");
    }
    None
}

fn is_uuid(w: &str) -> bool {
    w.len() == 36
        && w.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn looks_like_secret(v: &str) -> bool {
    const STARTS: [&str; 12] = [
        "sk_",
        "pk_",
        "rk_",
        "whsec_",
        "eyJ",
        "ghp_",
        "gho_",
        "ghs_",
        "github_pat_",
        "xox",
        "AKIA",
        "-----BEGIN",
    ];
    if STARTS.iter().any(|p| v.starts_with(p)) {
        return true;
    }
    // a long unbroken run of letters and digits with both kinds in it is how a generated token looks; a path or a UUID
    // has separators that break the runs
    v.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .filter(|w| !is_uuid(w))
        .any(|run| {
            run.len() >= 32
                && run.bytes().any(|b| b.is_ascii_digit())
                && run.bytes().any(|b| b.is_ascii_alphabetic())
        })
}

impl Policy {
    /// Refuse a declaration that could not be followed safely.
    pub fn validate(&self) -> Result<(), SecretError> {
        self.validate_inner(true)
    }

    /// The shape of a declaration only: what is needed to LOAD one stored by an earlier version. The rules for a command that receives
    /// a secret (pins, digests, no browser) are not applied, so a declaration that no longer meets them can still be read, shown and
    /// replaced; [`Policy::secret_rules`] refuses its secret commands at launch and says what to change.
    pub fn validate_shape(&self) -> Result<(), SecretError> {
        self.validate_inner(false)
    }

    /// [`Policy::validate`] for a declaration read back from the store at launch: the folder was checked when it was written, and is
    /// checked again by setup, so it is not re-judged here.
    pub fn validate_at_launch(&self) -> Result<(), SecretError> {
        self.validate_full(true, false)
    }

    fn validate_inner(&self, strict: bool) -> Result<(), SecretError> {
        self.validate_full(strict, true)
    }

    fn validate_full(&self, strict: bool, check_dir: bool) -> Result<(), SecretError> {
        if check_dir
            && !self.dir.is_empty()
            && !(self.dir.starts_with("/work/") && path_ok(&self.dir))
        {
            return Err(err("the project folder must be a path under /work"));
        }
        for w in &self.writable {
            if w.is_empty() || w.starts_with('/') || !path_ok(w) {
                return Err(err(
                    "a writable folder must be a plain path inside the project",
                ));
            }
        }
        crate::egress::parse_rules(&self.egress).map_err(err)?;
        crate::egress::validate_tcp(&self.tcp).map_err(err)?;
        if self.production_ids.len() > 32
            || self.production_ids.iter().any(|i| {
                i.len() < 4
                    || i.len() > 128
                    || !i.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')
                    })
            })
        {
            return Err(err("production identifiers are at most 32 words of 4 to 128 letters, digits and . _ - :"));
        }
        if self.commands.is_empty() || self.commands.len() > MAX_COMMANDS {
            return Err(err("declare between 1 and 64 commands"));
        }
        for (name, c) in &self.commands {
            if !seg_ok(name, 32) {
                return Err(err(
                    "a command name is 1 to 32 lowercase letters, digits or dashes",
                ));
            }
            if !c.allow.iter().all(|n| var_ok(n)) || !c.env.iter().all(|e| var_ok(&e.name)) {
                return Err(err(
                    "a secret name must look like an environment variable name",
                ));
            }
            if !c.env.iter().all(|e| c.allow.contains(&e.name)) {
                return Err(err("a name put in the environment must also be allowed"));
            }
            if c.argv.len() > 32 || c.argv.iter().any(|a| a.is_empty() || a.len() > 200) {
                return Err(err("the program of a command is at most 32 words"));
            }
            self.validate_command(name, c, strict)?;
        }
        self.validate_environment(strict)?;
        Ok(())
    }

    fn validate_command(
        &self,
        name: &str,
        c: &CommandPolicy,
        strict: bool,
    ) -> Result<(), SecretError> {
        // every name the command's environment ends up with, once: a secret, a rename, a fixed value and a passed one can
        // never share a name, so none can overwrite another
        let mut seen: Vec<String> = Vec::new();
        let mut take = |n: &str, what: &str| -> Result<(), SecretError> {
            if seen.iter().any(|x| x == n) {
                return Err(SecretError(format!(
                    "{n} is set twice for the command {name} ({what})"
                )));
            }
            seen.push(n.to_string());
            Ok(())
        };
        for e in &c.env {
            if let Some(r) = &e.rename {
                if !var_ok(r) {
                    return Err(err(
                        "a renamed secret must look like an environment variable name",
                    ));
                }
            }
            // G5 eighth round, NV7-I2: a RENAME onto a reserved name is refused when the declaration is read (it always was). A secret
            // declared with no rename is checked when it is set, in `secret_rules`, so an older stored declaration still loads
            let t = e.target();
            if e.rename.is_some() {
                if let Some(why) = reserved_name(t, &self.tcp) {
                    return Err(SecretError(format!(
                        "{t} cannot be set for a command: {why}"
                    )));
                }
            }
            take(t, "secret")?;
        }
        for (k, v) in &c.vars {
            if !var_ok(k) {
                return Err(err(
                    "a variable name is capital letters, digits and underscores",
                ));
            }
            if let Some(why) = reserved_name(k, &self.tcp) {
                return Err(SecretError(format!(
                    "{k} cannot be set for a command: {why}"
                )));
            }
            plain_value_ok(k, v).map_err(|w| SecretError(format!("the value of {k} {w}")))?;
            take(k, "fixed value")?;
        }
        for k in &c.pass {
            if !var_ok(k) {
                return Err(err(
                    "a passed name is capital letters, digits and underscores",
                ));
            }
            if let Some(why) = reserved_name(k, &self.tcp) {
                return Err(SecretError(format!(
                    "{k} cannot be passed to a command: {why}"
                )));
            }
            if name_says_secret(k) {
                return Err(SecretError(format!(
                    "{k} reads like a secret: a secret is stored and declared in `allow`, never passed"
                )));
            }
            take(k, "passed value")?;
        }
        for k in &c.public {
            if !var_ok(k) {
                return Err(err(
                    "a public name is capital letters, digits and underscores",
                ));
            }
            if let Some(why) = reserved_name(k, &self.tcp) {
                return Err(SecretError(format!(
                    "{k} cannot be set for a command: {why}"
                )));
            }
            if name_says_secret(k) || name_says_service_role(k) {
                return Err(SecretError(format!(
                    "{k} reads like a secret: a public value is a public URL or an anonymous key, and a secret is declared in `allow`"
                )));
            }
            take(k, "public value")?;
        }
        if !c.public.is_empty() && c.envs.is_empty() {
            return Err(SecretError(format!(
                "the command {name} names public values but no environment: add \"envs\": [\"staging\"], because the caller chooses the environment on every run"
            )));
        }
        if c.credential_env && !(c.service && !c.env.is_empty()) {
            return Err(err(
                "credential_env belongs to a service that receives a secret (it has `env` entries)",
            ));
        }
        if c.vars.len() + c.pass.len() + c.public.len() > 32 {
            return Err(err("a command takes at most 32 plain variables"));
        }
        if c.pin.len() > MAX_PINS {
            return Err(err("a command pins at most 16 files"));
        }
        let mut files: Vec<&str> = Vec::new();
        for p in &c.pin {
            if !pin_path_ok(&p.file) {
                return Err(SecretError(format!(
                    "a pinned file is a plain path inside the project folder: {}",
                    p.file
                )));
            }
            if !sha_ok(&p.sha256) {
                return Err(SecretError(format!(
                    "the digest of {} must be 64 lowercase hexadecimal digits (a SHA-256)",
                    p.file
                )));
            }
            if files.contains(&p.file.as_str()) {
                return Err(SecretError(format!("{} is pinned twice", p.file)));
            }
            if self.writable.iter().any(|w| {
                p.file == *w || p.file.starts_with(&format!("{}/", w.trim_end_matches('/')))
            }) {
                return Err(SecretError(format!(
                    "{} is inside a writable folder, where a pin cannot hold",
                    p.file
                )));
            }
            files.push(&p.file);
        }
        self.validate_trees(name, c)?;
        if strict && c.bears_secrets() {
            self.validate_secret_command(name, c)?;
        }
        if c.service {
            if !(1024..=65535).contains(&c.port.unwrap_or(0)) {
                return Err(err(
                    "a service declares the loopback port it listens on (1024 to 65535)",
                ));
            }
            if c.argv.is_empty() {
                return Err(err("a service declares the program it starts"));
            }
            // a service that receives a secret is a secret command in every rule (a pinned program, an environment list, exact
            // egress): `secret_rules` holds it to them, at launch and when the declaration is set
            if !c.pass.is_empty() {
                return Err(err(
                    "a service takes no values from the person who starts it",
                ));
            }
            if let Some(h) = &c.health {
                if !h.starts_with('/') || h.len() > 200 || !path_ok(h) {
                    return Err(err("a health check is a plain path that starts with /"));
                }
            }
        } else if c.port.is_some() || c.health.is_some() {
            return Err(err("port and health belong to a command marked service"));
        }
        Ok(())
    }

    /// Folder pins: plain paths inside the project, a real digest, never in a writable folder, none inside another.
    fn validate_trees(&self, name: &str, c: &CommandPolicy) -> Result<(), SecretError> {
        if c.pin_tree.len() > MAX_TREE_PINS {
            return Err(SecretError(format!(
                "the command {name} pins at most {MAX_TREE_PINS} folders"
            )));
        }
        let mut seen: Vec<&str> = Vec::new();
        for t in &c.pin_tree {
            if !pin_path_ok(&t.path) {
                return Err(SecretError(format!(
                    "a pinned folder is a plain path inside the project folder: {}",
                    t.path
                )));
            }
            if !sha_ok(&t.sha256) {
                return Err(SecretError(format!(
                    "the digest of the folder {} must be 64 lowercase hexadecimal digits",
                    t.path
                )));
            }
            if self.in_writable(&t.path) {
                return Err(SecretError(format!(
                    "{} is inside a writable folder, where a pin cannot hold",
                    t.path
                )));
            }
            let inside = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
            if seen
                .iter()
                .any(|o| inside(&t.path, o) || inside(o, &t.path))
                || c.pin.iter().any(|p| inside(&p.file, &t.path))
            {
                return Err(SecretError(format!(
                    "{} overlaps another pin of the command {name}",
                    t.path
                )));
            }
            seen.push(&t.path);
        }
        Ok(())
    }

    /// Whether a path relative to the project is, or is inside, a writable folder. A path with `..` is never trusted to stay out.
    fn in_writable(&self, rel: &str) -> bool {
        let rel = rel.trim_start_matches("./");
        self.writable.iter().any(|w| {
            let w = w.trim_start_matches("./").trim_end_matches('/');
            rel == w || rel.starts_with(&format!("{w}/"))
        })
    }

    /// The rules a command that is GIVEN A SECRET must meet at launch and when a declaration is written, on top of
    /// [`Policy::validate`] (ADR 0029 Amendment 10, revision 2). `Err` is a sentence that says what to change.
    ///
    /// - the command pins at least one file, and names its program: a secret command is exactly the words the owner approved, so an
    ///   agent can append nothing and the program is a pinned file, never `npm test`;
    /// - the command names the environments it may take its secrets from (the caller chooses one on every run);
    /// - the project's egress holds exact hosts only: under `*.example.com` a value the caller passed could aim a key at a host the
    ///   caller controls.
    pub fn secret_rules(&self, only: Option<&str>) -> Result<(), SecretError> {
        for (name, c) in &self.commands {
            if !c.bears_secrets() || only.is_some_and(|o| o != name) {
                continue;
            }
            // NV6-I5 / NV7-I2: the name the command sees, renamed or not, is never a reserved one (`NODE_OPTIONS`)
            for e in &c.env {
                let t = e.target();
                if let Some(why) = reserved_name(t, &self.tcp) {
                    return Err(SecretError(format!(
                        "the command {name} receives a secret as {t}, which cannot be set for a command: {why}. Give it another name (\"as\": \"MY_NAME\") and read that name in the script; the plain commands of this project are not affected"
                    )));
                }
            }
            if c.argv.is_empty() || c.pin.is_empty() {
                return Err(SecretError(format!(
                    "the command {name} receives a secret but pins no file: its program must be a pinned file (`ozbox env policy pin --entry FILE` on your computer prints the pins), and its words are exactly what you approve. A secret command whose code is not pinned would run whatever the agent writes"
                )));
            }
            node_only(name, c)?;
            if c.envs.is_empty() {
                return Err(SecretError(format!(
                    "the command {name} receives a secret but names no environment: add \"envs\": [\"staging\"], because the caller chooses the environment on every run"
                )));
            }
            if c.envs.iter().any(|e| !seg_ok(e, 32)) {
                return Err(err(
                    "an environment is 1 to 32 lowercase letters, digits or dashes",
                ));
            }
            if let Some(w) = self.egress.iter().find(|e| e.contains('*')) {
                return Err(SecretError(format!(
                    "the command {name} receives a secret, so the project's egress must name exact hosts: {w} is a wildcard"
                )));
            }
            self.writable_rules(name, c)?;
        }
        Ok(())
    }

    /// A writable folder of a project with a secret command must not put agent-written code where the pinned script looks for it
    /// (G5 fourth round, NV3-H1). The folder is bound into the private view from the live project, so a `tests/node_modules/pkg` the
    /// agent wrote would be found by `import 'pkg'` BEFORE the pinned `node_modules/pkg`. Refused: `.` (the whole project), any
    /// `node_modules`, Python package folders (`site-packages`, `dist-packages`, `__pycache__`), a folder that is, or is inside,
    /// the folder of a pinned file or a pinned folder, and one on the folder chain from a pinned file up to the project (Node and
    /// Python both look upward from the script). A folder ABOVE a pin is refused already by the pin rule.
    fn writable_rules(&self, name: &str, c: &CommandPolicy) -> Result<(), SecretError> {
        for w in &self.writable {
            let segs: Vec<&str> = w.split('/').filter(|s| !s.is_empty()).collect();
            let bad = |why: &str| {
                SecretError(format!("the writable folder {w} cannot be used with the command {name}, which receives a secret: {why}"))
            };
            if segs.is_empty() || segs.iter().all(|s| *s == ".") {
                return Err(bad(
                    "it is the whole project folder, which holds the pinned files",
                ));
            }
            if segs.contains(&".") {
                return Err(bad("write it as a plain path with no `.` in it"));
            }
            if let Some(s) = segs.iter().find(|s| {
                let l = s.to_ascii_lowercase();
                l == "node_modules"
                    || l == "site-packages"
                    || l == "dist-packages"
                    || l == "__pycache__"
                    || l == ".pth"
            }) {
                return Err(bad(&format!("{s} is where the script looks for the code it loads, and an agent can write there")));
            }
            let rel = segs.join("/");
            let inside = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
            for t in &c.pin_tree {
                if inside(&rel, &t.path) || inside(&t.path, &rel) {
                    return Err(bad(&format!("it overlaps the pinned folder {}", t.path)));
                }
            }
            for p in &c.pin {
                // the folder chain of a pinned file: its own folder, and each one above it
                let mut chain: Vec<&str> = Vec::new();
                let mut cur = p.file.as_str();
                while let Some((parent, _)) = cur.rsplit_once('/') {
                    chain.push(parent);
                    cur = parent;
                }
                if chain
                    .iter()
                    .any(|d| inside(&rel, d) && !inside(d, &rel) || *d == rel)
                    || inside(&p.file, &rel)
                {
                    return Err(bad(&format!(
                        "it is on the path of the pinned file {}",
                        p.file
                    )));
                }
            }
        }
        Ok(())
    }

    /// What a command that is GIVEN A SECRET may not be. The owner approves the declaration, but these are mistakes that hand the
    /// secret to code an agent wrote, so they are refused rather than trusted.
    fn validate_secret_command(&self, name: &str, c: &CommandPolicy) -> Result<(), SecretError> {
        if c.browser {
            return Err(SecretError(format!(
                "the command {name} receives a secret, so it cannot drive a browser (a browser is a large program an agent could have replaced, and it runs the pages it is given): mint the secret in one command and let another, with no secret, drive the browser"
            )));
        }
        let pinned = !c.pin.is_empty() || !c.pin_tree.is_empty();
        if pinned {
            if let Some(first) = c.argv.first() {
                let base = first.rsplit('/').next().unwrap_or(first);
                if matches!(
                    base,
                    "npm" | "npx" | "pnpm" | "yarn" | "bun" | "bunx" | "corepack"
                ) {
                    return Err(SecretError(format!(
                        "the command {name} is pinned and receives a secret, so it runs `node FILE`, not {base}: a package script and .npmrc are not covered by a pin"
                    )));
                }
            }
            node_only(name, c)?;
        }
        // a word of the command that names code in a writable folder, however it is spelled: the runner may write there, and so
        // may the agent
        for w in c.argv.iter().skip(1).chain(c.argv.iter().take(1)) {
            let cand = if w.starts_with('-') {
                w.split_once('=').map_or("", |(_, v)| v)
            } else {
                w.as_str()
            };
            let cand = cand
                .strip_prefix(&format!("{}/", self.dir.trim_end_matches('/')))
                .unwrap_or(cand);
            if cand.split('/').any(|seg| seg == "..") {
                return Err(SecretError(format!(
                    "the command {name} receives a secret, so none of its words may climb out of a folder with `..`: {w}"
                )));
            }
            if !cand.is_empty() && self.in_writable(cand) {
                return Err(SecretError(format!(
                    "the command {name} receives a secret, but its word {w} names a file in a writable folder, where an agent can put its own code"
                )));
            }
        }
        Ok(())
    }

    fn validate_environment(&self, strict: bool) -> Result<(), SecretError> {
        if self.tools.len() > 16 {
            return Err(err("declare at most 16 tools"));
        }
        let mut names: Vec<&str> = Vec::new();
        for t in &self.tools {
            if !seg_ok(&t.name, 32) {
                return Err(err(
                    "a tool is a catalog name: lowercase letters, digits and dashes",
                ));
            }
            if t.sha256.as_deref().is_some_and(|h| !sha_ok(h)) {
                return Err(SecretError(format!(
                    "the digest of the tool {} must be 64 lowercase hexadecimal digits",
                    t.name
                )));
            }
            if names.contains(&t.name.as_str()) {
                return Err(SecretError(format!("the tool {} is listed twice", t.name)));
            }
            names.push(&t.name);
        }
        // a tool on the PATH of a command that receives a secret is code that command runs with it
        if strict && self.commands.values().any(CommandPolicy::bears_secrets) {
            if let Some(t) = self.tools.iter().find(|t| t.sha256.is_none()) {
                return Err(SecretError(format!(
                    "the tool {} has no digest: a project with a command that receives a secret must pin every tool it declares (`ozbox env policy pin --tool {}` prints the digest; a system package such as jq needs no entry)",
                    t.name, t.name
                )));
            }
        }
        if self.browsers.len() > BROWSERS.len()
            || self
                .browsers
                .iter()
                .any(|b| !BROWSERS.contains(&b.as_str()))
        {
            return Err(err("a browser is one of chromium, firefox or webkit"));
        }
        if self.browser_digests.len() > 32 {
            return Err(err("declare at most 32 browser digests"));
        }
        for (dir, sha) in &self.browser_digests {
            if !browser_dir_ok(dir) || !sha_ok(sha) {
                return Err(SecretError(format!(
                    "a browser digest names a directory such as chromium-1169 and a SHA-256: {dir}"
                )));
            }
        }
        for b in self.browsers.iter().filter(|_| strict) {
            // every directory the browser needs, not just its own: a missing one is a launch that fails at run time (G5 fourth round,
            // NV3-L4)
            for kind in implied_kinds(b) {
                if !self
                    .browser_digests
                    .keys()
                    .any(|d| d.starts_with(&format!("{kind}-")))
                {
                    return Err(SecretError(format!(
                        "the browser {b} has no approved revision of {kind}: add its digest to browser_digests (`ozbox env policy pin --browser {b}` prints it)"
                    )));
                }
            }
        }
        if self.browsers.is_empty() && !self.browser_digests.is_empty() {
            return Err(err("browser_digests without browsers"));
        }
        if self.browsers.is_empty() && self.commands.values().any(|c| c.browser) {
            return Err(err("a command marked browser needs the project's browsers"));
        }
        let any_command_service_or_pin = self
            .commands
            .values()
            .any(|c| c.service || !c.pin.is_empty() || !c.pin_tree.is_empty());
        if any_command_service_or_pin && self.dir.is_empty() {
            return Err(err("a pin or a service needs the project folder (dir)"));
        }
        Ok(())
    }

    /// Whether `value` is, or contains, an identifier the owner listed as production: in the text itself, or in the payload of a
    /// JWT (a Supabase key carries the project ref in its `ref` claim, so the text of the key does not show it).
    pub fn production_hit(&self, value: &str) -> bool {
        if self.production_ids.is_empty() {
            return false;
        }
        // letter case does not hide an identifier (G5 third round, N-M4)
        let hit = |t: &str| {
            let t = t.to_ascii_lowercase();
            self.production_ids
                .iter()
                .any(|i| t.contains(&i.to_ascii_lowercase()))
        };
        if hit(value) {
            return true;
        }
        let mut parts = value.split('.');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(payload), Some(_)) if h.starts_with("eyJ") => {
                crate::serve::auth::b64::decode_url(payload)
                    .and_then(|b| String::from_utf8(b).ok())
                    .is_some_and(|t| hit(&t))
            }
            _ => false,
        }
    }

    /// Whether this declaration uses anything a box from before this format would silently drop. A laptop asks the box
    /// whether it can read these (`declaration_v2`) before it sends one.
    pub fn needs_v2(&self) -> bool {
        !self.tools.is_empty()
            || !self.production_ids.is_empty()
            || self.commands.values().any(|c| !c.envs.is_empty())
            || !self.browsers.is_empty()
            || !self.browser_digests.is_empty()
            || self.commands.values().any(|c| {
                !c.vars.is_empty()
                    || !c.pass.is_empty()
                    || !c.pin.is_empty()
                    || !c.pin_tree.is_empty()
                    || c.browser
                    || c.service
                    || c.env.iter().any(|e| e.rename.is_some())
            })
            || self.needs_public_values()
    }

    /// Whether this declaration uses what only a box that answers `public_values` can read: public names, or a service that
    /// receives a secret. An older box refuses the field (`deny_unknown_fields`), but it is asked first so the person is told why.
    pub fn needs_public_values(&self) -> bool {
        self.commands
            .values()
            .any(|c| !c.public.is_empty() || c.credential_env || (c.service && c.bears_secrets()))
    }

    /// Whether this declaration has a command that receives a secret next to another command. Such a project is only safe on a
    /// box that gives each secret-receiving command a runner user of its own (`capabilities` answers `runner_uids`): on one
    /// that does not, they share a user, and the other command can read the secret from `/proc`.
    pub fn needs_runner_uids(&self) -> bool {
        self.commands.len() > 1 && self.commands.values().any(CommandPolicy::bears_secrets)
    }

    pub fn parse(text: &str) -> Result<Policy, SecretError> {
        let p: Policy =
            serde_json::from_str(text).map_err(|_| err("that is not a valid policy"))?;
        p.validate()?;
        Ok(p)
    }

    /// The text the store keeps: the compact JSON. Refused, naming the size and the limit, when it is over
    /// [`MAX_DECLARATION_BYTES`]. Every place that is about to write a declaration (the laptop before it sends one, the box before
    /// it spends an approval, and the write itself) asks this, so one rule decides.
    pub fn to_record(&self) -> Result<String, SecretError> {
        let json = serde_json::to_string(self).map_err(|_| err("that is not a valid policy"))?;
        if json.len() > MAX_DECLARATION_BYTES {
            return Err(SecretError(format!(
                "this declaration is {} KB once written out, and a box keeps at most {} KB: pin fewer folders, or split the project's commands into a smaller declaration",
                json.len().div_ceil(1024),
                MAX_DECLARATION_BYTES / 1024
            )));
        }
        Ok(json)
    }

    /// The form an earlier version stored: hex of the JSON (the store then kept only plain single-line values, which capped a
    /// declaration at about 2 KB).
    pub fn to_hex(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        json.bytes().map(|b| format!("{b:02x}")).collect()
    }

    /// A stored declaration, in either form: the record (it starts with `{`) or the hex an earlier version wrote (hex digits
    /// only, so never `{`). The next save writes the record.
    pub fn from_stored(stored: &str) -> Result<Policy, SecretError> {
        if stored.starts_with('{') {
            let p: Policy =
                serde_json::from_str(stored).map_err(|_| err("the stored policy is damaged"))?;
            p.validate_shape()?;
            return Ok(p);
        }
        Policy::from_hex(stored)
    }

    pub fn from_hex(h: &str) -> Result<Policy, SecretError> {
        if !h.len().is_multiple_of(2) {
            return Err(err("the stored policy is damaged"));
        }
        let bytes: Option<Vec<u8>> = (0..h.len() / 2)
            .map(|i| u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok())
            .collect();
        let text = String::from_utf8(bytes.ok_or_else(|| err("the stored policy is damaged"))?)
            .map_err(|_| err("the stored policy is damaged"))?;
        // an earlier version stored what is now refused for a command that receives a secret: it still LOADS (so it can be shown and
        // replaced), and `secret_rules` and `validate` refuse its secret commands at launch
        let p: Policy =
            serde_json::from_str(&text).map_err(|_| err("the stored policy is damaged"))?;
        p.validate_shape()?;
        Ok(p)
    }

    /// Every check a declaration meets before anything is written, in one place: the rules of its shape, of a command that
    /// receives a secret, and its size. What the box's own checks decide that depend on the box (whether a second factor is
    /// enrolled) are not here. The laptop runs this before it sends a request, and the box runs it before it spends an approval.
    pub fn check_before_write(&self) -> Result<String, SecretError> {
        self.validate()?;
        self.secret_rules(None)?;
        self.to_record()
    }

    /// The declaration a request must follow: the named command, and a program that starts as declared.
    pub fn command(&self, name: &str, argv: &[String]) -> Result<&CommandPolicy, SecretError> {
        let c = self.commands.get(name).ok_or_else(|| {
            SecretError(format!(
                "this project does not declare a command named {name}"
            ))
        })?;
        // a pinned command is exactly what was approved: extra words would be handed to the approved script
        let exact = !c.pin.is_empty() && !c.argv.is_empty();
        if !c.argv.is_empty()
            && (!argv.starts_with(&c.argv) || (exact && argv != c.argv.as_slice()))
        {
            return Err(SecretError(format!(
                "the command {name} must start with: {}",
                c.argv.join(" ")
            )));
        }
        Ok(c)
    }
}

pub fn load(store: &dyn SecretStore, project: &str) -> Result<Option<Policy>, SecretError> {
    match store.get(&secret_name(project)?)? {
        Some(h) => Policy::from_stored(&h).map(Some),
        None => Ok(None),
    }
}

pub fn save(store: &dyn SecretStore, project: &str, p: &Policy) -> Result<(), SecretError> {
    let record = p.to_record()?;
    p.validate()?;
    store.set_record(&secret_name(project)?, &record)
}

/// A declaration shaped like a real Next.js application's: `commands` services, each pinning `pins` files and `trees` folders (the
/// packages a build's trace lists), plus a pinned tool. Test support, shared with the box's and the laptop's tests.
#[cfg(test)]
pub(crate) fn realistic_declaration(commands: usize, trees: usize, pins: usize) -> String {
    let h = "ab".repeat(32);
    let cmds: serde_json::Map<String, serde_json::Value> = (0..commands)
        .map(|c| {
            let pin: Vec<_> = (0..pins)
                .map(|i| serde_json::json!({"file": format!("server/chunks/chunk-{c}-{i}.js"), "sha256": h}))
                .collect();
            let tree: Vec<_> = (0..trees)
                .map(|i| serde_json::json!({"path": format!("node_modules/@scope-{c}/package-name-{i}"), "sha256": h}))
                .collect();
            (
                format!("web{c}"),
                serde_json::json!({"allow": [], "service": true, "port": 3100 + c, "argv": ["node", "server.js"],
                    "health": "/healthz", "pin": pin, "pin_tree": tree}),
            )
        })
        .collect();
    serde_json::json!({"dir": "/work/projects/app", "tools": [{"name": "pnpm", "sha256": h}], "commands": cmds}).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    /// user info and credential-bearing addresses are never public, by a person's mark or by a public name.
    #[test]
    fn an_address_with_user_info_or_a_webhook_is_never_public_and_a_plain_one_is() {
        let hook = [
            "https://hooks.slack.com/",
            "services/T0/B0/abcdefghijklmnopqrstuvwx",
        ]
        .concat();
        for v in [
            "https://admin:pass1234word@api.example.test/v1",
            "turns:user@turn.example.test:443",
            hook.as_str(),
            "https://discord.com/api/webhooks/1/abc",
            "https://script.google.com/macros/s/ABC/exec",
        ] {
            for name in ["NEXT_PUBLIC_X", "WHATEVER"] {
                assert!(public_mark_refusal(name, v, false).is_some(), "{name} {v}");
            }
        }
        for v in [
            "https://api.example.test/v1",
            "support@example.test",
            "mailto:help@example.test",
            "turns:turn.example.test:443",
        ] {
            assert!(
                public_mark_refusal("NEXT_PUBLIC_X", v, false).is_none(),
                "{v}"
            );
        }
    }
    use super::*;
    use crate::secrets::MemorySecrets;

    fn sample() -> Policy {
        Policy::parse(
            r#"{"dir":"/work/projects/app","writable":[".next","node_modules"],"commands":{
                "test":{"allow":["API_KEY","DB_URL"],"env":["API_KEY"],"argv":["npm","test"]},
                "dev":{"allow":["API_KEY"],"env":["API_KEY"]}}}"#,
        )
        .unwrap()
    }

    #[test]
    fn a_policy_round_trips_through_the_store_and_a_command_follows_its_declaration() {
        let s = MemorySecrets::default();
        save(&s, "app", &sample()).unwrap();
        // the store holds the declaration as a record (its compact JSON)
        let raw = s.get("workload-policy.app").unwrap().unwrap();
        assert_eq!(raw, serde_json::to_string(&sample()).unwrap());
        let p = load(&s, "app").unwrap().unwrap();
        assert_eq!(p, sample());
        assert!(load(&s, "other").unwrap().is_none());
        let argv = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let c = p
            .command("test", &argv(&["npm", "test", "--", "-u"]))
            .unwrap();
        assert_eq!(c.allow, ["API_KEY", "DB_URL"]);
        // a program that does not start as declared, and a command nobody declared, are refused
        assert!(p.command("test", &argv(&["sh", "-c", "env"])).is_err());
        assert!(p.command("deploy", &argv(&["npm", "test"])).is_err());
        // no declared program: any
        assert!(p.command("dev", &argv(&["anything"])).is_ok());
    }

    /// G5 second review, N-M5: a declaration stored before the secret-command rules still LOADS (so it can be shown and replaced); its
    /// secret commands are refused by `secret_rules` / `validate`, with a sentence that says what to change.
    #[test]
    fn a_declaration_stored_before_the_secret_rules_still_loads_and_its_secret_command_is_refused_with_what_to_change(
    ) {
        // the old example: an unpinned tool next to a secret command, browsers with no digests, and no pin at all
        let old = r#"{"dir":"/work/projects/app","tools":["node"],"browsers":["chromium"],"commands":{
            "mint":{"allow":["K"],"env":["K"],"argv":["node","mint.mjs"]},"plain":{"allow":[]}}}"#;
        assert!(
            Policy::parse(old).is_err(),
            "a new declaration is held to the rules"
        );
        let hex: String = old.bytes().map(|b| format!("{b:02x}")).collect();
        let p = Policy::from_hex(&hex).unwrap();
        assert!(p.validate().is_err());
        let e = p.secret_rules(Some("mint")).unwrap_err().0;
        assert!(e.contains("pins no file"), "{e}");
        assert!(
            p.secret_rules(Some("plain")).is_ok(),
            "a command with no secret is not held to them"
        );
        // and a store holding it loads it too
        let s = MemorySecrets::default();
        s.set("workload-policy.app", &hex).unwrap();
        assert!(load(&s, "app").unwrap().is_some());
    }

    /// G5 fourth round, NV3-H1: a writable folder may not sit on a pinned script's lookup path, at write and at launch.
    #[test]
    fn a_writable_folder_cannot_sit_on_a_pinned_scripts_lookup_path() {
        let h = "b".repeat(64);
        let decl = |w: &str| {
            format!(
                r#"{{"dir":"/work/projects/app","egress":["api.example.com"],"writable":[{w}],"commands":{{"m":{{"allow":["K"],"env":["K"],"argv":["node","tests/m.mjs"],"envs":["staging"],"pin":[{{"file":"tests/m.mjs","sha256":"{h}"}},{{"file":"node_modules/pkg/index.js","sha256":"{h}"}}],"pin_tree":[{{"path":"vendor","sha256":"{h}"}}]}}}}}}"#
            )
        };
        for w in [
            r#""tests/node_modules""#,
            r#""node_modules/pkg/lib""#,
            r#""node_modules/bufferutil""#,
            r#"".""#,
            r#""./x""#,
            r#""a/./b""#,
            r#""tests""#,
            r#""tests/out""#,
            r#""vendor/x""#,
            r#""vendor""#,
            r#""x/site-packages""#,
            r#""x/__pycache__""#,
            r#""X/Node_Modules""#,
        ] {
            // at write time (strict) and at launch (a stored declaration is parsed leniently, then held to the secret rules)
            let at_write = Policy::parse(&decl(w)).and_then(|p| p.secret_rules(None));
            assert!(
                at_write.is_err(),
                "{w} must be refused when the declaration is written"
            );
            let hex: String = decl(w).bytes().map(|b| format!("{b:02x}")).collect();
            // (a stored declaration the plain rules already refuse never loads at all)
            if let Ok(p) = Policy::from_hex(&hex) {
                let e = p.secret_rules(Some("m")).unwrap_err().0;
                assert!(e.contains("writable folder"), "{w}: {e}");
            }
        }
        for w in [r#"".next""#, r#""out/cache""#, r#""build""#] {
            let p = Policy::parse(&decl(w)).unwrap_or_else(|e| panic!("{w}: {}", e.0));
            assert!(p.secret_rules(None).is_ok(), "{w} is not on a lookup path");
        }
    }

    /// G5 fifth round, NV4-H1: only `node FILE` can be pinned. The reviewer's Python probes (a writable folder next to a pinned module,
    /// `python -m`) are refused at write and at launch, and the sentence says why.
    #[test]
    fn only_a_node_script_can_be_pinned_and_given_a_secret() {
        let h = "b".repeat(64);
        let decl = |argv: &str, w: &str| {
            format!(
                r#"{{"dir":"/work/projects/app","egress":["api.example.com"],"writable":[{w}],"commands":{{"m":{{"allow":["K"],"env":["K"],"argv":{argv},"envs":["staging"],"pin":[{{"file":"m.py","sha256":"{h}"}},{{"file":"helper.py","sha256":"{h}"}}]}}}}}}"#
            )
        };
        for (argv, w) in [
            (r#"["python3","m.py"]"#, r#""helper""#),
            (r#"["python3","m.py"]"#, r#""requests""#),
            (r#"["python3","-m","json"]"#, r#""json""#),
            (r#"["python3","m.py"]"#, ""),
            (r#"["/usr/bin/node","m.py"]"#, ""),
            (r#"["./node","m.py"]"#, ""),
            (r#"["sh","m.py"]"#, ""),
        ] {
            let text = decl(argv, w);
            let at_write = Policy::parse(&text).and_then(|p| p.secret_rules(None));
            let e = at_write.unwrap_err().0;
            assert!(
                e.contains("only Node scripts can be pinned"),
                "{argv} {w}: {e}"
            );
            // a declaration stored before the rule loads, and is refused when the command is launched
            let hex: String = text.bytes().map(|b| format!("{b:02x}")).collect();
            let p = Policy::from_hex(&hex).unwrap();
            let e = p
                .validate_at_launch()
                .and_then(|()| p.secret_rules(Some("m")))
                .unwrap_err()
                .0;
            assert!(
                e.contains("only Node scripts can be pinned"),
                "{argv} {w}: {e}"
            );
        }
        // NV5-H1: the script must be argv[1], a script file, with no option before it
        for argv in [
            r#"["node","tests/mint"]"#,
            r#"["node","-e","import('./tests/mint.mjs')"]"#,
            r#"["node","--import=./tests/mint.mjs","-e","0"]"#,
            r#"["node","-p","require('./tests/mint.mjs')"]"#,
            r#"["node","--require","./m.mjs","m.mjs"]"#,
            r#"["node","--loader","./m.mjs","m.mjs"]"#,
            r#"["node"]"#,
        ] {
            let text = decl(argv, "").replace("m.py", "tests/mint.mjs");
            let e = Policy::parse(&text)
                .and_then(|p| p.secret_rules(None))
                .unwrap_err()
                .0;
            assert!(e.contains("must be `node FILE`"), "{argv}: {e}");
            let hex: String = text.bytes().map(|b| format!("{b:02x}")).collect();
            let p = Policy::from_hex(&hex).unwrap();
            let e = p
                .validate_at_launch()
                .and_then(|()| p.secret_rules(Some("m")))
                .unwrap_err()
                .0;
            assert!(e.contains("must be `node FILE`"), "{argv}: {e}");
        }
        for argv in [
            r#"["node","tests/mint.mjs"]"#,
            r#"["node","tests/mint.mjs","--flag","-e"]"#,
        ] {
            let text = decl(argv, "").replace("m.py", "tests/mint.mjs");
            assert!(
                Policy::parse(&text)
                    .and_then(|p| p.secret_rules(None))
                    .is_ok(),
                "{argv}"
            );
        }
        // a command that receives no secret runs any program
        let plain = r#"{"dir":"/work/projects/app","commands":{"m":{"allow":[],"argv":["python3","m.py"]}}}"#;
        assert!(Policy::parse(plain).unwrap().secret_rules(None).is_ok());
    }

    #[test]
    fn a_secret_command_pins_its_program_names_its_environments_and_sees_no_wildcard_egress() {
        let base = |extra: &str, egress: &str| {
            format!(
                r#"{{"dir":"/work/projects/app",{egress}"commands":{{"m":{{"allow":["K"],"env":["K"],"argv":["node","m.mjs"],{extra}"pin":[{{"file":"m.mjs","sha256":"{}"}}]}}}}}}"#,
                "b".repeat(64)
            )
        };
        let ok = Policy::parse(&base(
            r#""envs":["staging"],"#,
            r#""egress":["api.example.com"],"#,
        ))
        .unwrap();
        assert!(ok.secret_rules(None).is_ok());
        let e = Policy::parse(&base("", ""))
            .unwrap()
            .secret_rules(None)
            .unwrap_err()
            .0;
        assert!(e.contains("names no environment"), "{e}");
        let e = Policy::parse(&base(
            r#""envs":["staging"],"#,
            r#""egress":["*.example.com"],"#,
        ))
        .unwrap()
        .secret_rules(None)
        .unwrap_err()
        .0;
        assert!(e.contains("wildcard"), "{e}");
        let nopin = r#"{"dir":"/work/projects/app","commands":{"m":{"allow":["K"],"env":["K"],"argv":["node","m.mjs"],"envs":["staging"]}}}"#;
        assert!(Policy::parse(nopin)
            .unwrap()
            .secret_rules(None)
            .unwrap_err()
            .0
            .contains("pins no file"));
        let noargv = r#"{"dir":"/work/projects/app","commands":{"m":{"allow":["K"],"env":["K"],"envs":["staging"]}}}"#;
        assert!(
            Policy::parse(noargv).unwrap().secret_rules(None).is_err(),
            "an agent must not choose the program"
        );
    }

    #[test]
    fn egress_entries_are_hosts_and_default_to_nowhere() {
        let p = Policy::parse(r#"{"commands":{"a":{"allow":[]}}}"#).unwrap();
        assert!(p.egress.is_empty());
        let p = Policy::parse(
            r#"{"egress":["api.example.com","*.example.org:8443"],"commands":{"a":{"allow":[]}}}"#,
        )
        .unwrap();
        assert_eq!(p.egress.len(), 2);
        for bad in ["10.0.0.1", "localhost", "a.example.com:0", "bad host.com"] {
            let t = format!(r#"{{"egress":["{bad}"],"commands":{{"a":{{"allow":[]}}}}}}"#);
            assert!(Policy::parse(&t).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_declaration_that_cannot_be_followed_safely_is_refused() {
        for bad in [
            r#"{"commands":{}}"#,
            r#"{"dir":"/etc","commands":{"a":{"allow":[]}}}"#,
            r#"{"dir":"/work/../etc","commands":{"a":{"allow":[]}}}"#,
            r#"{"writable":["/etc"],"commands":{"a":{"allow":[]}}}"#,
            r#"{"writable":["../x"],"commands":{"a":{"allow":[]}}}"#,
            r#"{"commands":{"Bad Name":{"allow":[]}}}"#,
            r#"{"commands":{"a":{"allow":["lower"]}}}"#,
            r#"{"commands":{"a":{"allow":["A"],"env":["B"]}}}"#,
            "not json",
        ] {
            assert!(Policy::parse(bad).is_err(), "{bad}");
        }
        assert!(secret_name("Bad Project").is_err());
        assert!(Policy::from_hex("zz").is_err() && Policy::from_hex("abc").is_err());
    }

    fn cmd(extra: &str) -> String {
        format!(
            r#"{{"dir":"/work/projects/app","writable":[".next"],"commands":{{"a":{{"allow":["K"],"env":["K"]{extra}}}}}}}"#
        )
    }

    #[test]
    fn an_old_declaration_keeps_its_bytes_and_a_new_one_round_trips() {
        // nothing new set: nothing new written, so the digest an approval covered is unchanged
        let old = sample();
        let json = serde_json::to_string(&old).unwrap();
        for k in [
            "vars",
            "pass",
            "pin",
            "service",
            "port",
            "health",
            "tools",
            "browsers",
            "\"as\"",
            "public",
            "credential_env",
        ] {
            assert!(!json.contains(k), "{k} in {json}");
        }
        assert!(!old.needs_v2());
        let p = Policy::parse(&cmd(r#","vars":{"PORT":"3100"},"pass":["E2E_SPEC"],"pin":[{"file":"tests/x.mjs","sha256":"%"}]"#.replace('%', &"a".repeat(64)).as_str())).unwrap();
        assert!(p.needs_v2());
        assert_eq!(Policy::from_hex(&p.to_hex()).unwrap(), p);
        let r = Policy::parse(
            r#"{"commands":{"a":{"allow":["K"],"env":[{"name":"K","as":"E2E_K"}]}}}"#,
        )
        .unwrap();
        assert_eq!(r.commands["a"].env[0].target(), "E2E_K");
        assert!(
            r.needs_v2()
                && serde_json::to_string(&r)
                    .unwrap()
                    .contains(r#"{"name":"K","as":"E2E_K"}"#)
        );
        // a field this program does not know is refused, never dropped
        assert!(Policy::parse(r#"{"commands":{"a":{"allow":[],"pinned":[]}}}"#).is_err());
        assert!(Policy::parse(
            r#"{"commands":{"a":{"allow":["K"],"env":[{"name":"K","as":"E","x":1}]}}}"#
        )
        .is_err());
    }

    #[test]
    fn plain_variables_are_names_and_values_that_cannot_be_a_secret_or_change_how_a_program_starts()
    {
        let ok = |extra: &str| Policy::parse(&cmd(extra)).is_ok();
        assert!(ok(
            r#","vars":{"PORT":"3100","NEXT_PUBLIC_APP_URL":"http://localhost:3100","E2E_ALLOW_WRITES":"1"}"#
        ));
        assert!(ok(r#","pass":["E2E_SPEC"]"#));
        for bad in [
            // names that choose the program, where it loads code from, or where it sends traffic
            r#","vars":{"PATH":"/tmp"}"#,
            r#","vars":{"NODE_OPTIONS":"--require=x"}"#,
            r#","vars":{"LD_PRELOAD":"x"}"#,
            r#","vars":{"HTTPS_PROXY":"x"}"#,
            r#","vars":{"PLAYWRIGHT_BROWSERS_PATH":"x"}"#,
            r#","pass":["HOME"]"#,
            r#","vars":{"npm_config_x":"y"}"#,
            r#","vars":{"lower":"x"}"#,
            r#","pass":["NODE_PATH"]"#,
            // a value that looks like a key, holds a space or a newline, or is empty or huge
            r#","vars":{"X":"a b"}"#,
            r#","vars":{"X":"a\nb"}"#,
            r#","vars":{"X":""}"#,
            concat!(r#","vars":{"X":"sk_"#, r#"live_abcdef0123456789"}"#),
            r#","vars":{"X":"eyJhbGciOiJIUzI1NiJ9"}"#,
            r#","vars":{"X":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"}"#,
            r#","vars":{"X":"https://prod.example.com/x"}"#,
            r#","vars":{"PROD_X":"1"}"#,
            // a name that says it is a secret cannot be passed
            r#","pass":["API_TOKEN"]"#,
            r#","pass":["DB_PASSWORD"]"#,
            // the same name set twice (a rename onto a fixed value, a passed name that is also fixed)
            r#","vars":{"K":"1"}"#,
            r#","vars":{"E2E_K":"1"},"env":[{"name":"K","as":"E2E_K"}]"#,
        ] {
            // the `env` in `bad` entries that set it themselves replace the default one
            let t = if bad.contains(r#""env""#) {
                format!(r#"{{"commands":{{"a":{{"allow":["K"]{bad}}}}}}}"#)
            } else {
                cmd(bad)
            };
            assert!(Policy::parse(&t).is_err(), "{bad}");
        }
        // a pass that is also a fixed variable
        assert!(!ok(r#","vars":{"E2E_SPEC":"1"},"pass":["E2E_SPEC"]"#));
        // a rename onto a reserved name
        assert!(Policy::parse(
            r#"{"commands":{"a":{"allow":["K"],"env":[{"name":"K","as":"PATH"}]}}}"#
        )
        .is_err());
        // NV6-I5: a secret declared WITHOUT a rename is checked against the reserved names too
        for n in ["NODE_OPTIONS", "NODE_PATH", "PATH", "LD_PRELOAD"] {
            let t = format!(
                r#"{{"commands":{{"a":{{"allow":["{n}"],"env":["{n}"]}},"plain":{{"allow":[]}}}}}}"#
            );
            // NV7-I2: it loads (an older stored declaration), its plain command is fine, and the secret command is refused with a fix
            let p: Policy = serde_json::from_str(&t).unwrap();
            p.validate_shape().unwrap();
            assert!(p.secret_rules(Some("plain")).is_ok(), "{n}");
            let e = p.secret_rules(Some("a")).unwrap_err().0;
            assert!(e.contains(n) && e.contains("another name"), "{n}: {e}");
            assert!(p.secret_rules(None).is_err(), "{n}");
        }
        // a tcp destination's own variables are reserved
        let t = r#"{"tcp":[{"host":"db.example.com","port":5432,"env":"DATABASE"}],"commands":{"a":{"allow":[],"vars":{"DATABASE_PORT":"1"}}}}"#;
        assert!(Policy::parse(t).is_err());
    }

    /// ADR 0029 Amendment 12: a service may receive a secret, but only under every rule a secret command meets.
    #[test]
    fn a_service_receives_a_secret_only_under_every_rule_a_secret_command_meets() {
        let h = "b".repeat(64);
        let svc = |extra: &str| {
            format!(
                r#"{{"dir":"/work/projects/app","writable":[".next"],"commands":{{"s":{{"allow":["K"],"env":["K"],"service":true,"port":3100{extra}}}}}}}"#
            )
        };
        let pin = format!(r#","pin":[{{"file":"server.mjs","sha256":"{h}"}}]"#);
        let good = svc(&format!(
            r#","argv":["node","server.mjs"],"envs":["staging"]{pin}"#
        ));
        let p = Policy::parse(&good).unwrap();
        p.secret_rules(None).unwrap();
        assert!(p.needs_public_values(), "an older box is asked first");
        // an unpinned program, no environment list, a package script and a browser are each refused
        let unpinned =
            Policy::parse(&svc(r#","argv":["node","server.mjs"],"envs":["staging"]"#)).unwrap();
        assert!(unpinned
            .secret_rules(Some("s"))
            .unwrap_err()
            .0
            .contains("pins no file"));
        let no_envs =
            Policy::parse(&svc(&format!(r#","argv":["node","server.mjs"]{pin}"#))).unwrap();
        assert!(no_envs
            .secret_rules(Some("s"))
            .unwrap_err()
            .0
            .contains("names no environment"));
        assert!(Policy::parse(&svc(&format!(
            r#","argv":["npm","run","start"],"envs":["staging"]{pin}"#
        )))
        .is_err());
        assert!(Policy::parse(&svc(&format!(
            r#","argv":["node","server.mjs"],"envs":["staging"],"browser":true{pin}"#
        )))
        .is_err());
        // a service takes nothing from the person who starts it
        assert!(Policy::parse(&svc(&format!(
            r#","argv":["node","server.mjs"],"envs":["staging"],"pass":["X"]{pin}"#
        )))
        .is_err());
        // credential_env: for a service that has secrets, nothing else
        let ce = svc(&format!(
            r#","argv":["node","server.mjs"],"envs":["staging"],"credential_env":true{pin}"#
        ));
        Policy::parse(&ce).unwrap().secret_rules(None).unwrap();
        let plain_service = r#"{"dir":"/work/projects/app","commands":{"s":{"allow":[],"service":true,"port":3100,"argv":["npm","start"],"credential_env":true}}}"#;
        assert!(
            Policy::parse(plain_service).is_err(),
            "no secrets: nothing to turn into variables"
        );
        let one_shot = r#"{"dir":"/work/projects/app","commands":{"a":{"allow":["K"],"env":["K"],"credential_env":true}}}"#;
        assert!(
            Policy::parse(one_shot).is_err(),
            "a one-shot command has the environment already"
        );
    }

    /// systemd's own variable names can never be set by a declaration, or the credential shim could be
    /// pointed at a folder the agent wrote.
    #[test]
    fn systemds_own_variable_names_are_reserved() {
        for n in [
            "CREDENTIALS_DIRECTORY",
            "RUNTIME_DIRECTORY",
            "STATE_DIRECTORY",
            "CACHE_DIRECTORY",
            "LOGS_DIRECTORY",
            "CONFIGURATION_DIRECTORY",
            "INVOCATION_ID",
            "NOTIFY_SOCKET",
            "MAINPID",
            "JOURNAL_STREAM",
            "WATCHDOG_USEC",
            "WATCHDOG_PID",
            "TRIGGER_UNIT",
            "LISTEN_FDS",
            "LISTEN_PID",
            "LISTEN_FDNAMES",
            "SYSTEMD_EXEC_PID",
            "MONITOR_UNIT",
            "EXIT_STATUS",
            "SERVICE_RESULT",
            "credentials_directory",
        ] {
            assert!(reserved_name(n, &[]).is_some(), "{n}");
            // and so a declaration that sets it, any way, is refused
            let vars = format!(
                r#"{{"dir":"/work/projects/app","commands":{{"a":{{"allow":[],"service":true,"port":3100,"argv":["node","x.mjs"],"vars":{{"{}":"/work/projects/app/.next/c"}}}}}}}}"#,
                n.to_ascii_uppercase()
            );
            assert!(Policy::parse(&vars).is_err(), "{n} as a var");
        }
        // ordinary names stay free
        for n in ["PORT", "NEXT_PUBLIC_APP_URL", "LOG_LEVEL", "EXITCODE_X"] {
            assert!(reserved_name(n, &[]).is_none(), "{n}");
        }
    }

    /// ADR 0029 Amendment 12: public names are plain, declared and environment-bound; they never widen what a secret command gets.
    #[test]
    fn public_names_are_declared_plainly_and_never_look_like_a_secret() {
        let base = |extra: &str| {
            format!(r#"{{"dir":"/work/projects/app","commands":{{"a":{{"allow":[]{extra}}}}}}}"#)
        };
        assert!(Policy::parse(&base(
            r#","public":["NEXT_PUBLIC_SUPABASE_ANON_KEY","NEXT_PUBLIC_APP_URL"],"envs":["staging"]"#
        ))
        .is_ok());
        for bad in [
            // the caller would choose the environment with nothing to bound it
            r#","public":["NEXT_PUBLIC_APP_URL"]"#,
            // a name that says it is secret, or is the service role
            r#","public":["API_TOKEN"],"envs":["staging"]"#,
            r#","public":["SUPABASE_SERVICE_ROLE_KEY"],"envs":["staging"]"#,
            // reserved, malformed, repeated, set another way too
            r#","public":["PATH"],"envs":["staging"]"#,
            r#","public":["NODE_OPTIONS"],"envs":["staging"]"#,
            r#","public":["lower"],"envs":["staging"]"#,
            r#","public":["X","X"],"envs":["staging"]"#,
            r#","public":["X"],"vars":{"X":"1"},"envs":["staging"]"#,
            r#","public":["X"],"pass":["X"],"envs":["staging"]"#,
        ] {
            assert!(Policy::parse(&base(bad)).is_err(), "{bad}");
        }
        // a name cannot be both a secret and public
        let both = r#"{"dir":"/work/projects/app","commands":{"a":{"allow":["X"],"env":["X"],"public":["X"],"envs":["staging"]}}}"#;
        assert!(Policy::parse(both).is_err());
        // naming a public value does not make a command a secret command
        let p = Policy::parse(&base(
            r#","public":["NEXT_PUBLIC_APP_URL"],"envs":["staging"]"#,
        ))
        .unwrap();
        assert!(!p.commands["a"].bears_secrets());
        assert!(p.needs_public_values());
        // the stored form leaves both new fields out when empty
        let json = serde_json::to_string(&Policy::parse(&base("")).unwrap()).unwrap();
        assert!(
            !json.contains("public") && !json.contains("credential_env"),
            "{json}"
        );
    }

    #[test]
    fn pins_services_tools_and_browsers_are_checked_when_the_declaration_is_made() {
        let h = "b".repeat(64);
        let ok = |extra: &str| Policy::parse(&cmd(extra)).is_ok();
        assert!(ok(&format!(
            r#","pin":[{{"file":"tests/x.mjs","sha256":"{h}"}},{{"file":"package.json","sha256":"{h}"}}]"#
        )));
        for bad in [
            format!(r#","pin":[{{"file":"/etc/passwd","sha256":"{h}"}}]"#),
            format!(r#","pin":[{{"file":"../x","sha256":"{h}"}}]"#),
            format!(r#","pin":[{{"file":"a//b","sha256":"{h}"}}]"#),
            format!(r#","pin":[{{"file":"x","sha256":"{}"}}]"#, "B".repeat(64)),
            r#","pin":[{"file":"x","sha256":"abc"}]"#.to_string(),
            format!(r#","pin":[{{"file":"x","sha256":"{h}"}},{{"file":"x","sha256":"{h}"}}]"#),
            // inside a writable folder, where the runner could change it
            format!(r#","pin":[{{"file":".next/x.js","sha256":"{h}"}}]"#),
            // a port with no service
            r#","port":3100"#.to_string(),
        ] {
            assert!(!ok(&bad), "{bad}");
        }
        let svc = |extra: &str| {
            Policy::parse(&format!(r#"{{"dir":"/work/projects/app","commands":{{"s":{{"allow":[],"service":true{extra}}}}}}}"#)).is_ok()
        };
        assert!(svc(
            r#","port":3100,"argv":["npm","run","start"],"health":"/healthz""#
        ));
        assert!(!svc(r#","argv":["npm","run","start"]"#), "no port");
        assert!(
            !svc(r#","port":80,"argv":["npm","run","start"]"#),
            "a privileged port"
        );
        assert!(!svc(r#","port":3100"#), "no program declared");
        assert!(!svc(r#","port":3100,"argv":["x"],"health":"http://x""#));
        assert!(!svc(r#","port":3100,"argv":["x"],"pass":["A"]"#));
        let t = |tools: &str, br: &str| {
            Policy::parse(&format!(
                r#"{{"tools":{tools},"browsers":{br},"commands":{{"a":{{"allow":[]}}}}}}"#
            ))
            .is_ok()
        };
        assert!(t(
            r#"["node",{"name":"pnpm","sha256":"%"}]"#.replace('%', &h).as_str(),
            "[]"
        ));
        assert!(
            !t(r#"["Node"]"#, "[]")
                && !t(r#"["node","node"]"#, "[]")
                && !t(r#"[{"name":"node","sha256":"zz"}]"#, "[]")
        );
        assert!(!t("[]", r#"["ie6"]"#));
        // a browser with no approved revision is refused (see the browser test below)
        assert!(!t("[]", r#"["chromium"]"#));
    }

    fn proj(tools: &str, extra_top: &str, cmds: &str) -> Result<Policy, SecretError> {
        Policy::parse(&format!(
            r#"{{"dir":"/work/projects/app","writable":[".next",".auth"],{extra_top}"tools":{tools},"commands":{{{cmds}}}}}"#
        ))
    }

    /// a tool on the PATH of a command that receives a secret is code that command runs with it.
    #[test]
    fn a_project_with_a_secret_receiving_command_must_pin_every_tool() {
        let h = "d".repeat(64);
        let mint = r#""mint":{"allow":["K"],"env":["K"]}"#;
        let plain = r#""run":{"allow":[]}"#;
        assert!(
            proj(r#"["node"]"#, "", plain).is_ok(),
            "no secret anywhere: an unpinned tool is allowed"
        );
        let e = proj(r#"["node"]"#, "", mint).unwrap_err().0;
        assert!(
            e.contains("node") && e.contains("must pin every tool"),
            "{e}"
        );
        assert!(
            proj(r#"["node"]"#, "", &format!("{mint},{plain}")).is_err(),
            "a project-wide tool: the plain command does not excuse it"
        );
        assert!(proj(
            &format!(r#"[{{"name":"node","sha256":"{h}"}}]"#),
            "",
            &format!("{mint},{plain}")
        )
        .is_ok());
        assert!(proj("[]", "", mint).is_ok());
    }

    /// a browser is for a command with no secret, and only an approved revision is ever copied.
    #[test]
    fn a_browser_needs_an_approved_revision_and_never_a_secret() {
        let h = "e".repeat(64);
        let top = format!(
            r#""browsers":["chromium"],"browser_digests":{{"chromium-1169":"{h}","chromium_headless_shell-1169":"{h}","ffmpeg-1011":"{h}"}},"#
        );
        let run = r#""run":{"allow":[],"browser":true}"#;
        let mint = r#""mint":{"allow":["K"],"env":["K"]}"#;
        assert!(
            proj("[]", &top, &format!("{run},{mint}")).is_ok(),
            "the browser command has no secret, the secret command no browser"
        );
        // the secret command cannot ask for a browser
        let e = proj(
            "[]",
            &top,
            r#""mint":{"allow":["K"],"env":["K"],"browser":true}"#,
        )
        .unwrap_err()
        .0;
        assert!(e.contains("cannot drive a browser"), "{e}");
        assert!(proj(
            "[]",
            &top,
            r#""mint":{"allow":[],"env":[],"browser":true,"service":false}"#
        )
        .is_ok());
        // browsers with no digest, a digest naming no browser directory, a digest with no browsers, a browser command with none
        assert!(proj("[]", r#""browsers":["chromium"],"#, run)
            .unwrap_err()
            .0
            .contains("no approved revision"));
        // one revision of three is not enough: the kinds the browser implies must all be there (NV3-L4)
        let two = format!(
            r#""browsers":["chromium"],"browser_digests":{{"chromium-1169":"{h}","ffmpeg-1011":"{h}"}},"#
        );
        assert!(proj("[]", &two, run)
            .unwrap_err()
            .0
            .contains("chromium_headless_shell"));
        for bad in [
            format!(
                r#""browsers":["chromium"],"browser_digests":{{"chromium-1169":"{h}","evil":"{h}"}},"#
            ),
            r#""browsers":["chromium"],"browser_digests":{"chromium-1169":"abc"},"#.to_string(),
            format!(r#""browsers":["chromium"],"browser_digests":{{"firefox-1488":"{h}"}},"#),
            format!(r#""browser_digests":{{"chromium-1169":"{h}"}},"#),
        ] {
            assert!(proj("[]", &bad, run).is_err(), "{bad}");
        }
        assert!(
            proj("[]", "", run).is_err(),
            "browser: true without the project's browsers"
        );
    }

    /// a secret-receiving command's words may not name code in a folder the runner (and the agent) can write.
    #[test]
    fn a_secret_receiving_command_may_not_run_code_from_a_writable_folder() {
        let c = |argv: &str| format!(r#""m":{{"allow":["K"],"env":["K"],"argv":{argv}}}"#);
        assert!(proj("[]", "", &c(r#"["node","tests/mint.mjs"]"#)).is_ok());
        for bad in [
            r#"["node",".next/x.mjs"]"#,
            r#"["node","./.next/x.mjs"]"#,
            r#"["node",".auth/x.js"]"#,
            r#"["node","/work/projects/app/.next/x.mjs"]"#,
            r#"["node","--require=.next/h.js","tests/m.mjs"]"#,
            r#"["node","tests/../.next/x.mjs"]"#,
            r#"[".next/node","x"]"#,
        ] {
            let e = proj("[]", "", &c(bad)).unwrap_err().0;
            assert!(
                e.contains("writable folder") || e.contains("climb"),
                "{bad}: {e}"
            );
        }
        // a command with no secret may run what it likes from a build folder
        assert!(proj(
            "[]",
            "",
            r#""run":{"allow":[],"argv":["node",".next/x.mjs"]}"#
        )
        .is_ok());
    }

    /// Declaration side: folder pins, and a pinned secret-receiving command is `node FILE`, never a package script.
    #[test]
    fn folder_pins_are_plain_paths_with_a_digest_and_do_not_overlap() {
        let h = "f".repeat(64);
        let t = |extra: &str| {
            proj(
                "[]",
                "",
                &format!(
                    r#""m":{{"allow":["K"],"env":["K"],"argv":["node","tests/m.mjs"]{extra}}}"#
                ),
            )
        };
        assert!(t(&format!(r#","pin":[{{"file":"tests/m.mjs","sha256":"{h}"}}],"pin_tree":[{{"path":"node_modules/@a/b","sha256":"{h}"}},{{"path":"node_modules/c","sha256":"{h}"}}]"#)).is_ok());
        for bad in [
            format!(r#","pin_tree":[{{"path":"/etc","sha256":"{h}"}}]"#),
            format!(r#","pin_tree":[{{"path":"../x","sha256":"{h}"}}]"#),
            r#","pin_tree":[{"path":"node_modules/c","sha256":"abc"}]"#.to_string(),
            format!(r#","pin_tree":[{{"path":".next/c","sha256":"{h}"}}]"#),
            format!(
                r#","pin_tree":[{{"path":"node_modules/c","sha256":"{h}"}},{{"path":"node_modules/c/sub","sha256":"{h}"}}]"#
            ),
            format!(
                r#","pin":[{{"file":"node_modules/c/i.js","sha256":"{h}"}}],"pin_tree":[{{"path":"node_modules/c","sha256":"{h}"}}]"#
            ),
            format!(r#","pin_tree":[{{"path":"node_modules/c","sha256":"{h}","x":1}}]"#),
        ] {
            assert!(t(&bad).is_err(), "{bad}");
        }
        let npm = proj(
            "[]",
            "",
            &format!(
                r#""m":{{"allow":["K"],"env":["K"],"argv":["npm","run","mint"],"pin":[{{"file":"package.json","sha256":"{h}"}}]}}"#
            ),
        );
        assert!(npm.unwrap_err().0.contains("not npm"));
        // unpinned `npm test` with a key keeps working as before: nothing was claimed about it
        assert!(proj(
            "[]",
            "",
            r#""m":{"allow":["K"],"env":["K"],"argv":["npm","test"]}"#
        )
        .is_ok());
        assert!(!sample().needs_v2());
        let p = t(&format!(
            r#","pin_tree":[{{"path":"node_modules/c","sha256":"{h}"}}]"#
        ))
        .unwrap();
        assert!(
            p.needs_v2() && !p.needs_runner_uids(),
            "one command alone shares nothing"
        );
        let two = proj(
            "[]",
            "",
            r#""m":{"allow":["K"],"env":["K"]},"s":{"allow":[]}"#,
        )
        .unwrap();
        assert!(two.needs_runner_uids());
        assert!(!proj("[]", "", r#""a":{"allow":[]},"b":{"allow":[]}"#)
            .unwrap()
            .needs_runner_uids());
    }

    #[test]
    fn a_pinned_command_takes_exactly_the_declared_words() {
        let h = "c".repeat(64);
        let p = Policy::parse(&format!(
            r#"{{"dir":"/work/projects/app","commands":{{
            "m":{{"allow":[],"argv":["node","t.mjs"],"pin":[{{"file":"t.mjs","sha256":"{h}"}}]}},
            "n":{{"allow":[],"argv":["npm","test"]}}}}}}"#
        ))
        .unwrap();
        let a = |w: &[&str]| w.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(p.command("m", &a(&["node", "t.mjs"])).is_ok());
        assert!(p.command("m", &a(&["node", "t.mjs", "--x"])).is_err());
        assert!(
            p.command("n", &a(&["npm", "test", "--", "-u"])).is_ok(),
            "an unpinned command keeps its prefix rule"
        );
    }

    /// G5 third round, N-M4: an identifier is found in any letter case, in the text and in a JWT payload.
    #[test]
    fn a_production_identifier_is_found_whatever_its_letter_case() {
        let mut p =
            Policy::parse(r#"{"dir":"/work/projects/app","commands":{"a":{"allow":[]}}}"#).unwrap();
        p.production_ids = vec!["AbcdProdRef".into()];
        assert!(p.production_hit("https://abcdprodref.supabase.co"));
        assert!(p.production_hit("https://ABCDPRODREF.supabase.co"));
        assert!(!p.production_hit("https://stagingref.supabase.co"));
    }

    /// A real application's declaration (one service, the folders its build traced, a few pinned files, a tool) is about 7 KB. It is
    /// a record, not a short credential, so it is stored whole and read back identically.
    #[test]
    fn a_realistic_declaration_is_stored_whole_and_read_back_identically() {
        let text = realistic_declaration(1, 45, 11);
        assert!(text.len() > 6000, "{}", text.len());
        let p = Policy::parse(&text).unwrap();
        let s = MemorySecrets::default();
        save(&s, "app", &p).unwrap();
        assert_eq!(load(&s, "app").unwrap().unwrap(), p);
    }

    /// The limit is enforced and says what it is: the size of the declaration and the size a box keeps.
    #[test]
    fn a_declaration_over_the_limit_is_refused_with_its_size_and_the_limit() {
        // valid by every count (64 commands, 64 folders and 16 files each) and still too big to keep
        let p = Policy::parse(&realistic_declaration(64, 64, 16)).unwrap();
        let s = MemorySecrets::default();
        let e = save(&s, "app", &p).unwrap_err().0;
        assert!(
            e.contains("256 KB") && e.contains(" KB once written out"),
            "{e}"
        );
        assert!(load(&s, "app").unwrap().is_none(), "nothing was stored");
        assert_eq!(p.to_record().unwrap_err().0, e);
        assert!(p.check_before_write().is_err());
        // one declaration just inside it is kept
        assert!(save(
            &s,
            "ok",
            &Policy::parse(&realistic_declaration(8, 64, 16)).unwrap()
        )
        .is_ok());
    }

    /// An earlier version stored the declaration as hex: it still loads, and the next save replaces it with the record.
    #[test]
    fn a_declaration_stored_as_hex_still_loads_and_the_next_save_writes_the_record() {
        let p = Policy::parse(&realistic_declaration(1, 4, 2)).unwrap();
        let s = MemorySecrets::default();
        s.set("workload-policy.app", &p.to_hex()).unwrap();
        assert_eq!(load(&s, "app").unwrap().unwrap(), p);
        save(&s, "app", &p).unwrap();
        let raw = s.get("workload-policy.app").unwrap().unwrap();
        assert!(raw.starts_with('{'), "{raw}");
        assert_eq!(load(&s, "app").unwrap().unwrap(), p);
    }
}
