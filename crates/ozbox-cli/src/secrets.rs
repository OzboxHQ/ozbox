//! Write-only secrets: API keys, bot tokens, webhook URLs and signing secrets.
//!
//! A secret goes in through [`SecretStore::set`] and is read back only by the code that makes the outbound call, at the
//! moment of the call ([`SecretStore::get`]). Nothing the dashboard server answers carries one: the API reports only
//! whether a name is set. Locally the store is the operating system's keychain; a value is never put in a command line
//! (where `ps` would show it) and never in a file this program writes.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A failure that is safe to show: it never contains a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretError(pub String);

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SecretError {}

pub trait SecretStore: Send + Sync {
    fn set(&self, name: &str, value: &str) -> Result<(), SecretError>;
    /// For the sender, at send time. Never for a response.
    fn get(&self, name: &str) -> Result<Option<String>, SecretError>;
    fn exists(&self, name: &str) -> Result<bool, SecretError>;
    fn delete(&self, name: &str) -> Result<(), SecretError>;
    /// Store any value exactly (spaces, quotes, several lines, any text), read back by [`Self::get`] as it was. The default
    /// is the plain rule of [`Self::set`]: a store that cannot carry such a value refuses it rather than store it
    /// changed. Only a store that has an encoded form overrides this (the encrypted file, the keychain, the box socket).
    /// Tokens and anything a script or a command line may see keep the strict [`Self::set`].
    fn set_exact(&self, name: &str, value: &str) -> Result<(), SecretError> {
        self.set(name, value)
    }
    /// Where secrets are kept, in words for a person.
    fn label(&self) -> &'static str;
    /// Whether this store's own service decides if a change to a gated secret (a tunnel token) goes ahead, by asking for the
    /// approval the box user cannot make. Such a store needs no typed confirmation from the caller: a word typed by the
    /// box user is no control against the box user, and the service's answer says what to do.
    fn gates_replacement(&self) -> bool {
        false
    }
    /// HMAC-SHA256 tags of `msg` under the server's internal token keys, newest key first (see `tokenmac`). A store
    /// that holds the keys but must not hand them out (the box's secrets service) answers here; `None` means this store
    /// does not do that and the caller reads the keys itself.
    fn mac_tags(&self, _msg: &[u8]) -> Result<Option<Vec<[u8; 32]>>, SecretError> {
        Ok(None)
    }
    /// A store whose model keys cannot be read by the caller (the box's secrets service) runs the free provider checks
    /// ("list models", "test connection") where the key is and answers with the result. `None` means this store
    /// does not, and the caller reads the key and makes the call itself.
    fn probe(
        &self,
        _op: &str,
        _args: &serde_json::Value,
    ) -> Option<Result<serde_json::Value, SecretError>> {
        None
    }
}

pub const MAX_VALUE: usize = 4096;

/// The names this server will store, which keeps the keychain namespace small and the command arguments plain.
pub fn valid_name(name: &str) -> bool {
    const FIXED: [&str; 17] = [
        "email-api-key",
        "telegram-bot-token",
        "slack-webhook-url",
        "google-client-secret",
        "smtp-password",
        "sms-account",
        "sms-secret",
        "whatsapp-token",
        "discord-webhook-url",
        "teams-webhook-url",
        "vapid-private-key",
        "restic-password",
        "restic-env",
        "restic-access-key",
        "restic-secret-key",
        "store-kek",
        "internal-hmac-keys",
    ];
    if FIXED.contains(&name) {
        return true;
    }
    // A box's IDE or desktop password: the box name is the id (a box name is up to 40 characters).
    if ["ide-password-", "desktop-password-"].iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|id| ozbox_core::BoxName::new(id).is_ok())
    }) {
        return true;
    }
    [
        "webhook-url-",
        "webhook-secret-",
        "model-key-",
        "totp-",
        "push-endpoint-",
        "push-key-",
        "push-auth-",
        "tunnel-token-",
        "trigger-secret-",
        "approval-key-",
    ]
    .iter()
    .any(|p| {
        name.strip_prefix(p).is_some_and(|id| {
            !id.is_empty()
                && id.len() <= 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    })
}

/// Secrets only the sign-in module writes (an authenticator-app secret, the Google client secret). The generic secrets
/// routes refuse them, so a signed-in session cannot overwrite or delete a second factor through them.
pub fn is_auth_secret(name: &str) -> bool {
    name == "google-client-secret" || name.starts_with("totp-")
}

/// Secrets the server creates itself (the push signing key and a device's subscription). The generic secrets routes
/// refuse them: a browser registers a device through the push routes, which check what it sends.
pub fn is_managed_secret(name: &str) -> bool {
    name == "vapid-private-key"
        || name == "store-kek"
        || name == "internal-hmac-keys"
        || [
            "push-endpoint-",
            "push-key-",
            "push-auth-",
            "trigger-secret-",
            "ide-password-",
            "desktop-password-",
        ]
        .iter()
        .any(|p| name.starts_with(p))
}

/// Visible ASCII only, no space, quote or backslash: the PLAIN rule.
///
/// Why this is a boundary and is kept (decision 2026-11-12, I3): the same rule guards every store that hands a value to a
/// program as text. The macOS store sends `add-generic-password ... -w "<value>"` to `security -i`, where a quote, a
/// backslash or a space ends or changes the argument; a value with one would be stored wrongly or run as part of the
/// command. Tunnel and dashboard tokens go the same way into a script. (The key-import route does not parse a value: it
/// carries JSON, sealed, to the box's ingress account.)
///
/// A value that needs more than this (spaces, quotes, JSON, several lines: a `.env` value) is NOT refused for good: it is
/// stored through [`SecretStore::set_exact`], as base64 text that passes this rule, marked beside the entry, and decoded
/// only where it is used (an environment variable; never a command line, a script or a text file another program
/// parses). A value that passes this rule is stored exactly as before, so nothing already stored changes. Tokens keep
/// this rule.
pub fn check_value(value: &str) -> Result<(), SecretError> {
    if value.is_empty() {
        return Err(SecretError("the value is empty".into()));
    }
    if value.len() > MAX_VALUE {
        return Err(SecretError("the value is too long".into()));
    }
    if !value
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    {
        return Err(SecretError(
            "the value must be plain visible characters without spaces, quotes or backslashes"
                .into(),
        ));
    }
    Ok(())
}

#[derive(Default)]
pub struct MemorySecrets {
    map: Mutex<BTreeMap<String, String>>,
}

impl SecretStore for MemorySecrets {
    fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
        check_value(value)?;
        if let Ok(mut m) = self.map.lock() {
            m.insert(name.to_string(), value.to_string());
        }
        Ok(())
    }
    fn get(&self, name: &str) -> Result<Option<String>, SecretError> {
        Ok(self.map.lock().ok().and_then(|m| m.get(name).cloned()))
    }
    fn exists(&self, name: &str) -> Result<bool, SecretError> {
        Ok(self.map.lock().is_ok_and(|m| m.contains_key(name)))
    }
    fn delete(&self, name: &str) -> Result<(), SecretError> {
        if let Ok(mut m) = self.map.lock() {
            m.remove(name);
        }
        Ok(())
    }
    fn label(&self) -> &'static str {
        "memory (lost when the server stops)"
    }
}

/// Used where no keychain exists: every call explains that.
pub struct UnavailableSecrets(pub &'static str);

impl SecretStore for UnavailableSecrets {
    fn set(&self, _: &str, _: &str) -> Result<(), SecretError> {
        Err(SecretError(self.0.into()))
    }
    fn get(&self, _: &str) -> Result<Option<String>, SecretError> {
        Err(SecretError(self.0.into()))
    }
    fn exists(&self, _: &str) -> Result<bool, SecretError> {
        Err(SecretError(self.0.into()))
    }
    fn delete(&self, _: &str) -> Result<(), SecretError> {
        Err(SecretError(self.0.into()))
    }
    fn label(&self) -> &'static str {
        "not available"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// macOS `security`, driven through its interactive mode so the value arrives on stdin.
    Mac,
    /// `secret-tool` (libsecret), which reads the value from stdin.
    Linux,
}

pub struct KeychainSecrets {
    flavor: Flavor,
    program: String,
}

const SERVICE: &str = "ozbox";
/// A value the plain rule refuses is kept as base64 text under this second service, so a program from before encoded
/// values never finds it under the name it reads (and never takes base64 text for the value).
const SERVICE_B64: &str = "ozbox.b64";
/// What the keychain takes as an exact value: its base64 form must itself pass [`check_value`].
const MAX_KEYCHAIN_EXACT: usize = 3000;
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

impl KeychainSecrets {
    pub fn with_program(flavor: Flavor, program: impl Into<String>) -> Self {
        KeychainSecrets {
            flavor,
            program: program.into(),
        }
    }

    /// The keychain this computer has, or a store that says there is none.
    pub fn detect() -> Box<dyn SecretStore> {
        if cfg!(target_os = "macos") {
            return Box::new(Self::with_program(Flavor::Mac, "security"));
        }
        let found = std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("secret-tool").is_file()));
        if found {
            Box::new(Self::with_program(Flavor::Linux, "secret-tool"))
        } else {
            Box::new(UnavailableSecrets(
                "no keychain was found on this computer (install libsecret's secret-tool), so secrets cannot be saved",
            ))
        }
    }

    /// Run the tool. `stdin` is the only place a value ever travels.
    fn run(
        &self,
        args: &[&str],
        stdin: Option<&str>,
    ) -> Result<(Option<i32>, String), SecretError> {
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SecretError("the keychain tool could not be started".into()))?;
        if let Some(mut si) = child.stdin.take() {
            if let Some(text) = stdin {
                si.write_all(text.as_bytes()).map_err(|_| {
                    SecretError("the keychain tool did not accept the value".into())
                })?;
            }
        }
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if start.elapsed() > CALL_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SecretError(
                        "the keychain did not answer in time (is it locked?)".into(),
                    ));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(15)),
                Err(_) => return Err(SecretError("the keychain tool failed".into())),
            }
        }
        let out = child
            .wait_with_output()
            .map_err(|_| SecretError("the keychain tool failed".into()))?;
        Ok((
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        ))
    }

    fn check_name(name: &str) -> Result<(), SecretError> {
        if valid_name(name) {
            Ok(())
        } else {
            Err(SecretError("that is not a name this server stores".into()))
        }
    }
}

/// The one line sent to `security -i`. Name and value are validated to plain characters first.
fn mac_add_command_in(service: &str, name: &str, value: &str) -> String {
    format!("add-generic-password -a {name} -s {service} -w \"{value}\" -U\n")
}

impl KeychainSecrets {
    fn set_in(&self, service: &str, name: &str, value: &str) -> Result<(), SecretError> {
        // whatever reaches the tool has passed the plain rule: it is either the value or the base64 of one
        check_value(value)?;
        let (code, _) = match self.flavor {
            Flavor::Mac => self.run(&["-i"], Some(&mac_add_command_in(service, name, value)))?,
            Flavor::Linux => self.run(
                &[
                    "store",
                    "--label=Oz Box",
                    "service",
                    service,
                    "account",
                    name,
                ],
                Some(value),
            )?,
        };
        if code == Some(0) {
            Ok(())
        } else {
            Err(SecretError("the keychain refused to save the value".into()))
        }
    }

    fn get_in(&self, service: &str, name: &str) -> Result<Option<String>, SecretError> {
        let (code, out) = match self.flavor {
            Flavor::Mac => self.run(
                &["find-generic-password", "-a", name, "-s", service, "-w"],
                None,
            )?,
            Flavor::Linux => self.run(&["lookup", "service", service, "account", name], None)?,
        };
        if code != Some(0) {
            return Ok(None);
        }
        let v = out.trim_end_matches(['\n', '\r']).to_string();
        Ok((!v.is_empty()).then_some(v))
    }

    fn exists_in(&self, service: &str, name: &str) -> Result<bool, SecretError> {
        match self.flavor {
            // No `-w` or `-g`: the item's attributes only, never its value.
            Flavor::Mac => Ok(self
                .run(&["find-generic-password", "-a", name, "-s", service], None)?
                .0
                == Some(0)),
            Flavor::Linux => Ok(self.get_in(service, name)?.is_some()),
        }
    }

    fn delete_in(&self, service: &str, name: &str) -> Result<(), SecretError> {
        match self.flavor {
            Flavor::Mac => self.run(
                &["delete-generic-password", "-a", name, "-s", service],
                None,
            )?,
            Flavor::Linux => self.run(&["clear", "service", service, "account", name], None)?,
        };
        Ok(())
    }
}

impl SecretStore for KeychainSecrets {
    fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
        Self::check_name(name)?;
        check_value(value)?;
        self.set_in(SERVICE, name, value)?;
        // a value set the plain way replaces an encoded one of the same name
        self.delete_in(SERVICE_B64, name)
    }

    fn set_exact(&self, name: &str, value: &str) -> Result<(), SecretError> {
        Self::check_name(name)?;
        if check_value(value).is_ok() {
            return self.set(name, value);
        }
        if value.is_empty() || value.contains('\0') {
            return Err(SecretError(
                "the value is empty or contains a NUL byte".into(),
            ));
        }
        if value.len() > MAX_KEYCHAIN_EXACT {
            return Err(SecretError(format!(
                "the keychain keeps values up to {MAX_KEYCHAIN_EXACT} bytes in this form"
            )));
        }
        // the tool only ever sees the base64 text: no quote, space, backslash or line break can reach its input
        let b64 = crate::serve::auth::b64::encode_std(value.as_bytes());
        self.set_in(SERVICE_B64, name, &b64)?;
        self.delete_in(SERVICE, name)
    }

    fn get(&self, name: &str) -> Result<Option<String>, SecretError> {
        Self::check_name(name)?;
        if let Some(v) = self.get_in(SERVICE, name)? {
            return Ok(Some(v));
        }
        match self.get_in(SERVICE_B64, name)? {
            None => Ok(None),
            Some(b64) => crate::serve::auth::b64::decode_std(&b64)
                .and_then(|b| String::from_utf8(b).ok())
                .map(Some)
                .ok_or_else(|| SecretError("a stored secret is damaged".into())),
        }
    }

    fn exists(&self, name: &str) -> Result<bool, SecretError> {
        Self::check_name(name)?;
        Ok(self.exists_in(SERVICE, name)? || self.exists_in(SERVICE_B64, name)?)
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        Self::check_name(name)?;
        self.delete_in(SERVICE, name)?;
        self.delete_in(SERVICE_B64, name)
    }

    fn label(&self) -> &'static str {
        match self.flavor {
            Flavor::Mac => "the macOS keychain",
            Flavor::Linux => "the desktop keyring",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn names_and_values_are_validated() {
        for ok in [
            "email-api-key",
            "telegram-bot-token",
            "slack-webhook-url",
            "webhook-url-ab1",
            "model-key-anthropic-main",
            "ide-password-dev",
            "desktop-password-my-box-2",
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        // a box's IDE password is made by the server, never through the generic route
        assert!(is_managed_secret("ide-password-dev") && is_managed_secret("desktop-password-dev"));
        for bad in [
            "",
            "x",
            "webhook-url-",
            "webhook-url-UP",
            "model-key-a b",
            "../x",
            "email-api-key ",
            "model-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ide-password-",
            "ide-password-UP",
            "ide-password-a--b",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(check_value("sk-ant-abc123_XYZ.=").is_ok());
        for bad in [
            "",
            "has space",
            "quo\"te",
            "back\\slash",
            "new\nline",
            "tab\t",
            "é",
        ] {
            assert!(check_value(bad).is_err(), "{bad:?}");
        }
        assert!(check_value(&"a".repeat(MAX_VALUE + 1)).is_err());
    }

    #[test]
    fn the_mac_command_carries_the_value_on_stdin_text_only() {
        assert_eq!(
            mac_add_command_in(SERVICE, "model-key-a", "tok123"),
            "add-generic-password -a model-key-a -s ozbox -w \"tok123\" -U\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_never_appears_in_the_tools_command_line() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let argv_log = dir.path().join("argv.log");
        let store_dir = dir.path().join("store");
        std::fs::create_dir(&store_dir)?;
        let script = dir.path().join("secret-tool");
        // A stand-in for libsecret's tool: logs argv, keeps the stdin value in a file named after the account.
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{log}'\ncmd=$1\nshift\nsvc=; acct=\nwhile [ $# -gt 0 ]; do case $1 in service) svc=$2;; account) acct=$2;; esac; shift; done\nkey=\"$svc.$acct\"\ncase $cmd in\n store) cat > '{s}'/\"$key\" ;;\n lookup) cat '{s}'/\"$key\" 2>/dev/null || exit 1 ;;\n clear) rm -f '{s}'/\"$key\" ;;\nesac\n",
                log = argv_log.display(),
                s = store_dir.display()
            ),
        )?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        let k = KeychainSecrets::with_program(Flavor::Linux, script.to_string_lossy());
        let sentinel = "SENTINEL-value-8472";
        assert!(!k.exists("model-key-a")?);
        k.set("model-key-a", sentinel)?;
        assert!(k.exists("model-key-a")?);
        assert_eq!(k.get("model-key-a")?.as_deref(), Some(sentinel));
        let log = std::fs::read_to_string(&argv_log)?;
        assert!(
            !log.contains(sentinel),
            "the value reached the command line"
        );
        assert!(log.contains("store"));
        k.delete("model-key-a")?;
        assert!(!k.exists("model-key-a")?);
        assert!(k.set("not-a-name", "x").is_err());
        Ok(())
    }

    /// A stand-in for `security` (macOS, driven by `-i` on standard input) and for `secret-tool` (Linux), both as python so
    /// the interactive line parser is real: a word in double quotes is one word, as `security -i` reads it. It keeps
    /// every byte it is sent in `stdin.log`, one file per item. Skipped where python3 is absent.
    #[cfg(unix)]
    fn fake_keychain(dir: &std::path::Path, mac: bool) -> Option<KeychainSecrets> {
        use std::os::unix::fs::PermissionsExt;
        if Command::new("python3").arg("--version").output().is_err() {
            return None;
        }
        let store = dir.join("items");
        std::fs::create_dir_all(&store).unwrap();
        let script = dir.join(if mac { "security" } else { "secret-tool" });
        let body = if mac {
            r#"#!/usr/bin/env python3
import os, shlex, sys
store = "STORE"
a = sys.argv[1:]
if a and a[0] == "-i":
    data = sys.stdin.read()
    open(os.path.join(store, "stdin.log"), "ab").write(data.encode())
    for line in data.split("\n"):
        if not line.strip():
            continue
        w = shlex.split(line)
        if w[0] == "add-generic-password":
            acct, svc, val = w[w.index("-a") + 1], w[w.index("-s") + 1], w[w.index("-w") + 1]
            open(os.path.join(store, svc + "__" + acct), "w").write(val)
    sys.exit(0)
acct, svc = a[a.index("-a") + 1], a[a.index("-s") + 1]
f = os.path.join(store, svc + "__" + acct)
if a[0] == "find-generic-password":
    if not os.path.exists(f):
        sys.exit(44)
    if "-w" in a:
        print(open(f).read())
    sys.exit(0)
if a[0] == "delete-generic-password" and os.path.exists(f):
    os.remove(f)
"#
        } else {
            r#"#!/usr/bin/env python3
import os, sys
store = "STORE"
a = sys.argv[1:]
svc, acct = a[a.index("service") + 1], a[a.index("account") + 1]
f = os.path.join(store, svc + "__" + acct)
if a[0] == "store":
    data = sys.stdin.read()
    open(os.path.join(store, "stdin.log"), "ab").write(data.encode() + b"\n")
    open(f, "w").write(data)
elif a[0] == "lookup":
    if not os.path.exists(f):
        sys.exit(1)
    sys.stdout.write(open(f).read() + "\n")
elif a[0] == "clear" and os.path.exists(f):
    os.remove(f)
"#
        }
        .replace("STORE", &store.to_string_lossy());
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        Some(KeychainSecrets::with_program(
            if mac { Flavor::Mac } else { Flavor::Linux },
            script.to_string_lossy(),
        ))
    }

    /// Both keychains, every hostile value that fits: stored and returned exactly, and the tool is only ever sent plain
    /// text (the base64 form), never the value, and never more than one line per add.
    #[cfg(unix)]
    #[test]
    fn the_keychain_stores_any_value_exactly_and_its_tool_only_ever_sees_base64() {
        for mac in [true, false] {
            let d = tempfile::tempdir().unwrap();
            let Some(k) = fake_keychain(d.path(), mac) else {
                return;
            };
            let mut sets = 0;
            for v in crate::secrets_enc::hostile::values()
                .iter()
                .filter(|v| v.len() <= MAX_KEYCHAIN_EXACT)
            {
                // the strict rule still refuses it, and refuses before the tool is started
                if check_value(v).is_err() {
                    assert!(k.set("restic-env", v).is_err());
                }
                k.set_exact("restic-env", v).unwrap();
                sets += 1;
                assert!(k.exists("restic-env").unwrap());
                assert_eq!(
                    k.get("restic-env").unwrap().as_deref(),
                    Some(v.as_str()),
                    "mac={mac}"
                );
            }
            // one entry per name, whichever way it was last stored
            k.set("restic-env", "plain-0123456789").unwrap();
            assert_eq!(
                k.get("restic-env").unwrap().as_deref(),
                Some("plain-0123456789")
            );
            k.set_exact("restic-env", "now has spaces").unwrap();
            assert_eq!(
                k.get("restic-env").unwrap().as_deref(),
                Some("now has spaces")
            );
            k.delete("restic-env").unwrap();
            assert!(!k.exists("restic-env").unwrap() && k.get("restic-env").unwrap().is_none());
            // what the tool was sent
            let log = std::fs::read(d.path().join("items/stdin.log")).unwrap();
            let log = String::from_utf8(log).unwrap();
            for frag in [
                "evil",
                "touch",
                "PRIVATE KEY",
                "quotes",
                "emoji",
                "leading",
                "CRLF",
                "$(",
                "\"double",
            ] {
                assert!(!log.contains(frag), "mac={mac}: {frag} reached the tool");
            }
            if mac {
                // one `add-generic-password` per line, and each line has exactly one newline
                assert!(
                    log.lines()
                        .all(|l| l.starts_with("add-generic-password -a restic-env -s ")),
                    "{log}"
                );
                assert_eq!(
                    log.matches("add-generic-password").count(),
                    log.lines().count()
                );
                assert!(log.matches("add-generic-password").count() >= sets);
            }
        }
    }

    /// The generic default: a store with no encoded form refuses what the plain rule refuses.
    #[test]
    fn a_store_without_an_encoded_form_keeps_the_plain_rule() {
        let m = MemorySecrets::default();
        assert!(m.set_exact("email-api-key", "has space").is_err());
        assert!(m.get("email-api-key").unwrap().is_none());
        m.set_exact("email-api-key", "plain-12345").unwrap();
        assert_eq!(
            m.get("email-api-key").unwrap().as_deref(),
            Some("plain-12345")
        );
    }

    #[test]
    fn memory_store_round_trips() -> Result<(), SecretError> {
        let m = MemorySecrets::default();
        m.set("email-api-key", "abc")?;
        assert_eq!(m.get("email-api-key")?.as_deref(), Some("abc"));
        m.delete("email-api-key")?;
        assert!(!m.exists("email-api-key")?);
        Ok(())
    }
}
