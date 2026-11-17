//! The two processes the credential holder is made of, started from the command line (ADR 0040 §1, §6): the holder's socket
//! service, and the apply unit it starts for one plan. Everything they decide lives in [`crate::fleet_holder`]; this file only
//! wires files, the clock and a real cloud CLI to it.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec, Provider, SystemRunner};

use crate::fleet_holder::{
    run_apply_unit, serve, AwsCliReadSource, Holder, HolderConfig, Peers, ProcessApplyUnit,
    SessionCreds, SOCKET_MODE,
};

pub struct HolderArgs {
    pub socket: PathBuf,
    pub dir: PathBuf,
    pub box_id: String,
    pub store_id: String,
    pub this_box: String,
    pub laptop_key: String,
    pub dashboard_uid: u32,
    pub ingress_uid: u32,
    pub role_arn: String,
    pub apply_uid: String,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The holder's own key: made on first start, readable by this user only (mode 0600, in this user's own folder). The box user
/// and the dashboard are other users and cannot read it.
fn load_or_make_key(dir: &std::path::Path) -> Result<ozbox_seal::ServiceKey, String> {
    use std::io::Write;
    let path = dir.join("service-key");
    match std::fs::read_to_string(&path) {
        Ok(hex) => {
            let bytes: Option<Vec<u8>> = ozbox_core::approval_subject::from_hex(hex.trim());
            ozbox_seal::ServiceKey::from_secret_bytes(&bytes.ok_or("the holder's key is damaged")?)
                .map_err(|e| e.to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = ozbox_seal::ServiceKey::generate().map_err(|e| e.to_string())?;
            let secret = key.secret_bytes();
            let hex = zeroize::Zeroizing::new(ozbox_core::approval_subject::to_hex(&secret[..]));
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode_0600()
                .open(&path)
                .map_err(|_| "the holder's key cannot be saved")?;
            f.write_all(hex.as_bytes())
                .and_then(|()| f.sync_all())
                .map_err(|_| "the holder's key cannot be saved")?;
            Ok(key)
        }
        Err(_) => Err("the holder's key cannot be read".into()),
    }
}

trait Mode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}
impl Mode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600)
    }
}

/// Run the holder until it is stopped.
pub fn holder_main(a: &HolderArgs) -> Result<(), String> {
    std::fs::create_dir_all(&a.dir).map_err(|_| "the holder's folder cannot be made")?;
    let key = load_or_make_key(&a.dir)?;
    println!("holder key {}", ozbox_seal::public_to_hex(&key.public()));
    let runner = SystemRunner;
    let mut holder = Holder::new(
        HolderConfig {
            box_id: a.box_id.clone(),
            store_id: a.store_id.clone(),
            this_box: a.this_box.clone(),
            laptop_public_hex: a.laptop_key.clone(),
            dir: a.dir.clone(),
        },
        key,
        Box::new(OwnedAwsCliSource {
            role_arn: a.role_arn.clone(),
            box_name: a.this_box.clone(),
        }),
    )?;
    let _ = std::fs::remove_file(&a.socket);
    let listener = std::os::unix::net::UnixListener::bind(&a.socket)
        .map_err(|_| "the holder's socket cannot be opened")?;
    std::fs::set_permissions(&a.socket, std::fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|_| "the holder's socket cannot be protected")?;
    let unit = ProcessApplyUnit {
        runner: &runner,
        uid: a.apply_uid.clone(),
        program: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "ozbox".into()),
        region: None,
    };
    let peers = Peers {
        dashboard_uid: a.dashboard_uid,
        ingress_uid: a.ingress_uid,
    };
    serve(&mut holder, &peers, &unit, &listener, &now_ms, &|| false);
    Ok(())
}

struct OwnedAwsCliSource {
    role_arn: String,
    box_name: String,
}

impl crate::fleet_holder::ReadSessionSource for OwnedAwsCliSource {
    fn assume_read(&self, now: u64) -> Result<SessionCreds, String> {
        AwsCliReadSource {
            runner: &SystemRunner,
            role_arn: self.role_arn.clone(),
            box_name: self.box_name.clone(),
        }
        .assume_read(now)
    }
}

/// The apply unit: the change session and the plan arrive on standard input; the plan is applied once, through the cloud
/// provider with that session's variables on each call and nowhere else.
pub fn apply_unit_main() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(1 << 20)
        .read_to_end(&mut input)
        .map_err(|_| "the apply's input cannot be read")?;
    let v = run_apply_unit(&input, &|i| {
        let runner: Arc<dyn CommandRunner> = Arc::new(SessionRunner(i.session.clone()));
        let cfg = ozbox_provider_aws::AwsConfig {
            region: i.region.clone(),
            ..ozbox_provider_aws::AwsConfig::default()
        };
        Ok(Box::new(ozbox_core::Engine::new(
            ozbox_provider_aws::AwsBackend::new(runner, cfg),
        )) as Box<dyn Provider>)
    })?;
    println!("{v}");
    Ok(())
}

struct SessionRunner(SessionCreds);

impl CommandRunner for SessionRunner {
    fn run(&self, cmd: &CommandSpec) -> ozbox_core::Result<ozbox_core::Output> {
        let mut c = cmd.clone();
        for (k, v) in self.0.env() {
            c.env.insert(k, v);
        }
        SystemRunner.run(&c)
    }
}
