//! Running the dashboard as a service on an Oz box, with its tunnel alongside. One systemd unit runs
//! `ozbox serve --public-url <address> --tunnel <provider>`: `serve` starts the tunnel itself and keeps it up, so the
//! two always start, stop and restart together.
//!
//! Everything that must outlive the machine lives on the `/work` disk (the program, its settings, state and secrets),
//! and the unit file (a `systemd --user` unit of the box user, which has no sudo: ADR 0011) is the only thing on the
//! system disk. An upgrade replaces the system disk, so after one the
//! install command is run again; it finds the program already there and only puts the unit back.

use super::{public_host, Kind};

/// Where the dashboard keeps everything on the box.
pub const HOME_DIR: &str = "/work/home/ozbox/ozbox-dashboard";

/// The box socket of the secrets service (see `secrets_service`).
pub const SECRET_SOCKET: &str = "/run/ozbox-secrets/box/box.sock";

/// Inputs are checked here again because the text is a file a service manager will run as the box user.
pub fn dashboard_unit(
    public_url: &str,
    kind: Option<Kind>,
    port: u16,
) -> Result<String, &'static str> {
    public_host(public_url)?;
    if !(1024..=65535).contains(&port) {
        return Err("tunnel.bad_port");
    }
    let tunnel = kind.map_or(String::new(), |k| format!(" --tunnel {}", k.id()));
    Ok(format!(
        "\
[Unit]
Description=Oz Box dashboard
After=network-online.target

[Service]
Type=simple
WorkingDirectory={HOME_DIR}
Environment=OZBOX_CONFIG={HOME_DIR}/config.toml
Environment=OZBOX_STATE_DIR={HOME_DIR}/state
# Secrets are kept by the box's secrets service (a different user); this process can write them and ask for the keyed tag
# of an id but cannot read the store. cloudflared runs under its own system unit as that user.
Environment=OZBOX_SECRET_STORE=socket
Environment=OZBOX_SECRET_SOCKET={SECRET_SOCKET}
Environment=OZBOX_TUNNEL_SYSTEM_UNIT=ozbox-cloudflared.service
EnvironmentFile=-{HOME_DIR}/dashboard.env
ExecStart={HOME_DIR}/bin/ozbox serve --bind 127.0.0.1 --port {port} --public-url {public_url}{tunnel}
Restart=on-failure
RestartSec=5
# Only what a user manager can do without namespaces (Ubuntu's AppArmor refuses those to an unprivileged user): no new
# privileges, no personality changes, and only the address families a web server and its tunnel use.
NoNewPrivileges=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes

[Install]
WantedBy=default.target
"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_binds_loopback_runs_as_the_box_user_and_carries_no_secret() {
        let u = dashboard_unit("https://ozbox.example.com", Some(Kind::Cloudflare), 7878).unwrap();
        assert!(u.contains("ExecStart=/work/home/ozbox/ozbox-dashboard/bin/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://ozbox.example.com --tunnel cloudflare\n"));
        // a user unit: no User=, no system target, and it needs no namespace-based sandboxing
        assert!(!u.contains("User=") && !u.contains("multi-user.target"));
        assert!(u.contains("WantedBy=default.target") && u.contains("NoNewPrivileges=yes"));
        assert!(
            !u.contains("ProtectSystem") && !u.contains("PrivateTmp") && !u.contains("ProtectHome")
        );
        assert!(!u.contains("0.0.0.0") && !u.contains("TOKEN") && !u.contains("token"));
        assert!(u.contains("OZBOX_SECRET_STORE=socket") && !u.contains("secrets.json"));
        // everything the service writes is on the persistent disk, in the box user's home
        assert!(u.contains("WorkingDirectory=/work/home/ozbox/"));
        let none = dashboard_unit("https://ozbox.example.com", None, 7878).unwrap();
        assert!(!none.contains("--tunnel"));
    }

    #[test]
    fn a_bad_address_or_port_makes_no_unit() {
        assert!(dashboard_unit("http://ozbox.example.com", None, 7878).is_err());
        assert!(dashboard_unit("https://x.example.com/a b", None, 7878).is_err());
        assert!(dashboard_unit(
            "https://ozbox.example.com\nExecStartPre=/bin/sh",
            None,
            7878
        )
        .is_err());
        assert!(dashboard_unit("https://ozbox.example.com", None, 80).is_err());
    }
}
