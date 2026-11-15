//! The box's layout keeps secrets out of the box user's reach: read from the cloud-init template, its setup script and the
//! image script, so it runs anywhere with no cloud.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

fn repo(file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(file);
    std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("could not read {file}"))
}

const SETUP: &str = "infra/cloud-init/scripts/ozbox-secrets-setup.sh";

/// The text of the here-document that ends at `marker`.
fn section<'a>(t: &'a str, marker: &str) -> &'a str {
    let end = t
        .find(&format!("\n{marker}\n"))
        .unwrap_or_else(|| panic!("{marker} is not in the script"));
    let start = t[..end]
        .rfind(&format!("'{marker}'"))
        .unwrap_or_else(|| panic!("{marker} has no start"));
    &t[start..end]
}

#[test]
fn the_secrets_user_and_directories_are_private_to_it() {
    let t = repo(SETUP);
    assert!(t.contains("useradd --system") && t.contains("--shell /usr/sbin/nologin"));
    assert!(t.contains("passwd --lock ozbox-secrets"));
    let tmp = section(&t, "EOF_TMPFILES");
    // the store's home and the admin socket's directory are 0700 and owned by the secrets user alone
    assert!(tmp.contains("d /var/lib/ozbox-secrets      0700 ozbox-secrets ozbox-secrets"));
    assert!(tmp.contains("d /run/ozbox-secrets/admin    0700 ozbox-secrets ozbox-secrets"));
    // the only directories the box user's group may enter are the box socket's and the broker's (it issues run tokens and
    // never returns a key), the import socket's (it takes keys in and answers names) and the
    // launcher's (root's, where the command launcher listens); the admin directory and the store stay private
    for line in tmp.lines().filter(|l| l.trim_start().starts_with("d ")) {
        let group = line.split_whitespace().nth(4).unwrap_or("");
        if group == "ozbox" {
            assert!(
                (line.contains("/run/ozbox-secrets/box")
                    || line.contains("/run/ozbox-secrets/broker")
                    || line.contains("/run/ozbox-secrets/import")
                    || line.contains("d /run/ozbox-runner "))
                    && line.contains("0750"),
                "{line}"
            );
        }
    }
    // the box user is not made a member of the secrets group anywhere
    assert!(!t.contains("usermod -aG ozbox-secrets") && !t.contains("gpasswd -a ozbox"));
}

#[test]
fn the_units_that_hold_secrets_run_as_the_secrets_user_with_their_hardening() {
    let t = repo(SETUP);
    for unit in ["EOF_SECRETS", "EOF_CLOUDFLARED"] {
        let b = section(&t, unit);
        for flag in [
            "User=ozbox-secrets",
            "NoNewPrivileges=true",
            "ProtectHome=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "LimitCORE=0",
        ] {
            assert!(b.contains(flag), "{unit} lacks {flag}");
        }
        // a root-owned program, never one in the box user's home or on /work
        assert!(
            b.contains("ExecStart=/usr/local/bin/") && !b.contains("ExecStart=/work/"),
            "{unit}"
        );
    }
}

#[test]
fn the_service_hosts_the_broker_and_holds_only_the_file_capabilities_restic_needs() {
    let t = repo(SETUP);
    let b = section(&t, "EOF_SECRETS");
    assert!(b.contains("--broker-socket /run/ozbox-secrets/broker/broker.sock"));
    // restic reads every file of /work and puts files back: those four capabilities, nothing else
    assert!(b.contains(
        "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER"
    ));
    assert!(
        b.contains("AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER")
    );
    assert!(!b.contains("CAP_SYS_") && !b.contains("CAP_NET_"));
    // the web IDE connector is its own unit under the secrets user, enabled by the admin action (root), never by the box
    // user; it has an [Install] section so that enabling it means something and it returns after a reboot or an upgrade
    let c = section(&t, "EOF_CODE_CONNECTOR");
    assert!(
        c.contains("User=ozbox-secrets")
            && c.contains("tunnel-token-ide")
            && c.contains("[Install]")
            && c.contains("WantedBy=multi-user.target")
    );
    // the box daemon is told where the service is, and writes no credentials file
    let tpl = repo("infra/cloud-init/box.yaml.tftpl");
    assert!(tpl.contains("service_socket = \"/run/ozbox-secrets/broker/broker.sock\""));
    assert!(
        !tpl.contains("restic.pass") && !tpl.contains("chown root:ozbox /etc/ozbox/restic.env")
    );
}

#[test]
fn no_secret_file_is_readable_by_the_box_user_in_the_rendered_layout() {
    let t = repo("infra/cloud-init/box.yaml.tftpl") + &repo(SETUP);
    // the tunnel token is not written as a file the box user can open
    assert!(!t.contains("cloudflared.env"));
    assert!(
        !t.lines()
            .any(|l| l.contains("chown root:ozbox") && l.contains("secret")),
        "a secret file is handed to the box group"
    );
    let sysctl = section(&t, "EOF_SYSCTL");
    assert!(
        sysctl.contains("kernel.yama.ptrace_scope = 1") && sysctl.contains("fs.suid_dumpable = 0")
    );
}

#[test]
fn the_image_makes_the_same_user_and_rule() {
    let p = repo("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(
        p.contains("useradd --system --gid ozbox-secrets")
            && p.contains("install -d -m 0700 -o ozbox-secrets")
    );
    assert!(p.contains("kernel.yama.ptrace_scope = 1"));
}

#[test]
fn the_setup_script_uses_the_socket_not_a_file_store() {
    let s = repo("infra/box/dashboard-setup.sh");
    assert!(s.contains("OZBOX_SECRET_STORE=socket") && !s.contains("OZBOX_SECRET_STORE=file"));
}

#[test]
fn the_user_data_stays_inside_the_provider_limit() {
    // Coarse guard on the raw template (the module tests check the rendered size) so growth is noticed early. Raised from
    // 24 000 when the first-boot record and the ingress account met in one template (24 447 bytes). The rendered checks are
    // what decide (the modules' own tests): Hetzner under 32 KiB raw, AWS under 16 KB gzipped. Both drop the template's
    // comment lines before rendering; the AWS module started doing so in the same change, when its rendered size had gone
    // over the limit. Raised again from 25 000 when the memory guard's first-boot line met the dashboard role's
    // additions in one template (25 118 bytes); the rendered AWS size is the one that matters and has about 1.4 KB of room.
    let t = repo("infra/cloud-init/box.yaml.tftpl");
    assert!(t.len() < 26_000, "the template is {} bytes", t.len());
}

#[test]
fn the_supervisor_has_a_socket_directory_the_box_group_cannot_enter_and_the_box_users_sockets_shrink(
) {
    let t = repo(SETUP);
    let tmp = section(&t, "EOF_TMPFILES");
    // only the supervisor's group may enter its directory; the memory store's directory is private to the secrets user
    assert!(tmp.contains("d /run/ozbox-secrets/supervisor 0750 ozbox-secrets ozbox-supervisor"));
    assert!(tmp.contains("d /run/ozbox-secrets/memory   0700 ozbox-secrets ozbox-secrets"));
    let svc = section(&t, "EOF_SECRETS");
    assert!(svc.contains("--supervisor-socket /run/ozbox-secrets/supervisor/supervisor.sock"));
    assert!(svc.contains("--memory-store /run/ozbox-secrets/memory/box-secrets.json"));
    // the supervisor is a user of its own, no login, and not the box user
    assert!(t.contains("useradd --system --user-group") && t.contains("ozbox-supervisor"));
    assert!(!t.contains("usermod -aG ozbox-supervisor ozbox") && !t.contains("gpasswd -a ozbox "));
    // the box's own secrets are loaded by the secrets user and from a file no secret is in
    let load = section(&t, "EOF_BOXSECRETS");
    assert!(
        load.contains("User=ozbox-secrets")
            && load.contains("ExecStart=/usr/local/bin/ozbox secrets load-box")
    );
    assert!(
        load.contains("EnvironmentFile=-/etc/ozbox/box-secrets.env")
            && load.contains("ExecStartPre=+/usr/local/bin/ozbox secrets configure-box")
            && !load.contains("/work/")
    );
}

#[test]
fn the_supervisors_unit_runs_a_root_owned_program_as_its_own_user_from_its_own_folder() {
    let t = repo("infra/cloud-init/scripts/ozbox-supervisor-setup.sh");
    let start = t
        .find("cat <<EOF_UNIT\n")
        .unwrap_or_else(|| panic!("the unit is written here"));
    let unit = &t[start
        ..t[start..]
            .find("\nEOF_UNIT\n")
            .map(|e| start + e)
            .unwrap_or_else(|| panic!("the unit ends"))];
    for want in [
        "User=$sup",
        "ExecStart=$ozbox_bin serve --bind 127.0.0.1",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "LimitCORE=0",
        "ReadWritePaths=$home",
    ] {
        assert!(unit.contains(want), "{want}");
    }
    // never the box user's home or a program on /work that the box user owns
    assert!(!unit.contains("/work/home") && !unit.contains("ozbox-dashboard/bin"));
    assert!(t.contains("ozbox_bin=\"${OZBOX_BIN:-/usr/local/bin/ozbox}\""));
}

#[test]
fn the_audit_chain_belongs_to_the_secrets_service_lives_on_the_persistent_disk_and_the_box_user_can_only_read_it(
) {
    let t = repo(SETUP);
    let svc = section(&t, "EOF_SECRETS");
    // the chain's folder is on /work (an upgrade keeps it), made by the service itself: owned by the secrets user, readable by all
    assert!(svc.contains("--audit-dir /work/ozbox-audit"));
    // the second copy of each checkpoint is in the secrets user's own private folder
    assert!(svc.contains("--audit-anchor-dir /work/ozbox-secrets-private/audit-anchor"));
    // the copy of the store that survives a system-disk replacement is in that private folder too
    assert!(svc.contains("--persist-dir /work/ozbox-secrets-private"));
    // the seal key is a secret in the store: no setup step makes a key file for the chain or hands a folder to a group
    assert!(
        !t.contains("audit.key")
            && !t.contains("chgrp ozbox /work/ozbox-audit")
            && !t.contains("chmod 0770 /work/ozbox-audit")
    );
}

#[test]
fn a_box_with_no_kms_key_still_starts_its_store_and_an_unconfigured_one_is_not_retried_every_few_seconds(
) {
    let t = repo(SETUP);
    // no KMS key: the file key is chosen explicitly, in the environment file the service reads
    assert!(t.contains("[ -n \"${2:-}\" ] || printf 'OZBOX_SECRET_ALLOW_FILE_KEK=1"));
    let svc = section(&t, "EOF_SECRETS");
    assert!(
        svc.contains("RestartPreventExitStatus=78"),
        "a not-configured exit must not crash-loop"
    );
    assert!(svc.contains("Restart=on-failure") && svc.contains("RestartSec=5"));
}

#[test]
fn the_box_secrets_loader_may_read_a_root_only_vault_token_file_and_nothing_puts_one_in_user_data()
{
    let t = repo(SETUP);
    let u = section(&t, "EOF_BOXSECRETS");
    assert!(u.contains("EnvironmentFile=-/etc/ozbox/bao.env"));
    // a token is placed through the root helper only: no template or module variable carries one
    let tpl = repo("infra/cloud-init/box.yaml.tftpl");
    assert!(!tpl.contains("BAO_TOKEN"));
    let vars = repo("infra/tofu/modules/hcloud-box/variables.tf");
    assert!(!vars.to_lowercase().contains("bao_token") && !vars.contains("vault_token"));
}

/// The box's first approver arrives with the first-boot configuration (root), never from inside the box; the store's key is
/// escrowed with the box's own vault credential, which the box user never holds.
#[test]
fn the_setup_step_pins_the_first_approver_and_the_units_carry_the_vault_credential_for_the_escrow()
{
    let s = repo(SETUP);
    // only a well-formed base32 key, written by root, readable by all, writable by root alone
    assert!(s.contains("grep -Eq '^[a-z2-7]{52}$'"));
    assert!(s.contains("printf 'laptop %s\\n' \"$4\""));
    assert!(s.contains("chmod 0644 \"$pinfile.tmp\""));
    let unit = section(&s, "EOF_SECRETS");
    assert!(unit.contains("EnvironmentFile=-/etc/ozbox/box-secrets.env"));
    assert!(unit.contains("EnvironmentFile=-/etc/ozbox/bao.env"));
    let loader = section(&s, "EOF_BOXSECRETS");
    assert!(loader.contains("Environment=OZBOX_SECRET_FILE=/var/lib/ozbox-secrets/secrets.json"));
    assert!(loader.contains("EnvironmentFile=/etc/ozbox/secrets.env"));
}

#[test]
fn the_box_users_own_folders_come_after_the_system_path_in_a_login_shell() {
    // Hygiene, not a lock: the home folders are appended so a program planted in ~/.local/bin does not shadow a system one
    // in a login shell that reads only this file. The stock ~/.profile still prepends ~/.local/bin, and the box user owns
    // its start-up files, so this does NOT protect key imports: those no longer go through this shell at all (they go to the
    // ingress account, see `workload_cli::ssh_receive`).
    let t = repo("infra/cloud-init/box.yaml.tftpl");
    let at = t
        .find("/etc/profile.d/ozbox-path.sh")
        .expect("the PATH file");
    let line = t[at..]
        .lines()
        .find(|l| l.trim_start().starts_with("export PATH="))
        .expect("an export PATH line");
    let value = line.split('"').nth(1).expect("a quoted value");
    let sys = value.find("$PATH").expect("the system PATH is kept");
    let local = value.find("$HOME/.local/bin").expect(".local/bin is there");
    let cargo = value.find("$HOME/.cargo/bin").expect(".cargo/bin is there");
    assert!(
        sys < local && sys < cargo,
        "home folders must follow $PATH: {value}"
    );
}

// ---- the ingress account (ADR 0029, Amendment 9) ----

#[test]
fn the_secrets_service_listens_for_the_ingress_account_and_the_box_users_folders_are_unchanged() {
    let t = repo(SETUP);
    let svc = section(&t, "EOF_SECRETS");
    assert!(svc.contains("--ingress-socket /run/ozbox-secrets/ingress/ingress.sock"));
    // the ingress folder is made by the ingress setup (its group is the account's), never here with the box user's group
    let tmp = section(&t, "EOF_TMPFILES");
    assert!(!tmp.contains("ingress"));
}

#[test]
fn first_boot_makes_the_ingress_account_before_the_secrets_service_and_lets_only_it_in_besides_the_box_user(
) {
    let tpl = repo("infra/cloud-init/box.yaml.tftpl");
    let ingress = tpl
        .find("ozbox secrets ingress-setup '${ingress_key}'")
        .expect("first boot makes the ingress account");
    let secrets = tpl
        .find("ozbox-secrets-setup.sh, \"${box_name}\"")
        .expect("first boot sets up the secrets service");
    assert!(
        ingress < secrets,
        "the account's group must exist before the service's folder is made"
    );
    assert!(tpl.contains("AllowUsers ozbox ozbox-ingress\n"));
    // no other account is let in, and the box user's key is still the only one on its own route
    assert!(!tpl.contains("AllowUsers ozbox ozbox-ingress "));
    assert!(tpl.contains("PermitRootLogin no") && tpl.contains("AuthenticationMethods publickey"));
}

#[test]
fn the_image_carries_the_ingress_account_with_no_key_and_nothing_in_a_user_writable_folder() {
    let p = repo("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(p.contains("/usr/local/bin/ozbox secrets ingress-setup \"\""));
    // made after the program is installed (it is the program that makes the account)
    let installed = p
        .find("install -m 0755 -o root -g root \"$ozbox_upload\" /usr/local/bin/ozbox")
        .unwrap();
    assert!(installed < p.find("secrets ingress-setup").unwrap());
    // no script of the box writes an ingress key anywhere the box user can write
    for f in [
        SETUP,
        "infra/cloud-init/box.yaml.tftpl",
        "infra/packer/ozbox-image/scripts/provision.sh",
    ] {
        let t = repo(f);
        for line in t.lines().filter(|l| l.contains("ozbox-ingress")) {
            assert!(
                !line.contains("/work")
                    && !line.contains("/home")
                    && !line.contains(".ssh/authorized_keys"),
                "{f}: {line}"
            );
        }
    }
}

/// The managed Claude Code setting that turns off commands written in a skill's text ships on every new box, root-owned and
/// not writable by the box user, with exactly this content; and the box user's own settings carry it as a second layer.
#[test]
fn the_box_ships_claude_codes_managed_setting_that_stops_skill_commands() {
    let t = repo("infra/cloud-init/box.yaml.tftpl");
    let entry = t
        .split("  - path: /etc/claude-code/managed-settings.json\n")
        .nth(1)
        .expect("the managed settings file is written")
        .split("\n  - path:")
        .next()
        .unwrap_or_default();
    assert!(entry.contains("permissions: \"0644\""), "{entry}");
    assert!(entry.contains("owner: root:root"), "{entry}");
    assert!(
        entry.contains("{\"disableSkillShellExecution\": true}"),
        "{entry}"
    );
    // a second layer in the box user's own settings, made only when there is none
    assert!(t.contains("/work/home/ozbox/.claude/settings.json"));
    assert!(t.contains("[ -e /work/home/ozbox/.claude/settings.json ] ||"));
    // it must not be the only copy a skill could switch off: the root-owned file is not under /work
    assert!(!entry.contains("/work/"));
}
