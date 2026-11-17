#!/usr/bin/env bash
# Sets up the box's secrets identity (ADR 0018): the secrets user, its private directories, the ptrace rule, and the two
# systemd units that run as that user. Run once by first-boot configuration; safe to run again. The units are inert until
# /usr/local/bin/ozbox (a root-owned program) exists. Nothing here is a secret.
set -euo pipefail
# Arguments: box name, KMS key id, KMS region, pinned approval key (the last three may be empty). Not secrets.
install -d -m 0755 /etc/ozbox
printf 'OZBOX_SECRET_SCOPE=%s\nOZBOX_KMS_KEY_ID=%s\nOZBOX_KMS_REGION=%s\n' "${1:-local}" "${2:-}" "${3:-}" >/etc/ozbox/secrets.env
# The box's first approver: the public half of the key on the computer that made the box (ozbox create). Written by root
# from the first-boot configuration, which nothing on the box can change, so the first approver never comes from inside
# the box. The secrets service enrols it once at start. A public key, so world readable is fine; only root may write it.
pinfile="${OZBOX_PIN_FILE:-/etc/ozbox/approval-keys}"
if printf '%s' "${4:-}" | grep -Eq '^[a-z2-7]{52}$'; then
  ( umask 022; printf 'laptop %s\n' "$4" >"$pinfile.tmp" )
  chmod 0644 "$pinfile.tmp"
  mv -f "$pinfile.tmp" "$pinfile"
fi
# No KMS key: keep the key-encryption key in a file only the secrets user can read, so a fresh box's store starts (a TPM, when
# the machine has one, is used first). `ozbox secrets status` says which protects the store.
[ -n "${2:-}" ] || printf 'OZBOX_SECRET_ALLOW_FILE_KEK=1\n' >>/etc/ozbox/secrets.env

if ! id ozbox-secrets >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/ozbox-secrets --no-create-home --shell /usr/sbin/nologin \
    --user-group --comment "Oz Box secrets" ozbox-secrets
  passwd --lock ozbox-secrets >/dev/null 2>&1 || true
fi

# The dashboard (the supervisor) has a user of its own, so no agent shares a uid with the process that issues run tokens
# and asks for approvals (ADR 0023). The user is made here so the socket directory below can name its group; the move of
# the dashboard itself is ozbox-supervisor-setup.sh.
if ! id ozbox-supervisor >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /work/ozbox-supervisor/home --no-create-home --shell /usr/sbin/nologin \
    --comment "Oz Box supervisor" ozbox-supervisor
  passwd --lock ozbox-supervisor >/dev/null 2>&1 || true
fi

# The hub daemon (ADR 0042) has a user of its own too, made here for the same reason: the socket directory below names its
# group. The daemon itself is set up only on a box that is a hub (`ozbox-hub-setup.sh`); elsewhere the user owns nothing.
if ! id ozbox-hub >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/ozbox-hub --no-create-home --shell /usr/sbin/nologin \
    --comment "Oz Box hub daemon" ozbox-hub
  passwd --lock ozbox-hub >/dev/null 2>&1 || true
fi

cat >/etc/sysctl.d/10-ozbox-yama.conf <<'EOF_SYSCTL'
# the box user cannot attach to processes it did not start
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
EOF_SYSCTL

cat >/etc/tmpfiles.d/ozbox-secrets.conf <<'EOF_TMPFILES'
d /var/lib/ozbox-secrets      0700 ozbox-secrets ozbox-secrets -
d /run/ozbox-secrets          0755 ozbox-secrets ozbox-secrets -
d /run/ozbox-secrets/box      0750 ozbox-secrets ozbox -
d /run/ozbox-secrets/broker   0750 ozbox-secrets ozbox -
d /run/ozbox-secrets/admin    0700 ozbox-secrets ozbox-secrets -
d /run/ozbox-secrets/import   0750 ozbox-secrets ozbox -
d /run/ozbox-secrets/resolver 0700 ozbox-secrets ozbox-secrets -
d /run/ozbox-secrets/supervisor 0750 ozbox-secrets ozbox-supervisor -
d /run/ozbox-secrets/hub      0750 ozbox-secrets ozbox-hub -
d /run/ozbox-secrets/memory   0700 ozbox-secrets ozbox-secrets -
d /run/ozbox-runner           0750 root ozbox -
d /run/ozbox-runner/env       0700 root root -
EOF_TMPFILES

cat >/etc/systemd/system/ozbox-secrets.service <<'EOF_SECRETS'
[Unit]
Description=Oz Box secrets service
After=network-online.target
Wants=network-online.target
ConditionPathExists=/usr/local/bin/ozbox

# Runs a root-owned program as the secrets user. The box user cannot replace that program, read this user's files or
# attach to it (Yama), so the key-encryption key and the opened secrets are out of its reach.
[Service]
Type=simple
User=ozbox-secrets
Group=ozbox-secrets
Environment=OZBOX_SECRET_FILE=/var/lib/ozbox-secrets/secrets.json
EnvironmentFile=/etc/ozbox/secrets.env
# A box that keeps its store's key in a file escrows it in its own vault and fetches it back after a system-disk
# replacement: the vault's address and token, from root-only and root-written files (the box user never holds the token).
EnvironmentFile=-/etc/ozbox/box-secrets.env
EnvironmentFile=-/etc/ozbox/bao.env
# Hosts the credential broker and runs restic; the four capabilities are what reading and restoring /work takes.
ExecStart=/usr/local/bin/ozbox secrets serve --box-socket /run/ozbox-secrets/box/box.sock --broker-socket /run/ozbox-secrets/broker/broker.sock --admin-socket /run/ozbox-secrets/admin/admin.sock --import-socket /run/ozbox-secrets/import/import.sock --ingress-socket /run/ozbox-secrets/ingress/ingress.sock --runner-socket /run/ozbox-secrets/resolver/resolver.sock --supervisor-socket /run/ozbox-secrets/supervisor/supervisor.sock --hub-socket /run/ozbox-secrets/hub/hub.sock --memory-store /run/ozbox-secrets/memory/box-secrets.json --audit-dir /work/ozbox-audit --audit-anchor-dir /work/ozbox-secrets-private/audit-anchor --persist-dir /work/ozbox-secrets-private
Restart=on-failure
RestartSec=5
# Exit 78 means "not configured" (no key for the store, say): it is written where the box user can read it
# (`ozbox secrets status`) and not retried every few seconds.
RestartPreventExitStatus=78
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ozbox-secrets /run/ozbox-secrets /work
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER
PrivateDevices=false
LimitCORE=0
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF_SECRETS

# Commands that need a project's secrets are started here, as root, one process per request: the box user may connect to
# the socket, the process starts the command as the project's runner user (see the CLI's runner module).
cat >/etc/systemd/system/ozbox-runner.socket <<'EOF_RUNNER_SOCKET'
[Unit]
Description=Oz Box command launcher
ConditionPathExists=/usr/local/bin/ozbox
[Socket]
ListenStream=/run/ozbox-runner/launch.sock
SocketMode=0660
SocketUser=root
SocketGroup=ozbox
Accept=yes
MaxConnections=8
[Install]
WantedBy=sockets.target
EOF_RUNNER_SOCKET
cat >/etc/systemd/system/ozbox-runner@.service <<'EOF_RUNNER'
[Unit]
Description=Oz Box command launcher
[Service]
ExecStart=/usr/local/bin/ozbox secrets run-as
StandardInput=socket
StandardOutput=socket
LimitCORE=0
PrivateTmp=true
EOF_RUNNER

# The box's own secrets (Staging keys for this box's role) are pulled from the provider's secret store into the service's
# memory: at boot, then every 15 minutes, as the secrets user. A root step first writes the settings from the instance tags
# (box_config); with no declaration the loader does nothing.
cat >/etc/systemd/system/ozbox-box-secrets.service <<'EOF_BOXSECRETS'
[Unit]
Description=Oz Box: load this box's own secrets into the secrets service's memory
After=network-online.target ozbox-secrets.service
Wants=network-online.target
ConditionPathExists=/usr/local/bin/ozbox

[Service]
Type=oneshot
User=ozbox-secrets
Group=ozbox-secrets
# the store's key file, when the box keeps one, is escrowed in the vault from here (see the CLI's secrets_escrow)
Environment=OZBOX_SECRET_FILE=/var/lib/ozbox-secrets/secrets.json
EnvironmentFile=/etc/ozbox/secrets.env
EnvironmentFile=-/etc/ozbox/box-secrets.env
# the vault token (root-only, placed by `ozbox admin <box> -- place-bao-token`); only systemd reads it, then the loader's environment holds it
EnvironmentFile=-/etc/ozbox/bao.env
ExecStartPre=+/usr/local/bin/ozbox secrets configure-box
ExecStart=/usr/local/bin/ozbox secrets load-box
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
LimitCORE=0
LockPersonality=true
EOF_BOXSECRETS
cat >/etc/systemd/system/ozbox-box-secrets.timer <<'EOF_BOXSECRETS_TIMER'
[Unit]
Description=Oz Box: refresh this box's own secrets
[Timer]
OnBootSec=30s
OnUnitActiveSec=15min
Persistent=false
[Install]
WantedBy=timers.target
EOF_BOXSECRETS_TIMER

# The commit barrier's hooks are put in every repository under /work, and put back when one is removed.
cat >/etc/systemd/system/ozbox-guard-install.service <<'EOF_GUARD'
[Unit]
Description=Oz Box: keep the commit barrier installed in every repository under /work
ConditionPathExists=/usr/local/bin/ozbox
RequiresMountsFor=/work
[Service]
Type=oneshot
User=ozbox
Group=ozbox
ExecStart=/usr/local/bin/ozbox guard install --root /work
NoNewPrivileges=true
PrivateTmp=true
EOF_GUARD
cat >/etc/systemd/system/ozbox-guard-install.timer <<'EOF_GUARD_TIMER'
[Unit]
Description=Oz Box: keep the commit barrier installed
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF_GUARD_TIMER

cat >/etc/systemd/system/ozbox-cloudflared.service <<'EOF_CLOUDFLARED'
[Unit]
Description=Oz Box dashboard tunnel (cloudflared as the secrets user)
After=network-online.target ozbox-secrets.service
Wants=network-online.target
ConditionPathExists=/usr/local/bin/ozbox
ConditionPathExists=/var/lib/ozbox-secrets/secrets.json

# The tunnel token is opened by this user and goes to cloudflared's environment only; the box user cannot read it
# from a file, from the service socket or from /proc.
[Service]
Type=simple
User=ozbox-secrets
Group=ozbox-secrets
Environment=OZBOX_SECRET_STORE=file
Environment=OZBOX_SECRET_FILE=/var/lib/ozbox-secrets/secrets.json
EnvironmentFile=/etc/ozbox/secrets.env
ExecStart=/usr/local/bin/ozbox secrets exec --env TUNNEL_TOKEN=tunnel-token-cloudflare -- /usr/bin/cloudflared tunnel --no-autoupdate run
Restart=always
RestartSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ozbox-secrets
LimitCORE=0
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF_CLOUDFLARED

cat >/etc/systemd/system/ozbox-code-connector.service <<'EOF_CODE_CONNECTOR'
[Unit]
Description=Oz Box web IDE tunnel connector (cloudflared as the secrets user)
After=network-online.target ozbox-secrets.service
Wants=network-online.target
ConditionPathExists=/usr/local/bin/ozbox

[Service]
Type=simple
User=ozbox-secrets
Group=ozbox-secrets
Environment=OZBOX_SECRET_STORE=file
Environment=OZBOX_SECRET_FILE=/var/lib/ozbox-secrets/secrets.json
EnvironmentFile=/etc/ozbox/secrets.env
ExecStart=/usr/local/bin/ozbox secrets exec --env TUNNEL_TOKEN=tunnel-token-ide -- /usr/bin/cloudflared tunnel --no-autoupdate run
Restart=on-failure
RestartSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ozbox-secrets
LimitCORE=0
LockPersonality=true

# Without this `systemctl enable` has nothing to enable, and the connector would not come back after a reboot or an upgrade.
[Install]
WantedBy=multi-user.target
EOF_CODE_CONNECTOR

systemd-tmpfiles --create /etc/tmpfiles.d/ozbox-secrets.conf
sysctl --system >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now ozbox-secrets.service ozbox-cloudflared.service ozbox-runner.socket || true
systemctl enable --now ozbox-box-secrets.timer ozbox-guard-install.timer || true
# an old plaintext tunnel token file, if the /work disk came from an older box
/usr/local/sbin/ozbox-admin.sh --run migrate-legacy-tunnel >/dev/null 2>&1 || true
