#!/usr/bin/env bash
# Sets up the box's task router (ADR 0044): a system user with no login that owns the channel's key, state and audit log, the
# directories the router's three sockets live in, and the systemd unit that runs `ozbox tasks serve` as that user. Run once by
# first-boot configuration; safe to run again. The unit is inert until /usr/local/bin/ozbox (a root-owned program) exists. Nothing
# here is a secret.
#
# Why a user of its own: agents run as the box user, so anything that user can read an agent can read. The channel's signing key,
# its sealing key and its state must not be that. The directory modes below are what decide who may connect to which socket (the
# pattern of the secrets service): the agent socket and the relay socket are for the box user's group, the admin socket is for root.
set -euo pipefail
etc="${OZBOX_ETC:-/etc}"
unit_dir="${OZBOX_SYSTEMD_DIR:-$etc/systemd/system}"
tmpfiles_dir="${OZBOX_TMPFILES_DIR:-$etc/tmpfiles.d}"

if ! id ozbox-mesh >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/ozbox-mesh --no-create-home --shell /usr/sbin/nologin \
    --user-group --comment "Oz Box task router" ozbox-mesh
  passwd --lock ozbox-mesh >/dev/null 2>&1 || true
fi

install -d -m 0755 "$tmpfiles_dir" "$unit_dir"
cat >"$tmpfiles_dir/ozbox-mesh.conf" <<'EOF_TMPFILES'
d /var/lib/ozbox-mesh      0700 ozbox-mesh ozbox-mesh -
d /run/ozbox-mesh          0755 ozbox-mesh ozbox-mesh -
d /run/ozbox-mesh/agent    0750 ozbox-mesh ozbox -
d /run/ozbox-mesh/relay    0750 ozbox-mesh ozbox -
d /run/ozbox-mesh/admin    0700 ozbox-mesh ozbox-mesh -
EOF_TMPFILES

cat >"$unit_dir/ozbox-mesh.service" <<'EOF_UNIT'
[Unit]
Description=Oz Box task router
After=network-online.target
ConditionPathExists=/usr/local/bin/ozbox

# Runs a root-owned program as the router's user. The box user cannot replace that program, read this user's files or attach to it
# (Yama), so the channel's keys, its state and its audit chain are out of an agent's reach; it can only use the agent socket.
[Service]
Type=simple
User=ozbox-mesh
Group=ozbox-mesh
ExecStart=/usr/local/bin/ozbox tasks serve --dir /var/lib/ozbox-mesh --agent-socket /run/ozbox-mesh/agent/agent.sock --relay-socket /run/ozbox-mesh/relay/relay.sock --admin-socket /run/ozbox-mesh/admin/admin.sock
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ozbox-mesh /run/ozbox-mesh
# A socket takes the group of the process that binds it; the router sets it to its directory's group, which takes CAP_CHOWN.
AmbientCapabilities=CAP_CHOWN
CapabilityBoundingSet=CAP_CHOWN
PrivateDevices=true
LimitCORE=0
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF_UNIT

if [ -z "${OZBOX_MESH_NO_SYSTEMCTL:-}" ] && command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create "$tmpfiles_dir/ozbox-mesh.conf" || true
  systemctl daemon-reload || true
  systemctl enable --now ozbox-mesh.service || echo 'the task router did not start; run: systemctl status ozbox-mesh' >&2
fi
