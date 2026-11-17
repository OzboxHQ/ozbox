#!/usr/bin/env bash
# Sets up the hub daemon on a box that is a hub (`main`, ADR 0042): its state directory, the folder its supervisor-facing socket
# lives in, the registrars file, and the two systemd units (a socket unit and the service it starts). Carried in the program and run
# as root by `ozbox-hubd setup <box-id>`; safe to run again. The units are inert until /usr/local/bin/ozbox-hubd (a root-owned
# program) exists. Nothing here is a secret: the hub's keys are made and kept by the secrets service, which this daemon reaches only
# on its own socket (handshake and token tags, nothing that opens or signs a message).
#
# The user `ozbox-hub` is made by ozbox-secrets-setup.sh, because the secrets service's socket folder names its group.
#
# Who may connect is decided by folders, not by the program:
#   /var/lib/ozbox-hub              0700 ozbox-hub          the daemon's state (public keys, sealed messages, counts)
#   /run/ozbox-hub/supervisor       0750 root:ozbox-supervisor   the socket: the supervisor's user, and root
#   /etc/ozbox/hub-registrars.json  0644 root               who may attest a worker; written by root from the laptop's pins
set -euo pipefail
etc="${OZBOX_ETC:-/etc}"
unit_dir="${OZBOX_SYSTEMD_DIR:-$etc/systemd/system}"
tmpfiles_dir="${OZBOX_TMPFILES_DIR:-$etc/tmpfiles.d}"
box_id="${1:-}"
listen="${2:-}"

if ! [[ "$box_id" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
  echo 'usage: ozbox-hubd setup <box-id> [<listen-address:port>] (the box id of this hub: letters, digits, dot, dash, underscore; the address workers dial, loopback or private only)' >&2
  exit 2
fi

# The address the hub listens on for workers (ADR 0042 section 3): loopback, a private range, or the tailnet's. Never a wildcard and
# never a public address: the daemon refuses one too, and the unit's own IP filter allows nothing else. Empty: no network at all.
listen_args=""
families="AF_UNIX"
ip_filter=""
if [ -n "$listen" ]; then
  ip_re='^(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})$'
  if ! [[ "$listen" =~ $ip_re ]] || [ "${BASH_REMATCH[4]}" -lt 1 ] || [ "${BASH_REMATCH[4]}" -gt 65535 ]; then
    echo 'the listen address must be a loopback, private or tailnet IPv4 address and a port (for example 10.0.1.5:7443); a wildcard or a public address is refused' >&2
    exit 2
  fi
  listen_args=" --listen $listen"
  families="AF_UNIX AF_INET"
  # the unit may reach only loopback, the private ranges and the tailnet's: nothing public, in either direction
  ip_filter=$'IPAddressDeny=any\nIPAddressAllow=127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10'
fi

if ! id ozbox-hub >/dev/null 2>&1; then
  echo 'the user ozbox-hub does not exist: set up the secrets service first (ozbox-secrets-setup.sh)' >&2
  exit 1
fi

install -d -m 0755 "$tmpfiles_dir" "$unit_dir" "$etc/ozbox"
cat >"$tmpfiles_dir/ozbox-hub.conf" <<'EOF_TMPFILES'
d /var/lib/ozbox-hub          0700 ozbox-hub ozbox-hub -
d /run/ozbox-hub              0755 root root -
d /run/ozbox-hub/supervisor   0750 root ozbox-supervisor -
EOF_TMPFILES

# no registrar is pinned until the laptop pins one: until then no worker can enrol (the self-test says so)
if [ ! -e "$etc/ozbox/hub-registrars.json" ]; then
  umask 022
  printf '{"registrars":[]}\n' >"$etc/ozbox/hub-registrars.json"
fi

# systemd binds the socket as root, in a folder root owns, and hands it to the daemon: the daemon's own user cannot change who
# may connect (the pattern of the dashboard's socket, ADR 0040 decision 3). A restart of the daemon queues connections.
cat >"$unit_dir/ozbox-hubd.socket" <<'EOF_SOCKET'
[Unit]
Description=Oz Box hub daemon socket
ConditionPathExists=/usr/local/bin/ozbox-hubd

[Socket]
ListenStream=/run/ozbox-hub/supervisor/hubd.sock
FileDescriptorName=ozbox-hubd.socket
SocketUser=root
SocketGroup=ozbox-supervisor
SocketMode=0660
RemoveOnStop=true

[Install]
WantedBy=sockets.target
EOF_SOCKET

cat >"$unit_dir/ozbox-hubd.service" <<EOF_UNIT
[Unit]
Description=Oz Box hub daemon
Requires=ozbox-hubd.socket
After=ozbox-hubd.socket ozbox-secrets.service
Wants=ozbox-secrets.service
ConditionPathExists=/usr/local/bin/ozbox-hubd

# Runs a root-owned program as the hub's user. The box user cannot replace that program, read this user's files or attach to it
# (Yama). The daemon holds no private key; it verifies, spools and enrols.
[Service]
Type=simple
User=ozbox-hub
Group=ozbox-hub
Sockets=ozbox-hubd.socket
ExecStart=/usr/local/bin/ozbox-hubd serve --dir /var/lib/ozbox-hub --socket /run/ozbox-hub/supervisor/hubd.sock --secrets-socket /run/ozbox-secrets/hub/hub.sock --registrars /etc/ozbox/hub-registrars.json --box-id ${box_id}${listen_args}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ozbox-hub
CapabilityBoundingSet=
# Unix sockets only unless a listen address was given at setup (then one IPv4 listener on a loopback, private or tailnet address,
# and an IP filter that denies everything else): workers dial out to the hub, the hub opens no connection of its own (ADR 0005)
RestrictAddressFamilies=${families}
${ip_filter}
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

if [ -z "${OZBOX_HUB_NO_SYSTEMCTL:-}" ] && command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create "$tmpfiles_dir/ozbox-hub.conf" || true
  systemctl daemon-reload || true
  systemctl enable --now ozbox-hubd.socket || echo 'the hub daemon socket did not start; run: systemctl status ozbox-hubd.socket' >&2
  systemctl enable ozbox-hubd.service >/dev/null 2>&1 || true
fi
