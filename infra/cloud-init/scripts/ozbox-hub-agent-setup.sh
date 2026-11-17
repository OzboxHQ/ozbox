#!/usr/bin/env bash
# Sets up the hub agent on a worker box (ADR 0042): the systemd unit that runs `ozbox-hubd agent`. Carried in the program and run as
# root by `ozbox-hubd agent-setup <worker-name> <hub-address:port> <hub-identity-fingerprint> [tasks-file]`; safe to run again. The unit is inert
# until /usr/local/bin/ozbox-hubd (a root-owned program) and /etc/ozbox/hub-identity.json (the hub's PUBLIC identity, which the owner
# copies here) exist. Nothing here is a secret: the worker's keys are made and kept by this box's own secrets service.
#
# The agent DIALS OUT to the hub. It binds no port and accepts no connection: its unit allows the loopback and the private ranges
# only (the hub's listener is on one), and nothing else, in either direction.
set -euo pipefail
etc="${OZBOX_ETC:-/etc}"
unit_dir="${OZBOX_SYSTEMD_DIR:-$etc/systemd/system}"
name="${1:-}"
addr="${2:-}"
fp="${3:-}"
# The box's task store (the file `ozbox serve` keeps its runs in): the agent queues each task it is handed there, as a supervised run,
# and the box's own supervisor runs it. Optional; with none, every task is refused by name.
tasks="${4:-}"

if ! [[ "$name" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || ! [[ "$fp" =~ ^[0-9a-f-]{16,200}$ ]]; then
  echo 'usage: ozbox-hubd agent-setup <worker-name> <hub-address:port> <hub-identity-fingerprint> [tasks-file]' >&2
  exit 2
fi
tasks_args=""
tasks_rw=""
if [ -n "$tasks" ]; then
  if ! [[ "$tasks" =~ ^/[A-Za-z0-9._/-]{1,200}$ ]] || [[ "$tasks" == *..* ]] || [[ "$tasks" == */ ]]; then
    echo 'the tasks file must be an absolute path made of letters, digits and . _ - /' >&2
    exit 2
  fi
  tasks_args=" --tasks ${tasks}"
  tasks_rw="ReadWritePaths=$(dirname "$tasks")"
fi
ip_re='^(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})$'
if ! [[ "$addr" =~ $ip_re ]] || [ "${BASH_REMATCH[4]}" -lt 1 ] || [ "${BASH_REMATCH[4]}" -gt 65535 ]; then
  echo 'the hub address must be a loopback, private or tailnet IPv4 address and a port (for example 10.0.1.5:7443)' >&2
  exit 2
fi
if ! id ozbox-hub >/dev/null 2>&1; then
  echo 'the user ozbox-hub does not exist: set up the secrets service first (ozbox-secrets-setup.sh)' >&2
  exit 1
fi

install -d -m 0755 "$unit_dir" "$etc/ozbox"
cat >"$unit_dir/ozbox-hub-agent.service" <<EOF_UNIT
[Unit]
Description=Oz Box hub agent (worker side)
After=ozbox-secrets.service
Wants=ozbox-secrets.service
ConditionPathExists=/usr/local/bin/ozbox-hubd
ConditionPathExists=/etc/ozbox/hub-identity.json

# Runs a root-owned program as the hub's user. It holds no key: it asks this box's secrets service to sign, to open and to keep. It
# refuses Production in three places (the task, a key by name, the service) and deletes every key at once when the hub is lost.
[Service]
Type=simple
User=ozbox-hub
Group=ozbox-hub
SupplementaryGroups=ozbox-supervisor
ExecStart=/usr/local/bin/ozbox-hubd agent --name ${name} --hub-addr ${addr} --hub-identity /etc/ozbox/hub-identity.json --hub-identity-fp ${fp} --secrets-socket /run/ozbox-secrets/supervisor/secrets.sock --hub-secrets-socket /run/ozbox-secrets/hub/hub.sock --fabric-socket /run/ozbox-hub-agent/fabric.sock${tasks_args}
${tasks_rw}
# The conversation fabric (messages, shared memory and skills) is this agent's: it serves it to the box's tool host on a local socket
# in a folder only the agent's group may enter. It still listens on no network port.
RuntimeDirectory=ozbox-hub-agent
RuntimeDirectoryMode=0750
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10
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

if [ -z "${OZBOX_HUB_NO_SYSTEMCTL:-}" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable ozbox-hub-agent.service >/dev/null 2>&1 || true
fi
