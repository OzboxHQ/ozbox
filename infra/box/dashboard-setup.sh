#!/usr/bin/env bash
# Stages the Oz Box dashboard on this box: its settings and the description of its service, in the box user's home.
# `ozbox dashboard install` sends this text, preceded by the values below as assignments, to `bash -s` over the box's own
# SSH route, and then asks the box's root helper to start it (`ensure-supervisor`, then `ensure-supervisor finish`): the
# dashboard runs as a user of its own from a system unit (ADR 0023), never as the box user. This script never starts it.
# The box user has no sudo (ADR 0011). Nothing here opens a port: the dashboard listens on loopback and its tunnel only
# dials out.
#
# Expected from the preamble: BINARY_SHA256, and one of BOX_PROGRAM (the `ozbox` program this box's image already carries,
# which the person's computer found to match the signed list of the image's release; its hash is checked again here), BINARY_FILE (a program
# the person's computer already downloaded and checked and sent to this box; it is checked again here) or BINARY_URL (this
# box downloads it), then PUBLIC_URL, UNIT_BODY, AUTH_TOML, TUNNEL_ARGS (an array: the
# arguments of `ozbox tunnel setup`, with --token-stdin when a token is sent; empty for no tunnel), TUNNEL_TOKEN (may
# be empty), TUNNEL_APPROVAL (a single-use approval code for the token change on a box whose dashboard has a second factor;
# may be empty; it is never put in an argument or an environment on the box), TOOL (a program the tunnel needs, may be empty) and KEY_FILE (Caddy only: where the tunnel's key lives).
set -euo pipefail

: "${BINARY_SHA256:?}" "${UNIT_BODY:?}" "${AUTH_TOML:?}" "${PUBLIC_URL:?}"
if [ -z "${BOX_PROGRAM:-}" ] && [ -z "${BINARY_FILE:-}" ] && [ -z "${BINARY_URL:-}" ]; then
  echo "dashboard-setup: no program, no program file and no address to download one from was given; nothing was changed" >&2
  exit 1
fi
# /work itself is root's; the box user's home on it is where this lives.
home=/work/home/ozbox/ozbox-dashboard
unit="$HOME/.config/systemd/user/ozbox-dashboard.service"

if [ "$(id -u)" = 0 ]; then
  echo "dashboard-setup: run this as the box user, not as root; nothing was changed" >&2
  exit 1
fi

if [ ! -d /work ] || ! mountpoint -q /work; then
  echo "dashboard-setup: /work is not mounted; nothing was changed" >&2
  exit 1
fi
# Since ADR 0023 the dashboard runs as the supervisor user from a system unit, not as the box user: this script can neither
# replace that program nor its settings (they are not the box user's to change). It stages the new settings and the root helper
# decides what to take (below).
if [ -e /etc/systemd/system/ozbox-dashboard.service ]; then
  # Its program and sign-in settings are not the box user's to change, but a new tunnel token still is to hand over. It goes
  # through the box's root helper, the one route every image has: the helper reads the token itself, asks the secrets service
  # for the approval (which a second factor, once enrolled, must give, and which is bound to THIS token), and stores it. This
  # script does not run the image's `ozbox` program for it: that program is whatever the image carried (a box from before the
  # approval flag ignores `--approval`), while the helper's `replace-tunnel-token` has taken a code since the first image
  # with a second factor.
  if [ "${#TUNNEL_ARGS[@]}" -gt 0 ] && [ -n "${TUNNEL_TOKEN:-}" ]; then
    which="${TUNNEL_ARGS[0]}"
    case "$which" in
      cloudflare|ngrok) ;;
      *) echo "dashboard-setup: only a cloudflare or ngrok tunnel token can be handed to the dashboard of this box; nothing was changed" >&2; exit 1 ;;
    esac
    req=/usr/local/bin/ozbox-admin-request
    [ -x "$req" ] || { echo "dashboard-setup: this box has no admin helper ($req); nothing was changed" >&2; exit 1; }
    tid="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    tokfile="/run/ozbox-admin/requests/$tid.tok"
    trap 'rm -f "$tokfile"' EXIT
    # a private file of this user, made new (never over an existing name or link), that the helper reads once and removes
    ( umask 077; set -o noclobber; printf '%s' "$TUNNEL_TOKEN" >"$tokfile" ) \
      || { echo "dashboard-setup: the box's admin helper is not reachable; nothing was changed" >&2; exit 1; }
    # the code goes on standard input when this box's request program reads it there, else (an older image) as the last word
    if grep -q -- --approval-stdin "$req" 2>/dev/null; then
      if [ -n "${TUNNEL_APPROVAL:-}" ]; then
        answer="$(printf '%s\n' "$TUNNEL_APPROVAL" | "$req" --approval-stdin replace-tunnel-token "$which" "$tid" 2>&1)" && rc=0 || rc=$?
      else
        answer="$("$req" replace-tunnel-token "$which" "$tid" 2>&1)" && rc=0 || rc=$?
      fi
    else
      answer="$("$req" replace-tunnel-token "$which" "$tid" ${TUNNEL_APPROVAL:+"$TUNNEL_APPROVAL"} 2>&1)" && rc=0 || rc=$?
    fi
    if [ "$rc" != 0 ]; then
      echo "dashboard-setup: the box's admin helper did not take the tunnel token: $(printf '%s\n' "$answer" | grep -v '^status=' | tail -n 1 | cut -c1-300)" >&2
      exit 1
    fi
    echo "dashboard-setup: tunnel-token-stored"
  fi
  [ -z "${TUNNEL_TOKEN:-}" ] || echo "dashboard-setup: the public address was not changed: this box's dashboard keeps the address it already has" >&2
  # The sign-in settings and the description of the service are staged here, as on any box, and the person's computer then asks
  # the root helper to take them (`ensure-supervisor expect SHA256`). The helper checks the file is the one the person's computer
  # sent, installs it when the dashboard has no sign-in settings to read (a box whose system disk an upgrade replaced), and keeps
  # the settings it has otherwise. Nothing is started from here, and no program is staged: the supervisor runs the root-owned one.
  install -d -m 0750 "$home" "$home/state"
  printf '%s\n' "$AUTH_TOML" >"$home/auth.toml"
  chmod 0640 "$home/auth.toml"
  mkdir -p "$(dirname "$unit")"
  printf '%s\n' "$UNIT_BODY" >"$unit"
  chmod 0644 "$unit"
  echo "dashboard-setup: supervisor-present"
  exit 0
fi
if [ -n "${TOOL:-}" ] && ! command -v "$TOOL" >/dev/null 2>&1; then
  echo "dashboard-setup: $TOOL is not installed on this box; install it, then run this again" >&2
  exit 1
fi

install -d -m 0750 "$home" "$home/bin" "$home/state"

# The program: kept on /work, so an upgrade of the system disk does not remove it.
if [ -x "$home/bin/ozbox" ] && [ "$(sha256sum "$home/bin/ozbox" | cut -d' ' -f1)" = "$BINARY_SHA256" ]; then
  echo "dashboard-setup: the program is already in place"
elif [ -n "${BOX_PROGRAM:-}" ]; then
  # The program the image carries. Nothing is downloaded, and nothing is taken on trust: it must still be the program whose
  # hash the person's computer verified against the signed manifest.
  if [ ! -f "$BOX_PROGRAM" ]; then
    echo "dashboard-setup: this box has no program at $BOX_PROGRAM; nothing was changed" >&2
    exit 1
  fi
  echo "$BINARY_SHA256  $BOX_PROGRAM" | sha256sum --check --strict -
  install -m 0755 "$BOX_PROGRAM" "$home/bin/ozbox.new"
  mv -f "$home/bin/ozbox.new" "$home/bin/ozbox"
elif [ -n "${BINARY_FILE:-}" ]; then
  # Sent here by the person's computer, which checked it. It is checked again: this box does not take anyone's word.
  if [ ! -f "$BINARY_FILE" ]; then
    echo "dashboard-setup: the program file was not found at $BINARY_FILE; nothing was changed" >&2
    exit 1
  fi
  echo "$BINARY_SHA256  $BINARY_FILE" | sha256sum --check --strict -
  install -m 0755 "$BINARY_FILE" "$home/bin/ozbox.new"
  mv -f "$home/bin/ozbox.new" "$home/bin/ozbox"
  rm -f "$BINARY_FILE"
else
  tmp="$(mktemp -p "$home/bin" .download.XXXXXX)"
  trap 'rm -f "$tmp"' EXIT
  curl --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 --output "$tmp" "$BINARY_URL"
  echo "$BINARY_SHA256  $tmp" | sha256sum --check --strict -
  chmod 0755 "$tmp"
  mv -f "$tmp" "$home/bin/ozbox"
  trap - EXIT
fi
# A program sent from the person's computer is not left lying on /work, whichever branch ran.
[ -z "${BINARY_FILE:-}" ] || rm -f "$BINARY_FILE"

# Settings. The sign-in settings hold no secret. The tunnel settings and its token are saved by the program itself,
# through the box's secrets service (the box user can write a secret there, never read the token back), and arrives on
# standard input rather than in a command line.
printf '%s\n' "$AUTH_TOML" >"$home/auth.toml"
chmod 0640 "$home/auth.toml"
if [ "${#TUNNEL_ARGS[@]}" -gt 0 ]; then
  # an approval code follows the token on its own line (--approval-stdin), so it is in no argument and no environment
  if [ -n "${TUNNEL_APPROVAL:-}" ] && [ -n "${TUNNEL_TOKEN:-}" ]; then
    printf '%s\n%s\n' "$TUNNEL_TOKEN" "$TUNNEL_APPROVAL" | env OZBOX_CONFIG="$home/config.toml" \
      OZBOX_SECRET_STORE=socket OZBOX_SECRET_SOCKET=/run/ozbox-secrets/box/box.sock \
      "$home/bin/ozbox" tunnel setup "${TUNNEL_ARGS[@]}" --approval-stdin
  else
    env OZBOX_CONFIG="$home/config.toml" \
      OZBOX_SECRET_STORE=socket OZBOX_SECRET_SOCKET=/run/ozbox-secrets/box/box.sock \
      "$home/bin/ozbox" tunnel setup "${TUNNEL_ARGS[@]}" <<<"${TUNNEL_TOKEN:-}"
  fi
fi

# An older install kept every secret in one plaintext file in this home, readable by every program the box user runs.
# It is destroyed here (overwritten, then removed) once the secrets service has taken the tunnel token above; keys that
# were set from the dashboard are entered again in Settings.
if [ -f "$home/secrets.json" ]; then
  echo "dashboard-setup: removing the old plaintext secrets file; enter channel and model keys again in the dashboard" >&2
  shred -u -z "$home/secrets.json" 2>/dev/null || rm -f "$home/secrets.json"
fi

# A server of your own (Caddy): the tunnel signs in with a key made for it. The public half is for you to authorise.
if [ -n "${KEY_FILE:-}" ]; then
  if [ ! -f "$KEY_FILE" ]; then
    ssh-keygen -q -t ed25519 -N '' -C ozbox-dashboard -f "$KEY_FILE"
  fi
  echo "dashboard-setup: add this public key to the tunnel account's authorized_keys on your server:"
  cat "$KEY_FILE.pub"
fi

# The description of the service, which the root helper reads (strictly: only the arguments it knows) when it moves the
# dashboard to its own user and system unit. It is not enabled or started here: a dashboard running as the box user, even
# for a minute, is one whose sign-in state and keys every agent on the box can read (ADR 0023).
mkdir -p "$(dirname "$unit")"
printf '%s\n' "$UNIT_BODY" >"$unit"
chmod 0644 "$unit"
echo "dashboard-setup: staged (public address: ${PUBLIC_URL:-unknown}); the root helper starts it as its own user"
