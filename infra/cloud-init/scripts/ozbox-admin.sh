#!/usr/bin/env bash
# The narrow root path on a box. The box user has no sudo (ADR 0005 keeps every inbound port shut; this keeps root shut
# too). A person who must fix a box asks for one of a short, fixed list of actions; root does exactly that and nothing
# else. There is no way through here to a shell, an arbitrary path or an arbitrary command.
#
#   reown [--from-uid N] [--from-gid N]   put the box user's files on /work back under the box user
#   reinstall-ozboxd [SHA256]             install ozboxd again from the signed release, then restart it
#   restart-services [NAME ...]           restart ozboxd and its helpers (only the names listed below)
#   collect-logs                          the recent log lines of the box daemon and its services (the tool installer too), the
#                                         loaded security modules and the kernel's denial lines, redacted and bounded in size
#   replace-tunnel-token WHICH ID [CODE]  store a tunnel token (cloudflare, ngrok, ide) read once from requests/ID.tok; a code
#                                         approves THAT token only (its digest is signed into the code)
#   clear-tunnel-token WHICH              remove one (and stop the web IDE connector)
#   ensure-runner PROJECT                 make the project's runner user and its home (commands run as that user)
#   migrate-legacy-tunnel                 move an old ~/.config/ozbox/cloudflared.env token into the secrets store, destroy
#                                         the file and start the connector the new way (also run by --run at boot/upgrade)
#   ensure-supervisor [finish|rollback|expect SHA256]
#                                         give the dashboard a user of its own (ADR 0023); finish destroys the box user's old
#                                         copies; expect refuses unless the staged sign-in settings have that sha256
#   configure-box-secrets                 read this box's secrets declaration (instance tags) again and write the loader's settings
#   recover-secrets challenge | NONCE EXPIRES SIGNATURE
#                                         start a new secrets store on a box whose store can no longer be opened (system disk
#                                         replaced, key not escrowed): only when the secrets service itself recorded that, and
#                                         only with the signature of the key pinned when the box was made over a one-time
#                                         challenge (`ozbox admin <box> -- recover-secrets` does both steps); the old store is
#                                         renamed aside
#   host-guard egress|patch|metadata|memory|helper ...  the box's own guards: the egress list and the restart-after-patches rule (ADR
#                                         0034, 0035; a change that loosens one needs a fresh approval, checked by the program),
#                                         the metadata guard (ADR 0029) and the memory guard (ADR 0045: swap in RAM only,
#                                         protected scores, soft limits; it only tightens and restarts nothing) and the helper's own
#                                         refresh from the installed release (ADR 0045)
#   write-box-secrets | clear-box-secrets | place-bao-token   the box's own secrets declaration and vault token where the
#                                         provider has no instance tags (see ozbox-box-secrets.sh)
#   enable-linger                         let the box user's own services (IDE, desktop, dashboard) start at boot and
#                                         keep running after the last login ends (loginctl enable-linger ozbox)
#
# How a request gets here: `ozbox admin` (or the box user over SSH) runs /usr/local/bin/ozbox-admin-request, which drops
# one small file into /run/ozbox-admin/requests (sticky, group ozbox). A systemd path unit starts this script as root;
# it takes each request, checks the owner (the box user) and the action against the list, runs it, writes the answer to
# /run/ozbox-admin/results, and records who asked for what in the journal and /var/log/ozbox-admin.log (action words and
# counts, never file names or contents).
# Environment (for tests): OZBOX_ADMIN_DIR, OZBOX_ADMIN_LOG, OZBOX_REOWN, OZBOX_INSTALL_AGENT, OZBOX_SYSTEMCTL,
# OZBOX_JOURNALCTL, OZBOX_LOGINCTL, OZBOX_REQUESTER_UID, OZBOX_USER_MANAGER.
set -euo pipefail

helper_rev=1
dir="${OZBOX_ADMIN_DIR:-/run/ozbox-admin}"
log="${OZBOX_ADMIN_LOG:-/var/log/ozbox-admin.log}"
reown="${OZBOX_REOWN:-/usr/local/sbin/ozbox-reown.sh}"
install_agent="${OZBOX_INSTALL_AGENT:-/usr/local/sbin/ozbox-install-agent.sh}"
user_manager="${OZBOX_USER_MANAGER:-/usr/local/sbin/ozbox-user-manager.sh}"
systemctl_bin="${OZBOX_SYSTEMCTL:-systemctl}"
journalctl_bin="${OZBOX_JOURNALCTL:-journalctl}"
loginctl_bin="${OZBOX_LOGINCTL:-loginctl}"
allowed_units="ozboxd ozbox-tools.path ozbox-backup.path ozbox-growfs.timer ozbox-dashboard ozbox-browser.socket"
max_out=200000
useradd_bin="${OZBOX_USERADD:-useradd}"
install_bin="${OZBOX_INSTALL:-install}"
id_bin="${OZBOX_ID:-id}"
ozbox_bin="${OZBOX_BIN:-/usr/local/bin/ozbox}"
admin_socket="${OZBOX_SECRETS_ADMIN_SOCKET:-/run/ozbox-secrets/admin/admin.sock}"

# Every action, and whether it needs an approval the box user cannot make. An action that is not listed here is refused
# before anything runs. The ozbox program keeps the same list (`HELPER_ACTIONS` in its admin command) and a test compares
# the two, so a new action must say which it is.
#   ungated  the action cannot let the box do more than its owner set:
#              reown (the box user's own files only, never a system or service id), reinstall-ozboxd (the signed release
#              only), restart-services (a fixed list), collect-logs (redacted, bounded), ensure-runner (a user with less, and access only to the folder, tools and browsers of the stored, approved declaration),
#              migrate-legacy-tunnel (moves a token INTO the store), ensure-supervisor (moves the dashboard to a user of its
#              own; a rollback returns only what the box user could already read before finish), configure-box-secrets
#              (reads tags the box cannot change), enable-linger (the box user's own services)
#   gated    the action needs an approval the box user cannot make, and the program checks it before anything changes:
#              replace-tunnel-token, clear-tunnel-token (scope tunnel-token), host-guard (a change that loosens a guard),
#              write-box-secrets, clear-box-secrets, place-bao-token (scope box-secrets), recover-secrets (the pinned key's
#              signature: the secrets service is down, so it cannot spend an approval)
action_gates="
reown ungated
reinstall-ozboxd ungated
restart-services ungated
collect-logs ungated
replace-tunnel-token gated
clear-tunnel-token gated
ensure-runner ungated
migrate-legacy-tunnel ungated
ensure-supervisor ungated
configure-box-secrets ungated
recover-secrets gated
host-guard gated
write-box-secrets gated
clear-box-secrets gated
place-bao-token gated
enable-linger ungated
"
gate_of() { printf '%s\n' "$action_gates" | awk -v a="$1" '$1 == a { print $2; f = 1 } END { exit !f }'; }
action_names() { printf '%s\n' "$action_gates" | awk 'NF { printf "%s%s", s, $1; s = ", " }'; }

record() {
  local line
  line="$(date -u +%Y-%m-%dT%H:%M:%SZ) request=$1 uid=$2 action=$3 result=$4"
  printf '%s\n' "$line" >>"$log" 2>/dev/null || true
  logger -t ozbox-admin "$line" 2>/dev/null || true
}

is_number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# Log lines reach the box user (collect-logs), so anything shaped like a credential is blanked first: known prefixes, a
# bearer token, `token=…` / `secret: …` / `password …`, and a JSON- or quote-wrapped value under a key that names one.
redact() {
  sed -E \
    -e 's#([Bb]earer[[:space:]]+)[A-Za-z0-9_.~+/=-]+#\1[redacted]#g' \
    -e 's#("[A-Za-z_-]*([Tt]oken|[Ss]ecret|[Kk]ey|[Pp]assword|[Cc]redential)[A-Za-z_-]*"[[:space:]]*:[[:space:]]*")[^"]*#\1[redacted]#g' \
    -e 's#(ozrt_|hvs\.|sk-|AKIA|ASIA|eyJ|([Tt]oken|TOKEN|[Ss]ecret|SECRET|[Pp]assword|PASSWORD)[=: ]+)[A-Za-z0-9_.+/=-]+#\1[redacted]#g'
}

# run_action ACTION ARGS...: prints what a person reads; returns non-zero when it failed.
run_action() {
  local action="$1"; shift
  gate_of "$action" >/dev/null || { echo "unknown action; the actions are: $(action_names)"; return 2; }
  case "$action" in
    reown)
      local -a a=(--force)
      while [ $# -gt 0 ]; do
        case "$1" in
          --from-uid|--from-gid)
            is_number "${2:-}" || { echo "$1 needs a number"; return 2; }
            # a system id is never an old box user (the script also refuses the box's own service accounts by name)
            if [ "$2" -lt 1000 ] || [ "$2" = 65534 ]; then echo "$1 must be an id of 1000 or more (not a system account)"; return 2; fi
            a+=("$1" "$2"); shift 2 ;;
          *) echo "reown takes only --from-uid and --from-gid"; return 2 ;;
        esac
      done
      "$reown" "${a[@]}" 2>&1 ;;
    reinstall-ozboxd)
      local -a a=(--force)
      if [ $# -gt 1 ]; then echo "reinstall-ozboxd takes at most one SHA-256"; return 2; fi
      if [ $# = 1 ]; then
        printf '%s' "$1" | grep -Eq '^[0-9a-f]{64}$' || { echo "the SHA-256 must be 64 hex digits"; return 2; }
        a+=(--sha256 "$1")
      fi
      # ORDER MATTERS (ADR 0043): the new `ozbox` program is installed FIRST, and only then does it run the socket step. The old
      # program does not know what the new unit and settings need, so running the step before the install would bring a box
      # up to date with the OLD program's idea of it. If the install failed, the step is skipped and says so.
      if "$install_agent" "${a[@]}" 2>&1; then
        # a box made before the dashboard's own socket to the daemon gets its socket unit here (it restarts the daemon when it
        # adds one; the restart below is then a second, harmless one); an older program that does not know the flag changes nothing
        "$ozbox_bin" secrets supervisor-setup --socket-only 2>&1 || true
      else
        # a failed install is reported as failed, and nothing is restarted onto a half-installed program
        echo "the program was not installed, so the dashboard's socket step was skipped and ozboxd was not restarted"
        return 1
      fi
      "$systemctl_bin" daemon-reload 2>&1 || true
      # a daemon that did not restart is reported as failed, after the rest still ran
      local rc=0
      "$systemctl_bin" restart ozboxd 2>&1 && echo "ozboxd restarted" || { echo "ozboxd did not restart"; rc=1; }
      # the helper itself is replaced by the program's own, only when that one is a strictly newer revision (helper_rev at the
      # top; never a file or an argument, never an older one), so a helper addition reaches a box whose installed program
      # already carries it; a program that is older than the helper changes nothing here
      "$ozbox_bin" host-guard helper refresh 2>&1 || true
      # a box made before the metadata guard gets it here (only root and the machine's own services reach the metadata service)
      "$ozbox_bin" host-guard metadata install 2>&1 || true
      # and the memory guard (swap in RAM, protected scores, soft limits): it only tightens and restarts no unit
      "$ozbox_bin" host-guard memory install 2>&1 || true
      run_action migrate-legacy-tunnel 2>&1 || true
      return "$rc" ;;
    restart-services)
      local u ok
      local -a todo=("$@")
      [ "${#todo[@]}" -gt 0 ] || read -r -a todo <<<"$allowed_units"
      for u in "${todo[@]}"; do
        ok=0
        for k in $allowed_units; do [ "$u" = "$k" ] && ok=1; done
        [ "$ok" = 1 ] || { echo "$u is not a service this action may restart (allowed: $allowed_units)"; return 2; }
      done
      for u in "${todo[@]}"; do
        "$systemctl_bin" restart "$u" 2>&1 && echo "restarted $u"
      done ;;
    collect-logs)
      [ $# = 0 ] || { echo "collect-logs takes no arguments"; return 2; }
      {
        echo "== ozboxd (last 300 lines) =="
        "$journalctl_bin" -u ozboxd -n 300 --no-pager 2>&1 || true
        for u in ozbox-secrets ozbox-dashboard ozbox-box-secrets ozbox-guard-install 'ozbox-runner@*' ozbox-cloudflared ozbox-code-connector ozbox-tools.service ozbox-tools.path ozbox-browser.socket 'ozbox-browser@*'; do
          echo "== $u =="
          "$journalctl_bin" -u "$u" -n 60 --no-pager 2>&1 || true
        done
        echo "== security modules loaded =="
        cat "${OZBOX_LSM_LIST:-/sys/kernel/security/lsm}" 2>&1 || true
        echo "== kernel and audit denials (last 50) =="
        "$journalctl_bin" -k -n 50 --no-pager -g 'apparmor="DENIED"|type=1326|type=1400|seccomp|capability' 2>&1 | head -n 50 || true
        echo "== package refresh (apt-daily, unattended-upgrades) =="
        "$journalctl_bin" -u apt-daily.service -u apt-daily-upgrade.service -n 30 --no-pager 2>&1 || true
        echo "== ozbox-admin (last 100 lines) =="
        tail -n 100 "$log" 2>&1 || true
        echo "== first-boot configuration (last 100 lines) =="
        tail -n 100 /var/log/cloud-init-output.log 2>&1 || true
      } | redact | tail -c "$max_out" ;;
    replace-tunnel-token)
      local which="${1:-}" tid="${2:-}" tok uidr first via
      [ $# = 2 ] || [ $# = 3 ] || { echo "replace-tunnel-token takes a name, an id and, once the dashboard has a second factor, an approval code"; return 2; }
      printf '%s' "$which" | grep -Eq '^(cloudflare|ngrok|ide)$' || { echo "the tunnel must be cloudflare, ngrok or ide"; return 2; }
      printf '%s' "$tid" | grep -Eq '^[0-9a-f]{16}$' || { echo "the token id must be 16 hex digits"; return 2; }
      tok="$dir/requests/$tid.tok"
      uidr="${OZBOX_REQUESTER_UID:-$(id -u ozbox)}"
      # The token is read FIRST, into this process's own memory, and the approval is then checked against THAT token (its
      # digest is signed into the code), so the code approves this token and no other: the box user owns the file and can
      # rewrite it at any moment, but cannot change the bytes already read here. The file is opened once without following a
      # link, checked and read through that one descriptor, and removed whatever happens.
      if ! first="$("$ozbox_bin" host-guard take-file --dir "$dir/requests" --id "$tid" --owner "$uidr" --max 4096 2>/dev/null)"; then
        rm -f "$tok"; echo "the token file was not found, or is not the box user's"; return 2
      fi
      if ! printf '%s' "$first" | grep -Eq '^[A-Za-z0-9+/=_.-]+$' || [ "${#first}" -lt 20 ] || [ "${#first}" -gt 2048 ]; then echo "the token has an unexpected shape"; return 2; fi
      # Once a second factor is enrolled the secrets service wants a fresh approval, bound to this token, for this change; before
      # that it allows it and records "bootstrap". The code and the token go to the program on standard input, never in an
      # argument. The service spends the code; a refusal ends here and nothing is stored.
      if ! via="$(printf '%s\n%s\n' "${3:-}" "$first" | "$ozbox_bin" secrets gate --scope tunnel-token --project "$which" --bind-token-stdin --socket "$admin_socket" 2>&1)"; then
        echo "$via"; return 3
      fi
      if printf '%s\n' "$first" | "$ozbox_bin" secrets put --name "tunnel-token-$which" --socket "$admin_socket" 2>&1; then
        if [ "$which" = ide ]; then "$systemctl_bin" enable --now ozbox-code-connector.service 2>&1 || true; "$systemctl_bin" restart ozbox-code-connector.service 2>&1 || true; fi
        [ "$which" = ide ] || "$systemctl_bin" restart ozbox-cloudflared.service 2>&1 || true
        echo "tunnel token for $which stored"
      else
        echo "the secrets service did not take the token"; return 1
      fi ;;
    clear-tunnel-token)
      local via
      [ $# = 1 ] || [ $# = 2 ] || { echo "clear-tunnel-token takes a name and, once the dashboard has a second factor, an approval code"; return 2; }
      if ! via="$(printf '%s\n' "${2:-}" | "$ozbox_bin" secrets gate --scope tunnel-token --project "$1" --socket "$admin_socket" 2>&1)"; then
        echo "$via"; return 3
      fi
      printf '%s' "$1" | grep -Eq '^(cloudflare|ngrok|ide)$' || { echo "the tunnel must be cloudflare, ngrok or ide"; return 2; }
      if [ "$1" = ide ]; then "$systemctl_bin" disable --now ozbox-code-connector.service 2>&1 || true; fi
      "$ozbox_bin" secrets remove --name "tunnel-token-$1" --socket "$admin_socket" 2>&1 && echo "tunnel token for $1 removed" ;;
    ensure-runner)
      [ $# = 1 ] || { echo "ensure-runner takes a project name"; return 2; }
      printf '%s' "$1" | grep -Eq '^[a-z0-9][a-z0-9-]{0,19}$' || { echo "the project name must be 1 to 20 lowercase letters, digits or dashes"; return 2; }
      local ru="ozbox-run-$1" setup_out
      if ! "$id_bin" "$ru" >/dev/null 2>&1; then
        # no shared group: the runner reads nothing of the box user's. What it may read is set below, from the stored declaration.
        "$useradd_bin" --system --user-group --no-create-home --home-dir "/var/lib/ozbox-run/$1" \
          --shell /usr/sbin/nologin --comment "Oz Box runner $1" "$ru" 2>&1 || { echo "the runner user could not be made"; return 1; }
      elif "$id_bin" -nG "$ru" 2>/dev/null | tr ' ' '\n' | grep -qx ozbox; then
        # a runner made by an earlier image was in the box user's group, which let it read the box user's whole home
        "${OZBOX_GPASSWD:-gpasswd}" -d "$ru" ozbox >/dev/null 2>&1 || { echo "the runner could not be taken out of the box user's group"; return 1; }
      fi
      "$install_bin" -d -m 0700 -o "$ru" -g "$ru" "/var/lib/ozbox-run/$1" 2>&1
      # The folder, tools and browsers come from the STORED, approved declaration (the program reads it from the secrets service);
      # nothing in this request names a path.
      if ! setup_out="$("$ozbox_bin" secrets runner-setup "$1" 2>&1)"; then echo "$setup_out"; return 1; fi
      echo "runner $ru is ready"
      [ -z "$setup_out" ] || printf '%s\n' "$setup_out" ;;
    migrate-legacy-tunnel)
      [ $# = 0 ] || { echo "migrate-legacy-tunnel takes no arguments"; return 2; }
      local bh lf lt
      bh="${OZBOX_BOX_HOME:-$(getent passwd ozbox | cut -d: -f6)}"; lf="$bh/.config/ozbox/cloudflared.env"
      if [ -z "$bh" ] || [ -L "$lf" ] || [ ! -f "$lf" ]; then echo "no old tunnel token file"; return 0; fi
      lt="$(sed -n 's/^TUNNEL_TOKEN=//p' "$lf" | head -n 1)"
      if ! printf '%s' "$lt" | grep -Eq '^[A-Za-z0-9+/=_.-]+$' || [ "${#lt}" -lt 20 ] || [ "${#lt}" -gt 2048 ]; then echo "the old token file has an unexpected shape; left alone"; return 1; fi
      if printf '%s\n' "$lt" | "$ozbox_bin" secrets put --name tunnel-token-ide --socket "$admin_socket" >/dev/null 2>&1; then
        "${OZBOX_SHRED:-shred}" -u "$lf" 2>/dev/null || rm -f "$lf"
        rm -f "$bh/.config/systemd/user/ozbox-cloudflared.service"
        "${OZBOX_RUNUSER:-runuser}" -u ozbox -- env "XDG_RUNTIME_DIR=/run/user/$(id -u ozbox)" systemctl --user disable --now ozbox-cloudflared.service >/dev/null 2>&1 || true
        "$systemctl_bin" enable --now ozbox-code-connector.service 2>&1 || true
        echo "the old tunnel token moved into the secrets store and its file was destroyed"
      else echo "the secrets service did not take the old token; the file is left in place"; return 1; fi ;;
    ensure-supervisor)
      case "${1:-}" in
        '') "$ozbox_bin" secrets supervisor-setup 2>&1 ;;
        finish|rollback) "$ozbox_bin" secrets supervisor-setup "--$1" 2>&1 ;;
        expect)
          printf '%s' "${2:-}" | grep -Eq '^[0-9a-f]{64}$' || { echo "ensure-supervisor expect takes the sha256 of the sign-in settings"; return 2; }
          "$ozbox_bin" secrets supervisor-setup --expect-auth "$2" 2>&1 ;;
        *) echo "ensure-supervisor takes finish, rollback, or expect SHA256"; return 2 ;;
      esac ;;
    configure-box-secrets)
      [ $# = 0 ] || { echo "configure-box-secrets takes no arguments"; return 2; }
      "$ozbox_bin" secrets configure-box 2>&1 ;;
    host-guard)
      # the guards only; the program's own token reader (take-file) is for this helper, never for a request
      case "${1:-}" in
        egress|patch|metadata|memory|helper) "$ozbox_bin" host-guard "$@" 2>&1 ;;
        *) echo "host-guard takes egress, patch, metadata, memory or helper"; return 2 ;;
      esac ;;
    write-box-secrets|clear-box-secrets|place-bao-token)
      # the logic is in the box's own program (infra/cloud-init/scripts/ozbox-box-secrets.sh), so first boot stays small
      "$ozbox_bin" secrets box-secrets-admin "$action" "$@" 2>&1 ;;
    recover-secrets)
      # Only for a store that can no longer be opened. A running service is never stopped here (so a request cannot be
      # used to interrupt it). The program decides the rest, as root: the service's own state must say its key is lost with
      # no escrow, or that the store is sealed by a file-kept key that is gone while the box is configured for another kind, and the key pinned when the box was made must have signed this box's one-time challenge. Nothing is
      # deleted.
      # (a service that records an unopenable store stops for good, so it is not active here; one still in its retry loop, or
      # running, is refused with the state the unit is in)
      if "$systemctl_bin" is-active --quiet ozbox-secrets.service; then
        echo "refused: the secrets service is running or still starting (unit state: $("$systemctl_bin" is-active ozbox-secrets.service 2>/dev/null || true)), so it has not recorded that its store cannot be opened and nothing is recorded as lost; if it keeps restarting, see ozbox secrets status on the box. Nothing was changed"; return 1
      fi
      if [ "${1:-}" = challenge ] && [ $# = 1 ]; then
        "$ozbox_bin" secrets recover-store --challenge 2>&1; return $?
      fi
      [ $# = 3 ] || { echo "recover-secrets takes the word challenge, or the challenge's nonce, its expiry and the pinned key's signature (ozbox admin <box> -- recover-secrets on your computer does both)"; return 2; }
      printf '%s' "$1" | grep -Eq '^[0-9a-f]{32}$' && printf '%s' "$2" | grep -Eq '^[0-9]{1,16}$' && printf '%s' "$3" | grep -Eq '^[0-9a-f]{128}$' \
        || { echo "the nonce, expiry or signature is not in the expected shape"; return 2; }
      "$ozbox_bin" secrets recover-store --nonce "$1" --expires "$2" --signature "$3" 2>&1 || return 1
      "$systemctl_bin" reset-failed ozbox-secrets.service >/dev/null 2>&1 || true
      "$systemctl_bin" start ozbox-secrets.service 2>&1 && echo "a new secrets store was started" ;;
    enable-linger)
      [ $# = 0 ] || { echo "enable-linger takes no arguments"; return 2; }
      # The user is fixed here, never taken from the request.
      "$loginctl_bin" enable-linger ozbox 2>&1 && echo "the box user's services now start at boot and keep running after logout" || return 1
      # and a manager that started before /work was mounted (so started none of the enabled units) is started properly
      # once; a healthy one is left alone
      if [ -x "$user_manager" ]; then "$user_manager" 2>&1 || return 1; fi ;;
    *) echo "unknown action; the actions are: $(action_names)"; return 2 ;;
  esac
}

process_one() {
  local req="$1" id uid owner words out rc
  id="$(basename "$req" .req)"
  printf '%s' "$id" | grep -Eq '^[a-z0-9]{8,40}$' || { rm -f "$req"; return 0; }
  # a plain file, small, owned by the box user: nothing else is a request
  if [ -L "$req" ] || [ ! -f "$req" ] || [ "$(wc -c <"$req" | tr -d ' ')" -gt 512 ]; then rm -f "$req"; return 0; fi
  owner="$(stat -c %u "$req" 2>/dev/null || stat -f %u "$req")"
  uid="${OZBOX_REQUESTER_UID:-$(id -u ozbox)}"
  if [ "$owner" != "$uid" ]; then record "$id" "$owner" refused not-the-box-user; rm -f "$req"; return 0; fi
  # one line: the action, then its words (letters, digits, dash, dot, underscore only)
  words="$(head -n 1 "$req")"
  rm -f "$req"
  if printf '%s' "$words" | grep -Eq '[^A-Za-z0-9 ._-]'; then
    out="the request holds characters that are not allowed"; rc=2
  else
    # shellcheck disable=SC2086
    set -- $words
    action="${1:-}"; shift || true
    set +e
    out="$(run_action "$action" "$@")"
    rc=$?
    set -e
    record "$id" "$owner" "${action:-none}" "$([ "$rc" = 0 ] && echo ok || echo failed)"
  fi
  mkdir -p "$dir/results"
  { printf 'status=%s\n' "$([ "$rc" = 0 ] && echo ok || echo failed)"; printf '%s\n' "$out"; } >"$dir/results/$id.out.tmp"
  chmod 0644 "$dir/results/$id.out.tmp"
  mv -f "$dir/results/$id.out.tmp" "$dir/results/$id.out"
}

# run by root at first boot and after an upgrade: `ozbox-admin.sh --run ACTION ARGS`
if [ "${1:-}" = "--run" ]; then shift; run_action "$@"; exit $?; fi
for r in "$dir"/requests/*.req; do
  [ -e "$r" ] || continue
  process_one "$r"
done
# results older than an hour are not needed
find "$dir/results" -type f -mmin +60 -delete 2>/dev/null || true
