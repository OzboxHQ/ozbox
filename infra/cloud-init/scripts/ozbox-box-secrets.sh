#!/usr/bin/env bash
# The box's own secrets declaration where the provider has no instance tags to carry it (Hetzner), and the vault token. Run as
# root by the narrow root helper, through `ozbox secrets box-secrets-admin ACTION ARGS...` (the program carries this script, so
# the first-boot configuration does not have to).
#
#   write-box-secrets APPROVAL BACKEND ROLE PATH ADDRHEX MOUNT
#       writes /etc/ozbox/box-secrets.env (names and an address, never a secret) and reloads the box's secrets. PATH is the path
#       with / written as .. and no leading slash (the helper's request holds plain words only); ADDRHEX is the OpenBao address
#       in hex, or - for none. APPROVAL is a fresh approval code once a second factor exists, or -. The approval is bound
#       to this exact declaration: scope box-secrets, project declaration, env d-<the first 16 hex digits of the sha256
#       of "openbao ROLE PATH ADDRHEX MOUNT">, so an approval for one path cannot carry a different address. A change of
#       address deletes the vault token in the same step (a new address always needs a new token). With no second factor
#       yet (bootstrap) the box user cannot be told from the owner, so a change of address, or any change while a vault
#       token is in place, is refused: set the address with the module's variables when the box is made, or enrol a second
#       factor first.
#   clear-box-secrets APPROVAL     removes that declaration (only a file this script wrote), and the vault token with it
#   place-bao-token ID APPROVAL    stores the box's OpenBao token, read once from requests/ID.tok, in a root-only file the
#                                  loader's unit reads as environment (the box user never can)
#
# Environment (for tests): OZBOX_ADMIN_DIR, OZBOX_SYSTEMCTL, OZBOX_BIN, OZBOX_SECRETS_ADMIN_SOCKET, OZBOX_BOX_SECRETS_ENV,
# OZBOX_BAO_ENV, OZBOX_REQUESTER_UID.
set -euo pipefail

dir="${OZBOX_ADMIN_DIR:-/run/ozbox-admin}"
systemctl_bin="${OZBOX_SYSTEMCTL:-systemctl}"
ozbox_bin="${OZBOX_BIN:-/usr/local/bin/ozbox}"
admin_socket="${OZBOX_SECRETS_ADMIN_SOCKET:-/run/ozbox-secrets/admin/admin.sock}"
box_secrets_env="${OZBOX_BOX_SECRETS_ENV:-/etc/ozbox/box-secrets.env}"
bao_env="${OZBOX_BAO_ENV:-/etc/ozbox/bao.env}"
declared_marker="# written by ozbox write-box-secrets (no instance tags here)"

run_action() {
  local action="$1"; shift
  case "$action" in
    write-box-secrets)
    local appr="${1:-}" backend="${2:-}" role="${3:-}" enc="${4:-}" addrhex="${5:-}" mount="${6:-}" via bpath addr="" tmp old_addr bind dropped
    [ $# = 6 ] || { echo "write-box-secrets takes an approval (or -), a backend, a role, a path, an address (hex, or -) and a mount"; return 2; }
    [ "$appr" != - ] || appr=""
    [ "$backend" = openbao ] || { echo "on this box the backend must be openbao"; return 2; }
    printf '%s' "$role" | grep -Eq '^[a-z0-9-]{1,32}$' || { echo "the role must be lowercase letters, digits and dashes"; return 2; }
    printf '%s' "$mount" | grep -Eq '^[a-z0-9_-]{1,32}$' || { echo "the mount must be lowercase letters, digits, dashes and underscores"; return 2; }
    # The path is written with .. for /, so the request holds only plain words: no segment may start or end with a dot,
    # and three dots in a row are refused, which keeps the reading one way only.
    if ! printf '%s' "$enc" | grep -Eq '^[A-Za-z0-9_-]([A-Za-z0-9_.-]{0,100}[A-Za-z0-9_-])?$' || printf '%s' "$enc" | grep -q '[.][.][.]'; then
      echo "the path is not valid"; return 2
    fi
    sl=/; bpath="/${enc//../$sl}"
    if printf '%s' "$bpath" | grep -Eq '[.][.]|//' || [ "${#bpath}" -gt 100 ]; then echo "the path is not valid"; return 2; fi
    if [ "$addrhex" != - ]; then
      printf '%s' "$addrhex" | grep -Eq '^([0-9a-f]{2}){1,100}$' || { echo "the address must be hex"; return 2; }
      addr="$(printf '%b' "$(printf '%s' "$addrhex" | sed 's/../\\x&/g')")"
      printf '%s' "$addr" | grep -Eq '^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{2,5})?$' || { echo "the vault address must be https://host or https://host:port"; return 2; }
    fi
    old_addr=""
    [ -f "$box_secrets_env" ] && old_addr="$(sed -n 's/^BAO_ADDR=//p' "$box_secrets_env" | head -n 1)"
    bind="d-$(printf 'openbao %s %s %s %s' "$role" "$enc" "$addrhex" "$mount" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-16)"
    if ! via="$(printf '%s\n' "$appr" | "$ozbox_bin" secrets gate --scope box-secrets --project declaration --env "$bind" --socket "$admin_socket" 2>&1)"; then
      echo "$via"; return 3
    fi
    if [ "$via" = bootstrap ] && { [ "$addr" != "$old_addr" ] || [ -e "$bao_env" ]; }; then
      echo "this box has no second factor yet, so its vault address cannot be changed (nor its declaration while a vault token is in place): set it with the module's variables when the box is made, or enrol a second factor and approve this declaration ($bind)"
      return 3
    fi
    tmp="$box_secrets_env.tmp"
    {
      printf '%s\n' "$declared_marker"
      printf 'OZBOX_BOX_SECRETS_BACKEND=%s\n' "$backend"
      printf 'OZBOX_BOX_SECRETS_PATH=%s\n' "$bpath"
      printf 'OZBOX_BOX_ROLE=%s\n' "$role"
      printf 'OZBOX_BOX_SECRETS_REGION=\n'
      printf 'OZBOX_BOX_SECRETS_MOUNT=%s\n' "$mount"
      [ -z "$addr" ] || printf 'BAO_ADDR=%s\n' "$addr"
    } >"$tmp"
    chmod 0644 "$tmp"
    # a token is only ever sent to the address it was placed for
    dropped=""
    if [ "$addr" != "$old_addr" ] && [ -e "$bao_env" ]; then rm -f "$bao_env"; dropped=1; fi
    mv "$tmp" "$box_secrets_env"
    "$systemctl_bin" restart ozbox-box-secrets.service 2>&1 || true
    echo "the box's secrets declaration was written ($via)"
    [ -z "$dropped" ] || echo "the vault address changed, so the vault token was removed: place one for the new address (place-bao-token)" ;;
  clear-box-secrets)
    local via
    [ $# = 1 ] || { echo "clear-box-secrets takes an approval (or -)"; return 2; }
    [ "$1" != - ] || set -- ""
    if ! via="$(printf '%s\n' "$1" | "$ozbox_bin" secrets gate --scope box-secrets --project declaration --socket "$admin_socket" 2>&1)"; then
      echo "$via"; return 3
    fi
    # the same rule as a write: with no second factor, nothing changes while a vault token is in place
    if [ "$via" = bootstrap ] && [ -e "$bao_env" ]; then
      echo "this box has no second factor yet, so its declaration cannot be removed while a vault token is in place: enrol a second factor first"
      return 3
    fi
    if [ -f "$box_secrets_env" ] && [ "$(head -n 1 "$box_secrets_env")" = "$declared_marker" ]; then
      rm -f "$box_secrets_env" "$bao_env"
      "$systemctl_bin" restart ozbox-box-secrets.service 2>&1 || true
      echo "the box's secrets declaration was removed ($via)"
    else
      echo "there is no declaration written by this action; a file placed by hand is left alone"
    fi ;;
  place-bao-token)
    local tid="${1:-}" appr="${2:-}" tok uidr first via
    [ $# = 2 ] || { echo "place-bao-token takes an id and an approval (or -)"; return 2; }
    [ "$appr" != - ] || appr=""
    printf '%s' "$tid" | grep -Eq '^[0-9a-f]{16}$' || { echo "the token id must be 16 hex digits"; return 2; }
    tok="$dir/requests/$tid.tok"
    if ! via="$(printf '%s\n' "$appr" | "$ozbox_bin" secrets gate --scope box-secrets --project bao-token --socket "$admin_socket" 2>&1)"; then
      rm -f "$tok"; echo "$via"; return 3
    fi
    uidr="${OZBOX_REQUESTER_UID:-$(id -u ozbox)}"
    # opened once without following a link, checked and read through that descriptor, and removed (never check the name
    # and then read it again: the box user owns the file and can swap it for a link in between)
    if ! first="$("$ozbox_bin" host-guard take-file --dir "$dir/requests" --id "$tid" --owner "$uidr" --max 1024 2>/dev/null)"; then
      rm -f "$tok"; echo "the token file was not found, or is not the box user's"; return 2
    fi
    printf '%s' "$first" | grep -Eq '^[A-Za-z0-9._-]{20,255}$' || { echo "the token has an unexpected shape"; return 2; }
    # root-only: the secrets loader's unit reads it as an environment file, the box user never can
    ( umask 077; printf 'BAO_TOKEN=%s\n' "$first" >"$bao_env.tmp" )
    chmod 0600 "$bao_env.tmp"
    mv "$bao_env.tmp" "$bao_env"
    "$systemctl_bin" restart ozbox-box-secrets.service 2>&1 || true
    echo "the box's vault token was stored ($via)" ;;
    *) echo "unknown action"; return 2 ;;
  esac
}

run_action "$@"
