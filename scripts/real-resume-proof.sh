#!/usr/bin/env bash
# Real-box proof that sessions come back after a restart of the box (ADR 0049): Claude Code sessions in tmux, then an in-place
# resize, then everything the review of 2026-11-13 said a proof must show.
#
#   OZBOX_REAL_PROOF=1 scripts/real-resume-proof.sh --profile <aws-profile> --box <existing box>             prints the steps (default)
#   OZBOX_REAL_PROOF=1 scripts/real-resume-proof.sh --profile <aws-profile> --box <existing box> --execute   runs them
#
# It RESIZES the box you name (stop, change type, start), which bills and ends every process on it, so it refuses without both
# the variable and --execute. Use a box you can lose work on, on a size that is NOT already the target size (a resize to the
# size the box has may do nothing; the proof requires a new boot id and a new tmux server, so that case FAILS instead of passing).
# Needs: aws (v2) with the Session Manager plugin, ssh, an ozbox binary, a terminal (it pauses for the steps only a person can
# do), and Claude Code signed in on the box. The proof passes only when every "check" below holds. Run it on the benchmark's
# shape (4 vCPU / 8 GiB) where a size for it exists, else on S, and write the timings in your own notes (and, for Oz Box's own releases, the release record).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="" BOX="" REGION="us-east-1" SIZE="M" EXECUTE=0
OZBOX="${OZBOX_BIN:-$ROOT/target/debug/ozbox}"
FAILED=0
# shellcheck disable=SC2016  # expanded on the box, on purpose
DIR='$HOME/.local/state/ozbox/sessions'
HOSTILE_DIR='/work/repos/#(touch /tmp/ozbox-fmt-probe)'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --box) BOX="${2:-}"; shift 2 ;;
    --region) REGION="${2:-}"; shift 2 ;;
    --size) SIZE="${2:-}"; shift 2 ;;
    --ozbox) OZBOX="${2:-}"; shift 2 ;;
    --execute) EXECUTE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "${OZBOX_REAL_PROOF:-}" == "1" ]] || { echo "refusing: this resizes a real box. Set OZBOX_REAL_PROOF=1." >&2; exit 2; }
[[ -n "$PROFILE" && -n "$BOX" ]] || { echo "refusing: pass --profile and --box." >&2; exit 2; }
[[ "$PROFILE" =~ ^[A-Za-z0-9._@-]+$ && "$BOX" =~ ^[a-z0-9-]+$ && "$REGION" =~ ^[a-z0-9-]+$ && "$SIZE" =~ ^[A-Za-z-]+$ ]] ||
  { echo "refusing: plain words only." >&2; exit 2; }
if [[ "$EXECUTE" == "1" && ! -t 0 ]]; then
  echo "refusing: the proof pauses for steps only a person can do (it needs a terminal)." >&2; exit 2
fi
export AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" AWS_PAGER=""

say() { printf '%s\n' "$*"; }
# Run one command on the box as the box user (a push-key SSH over Session Manager); in a dry run, print it.
on_box() {
  if [[ "$EXECUTE" != "1" ]]; then say "  [dry-run] on the box: $*" >&2; return 0; fi
  "$OZBOX" connect "$BOX" --ssh --push-key >/dev/null
  ssh -n -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 \
    -o "ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region $REGION --profile $PROFILE" \
    "ozbox@$("$OZBOX" show "$BOX" --json | sed -n 's/.*"instance_id": *"\([^"]*\)".*/\1/p' | head -n 1)" -- "$@"
}
check() {
  local what="$1"; shift
  if [[ "$EXECUTE" != "1" ]]; then say "  [dry-run] check: $what"; return 0; fi
  if "$@"; then say "  ok: $what"; else say "  FAILED: $what" >&2; FAILED=1; fi
}
# A check that only reports (a limit another ADR provides, which this box may not have yet).
note_check() {
  local what="$1"; shift
  if [[ "$EXECUTE" != "1" ]]; then say "  [dry-run] note: $what"; return 0; fi
  if "$@"; then say "  ok: $what"; else say "  NOTE (does not fail the proof): $what"; fi
}
step() { say "== $1"; shift; if [[ "$EXECUTE" == "1" ]]; then "$@"; else say "  [dry-run] $*"; fi; }
by_hand() {
  say "== BY HAND: $1"
  if [[ "$EXECUTE" == "1" ]]; then read -r -p "   press Enter when done (Ctrl-C to abandon): " _; else say "  [dry-run] pause for a person"; fi
}
# Run on the box and require the output to contain a line exactly equal to $1.
box_has_line() { local want="$1"; shift; on_box "$@" | grep -qxF -- "$want"; }
# Run on the box and require the output to be non-empty after the filter.
box_nonempty() { [[ -n "$(on_box "$@")" ]]; }
# True when $1 is not empty and differs from $2.
differs() { [[ -n "$1" && "$1" != "$2" ]]; }
boot_changed() { [[ -n "$BOOT_AFTER" ]]; }
boot_id() { on_box 'cat /proc/sys/kernel/random/boot_id'; }
tmux_pid() { on_box "tmux display-message -p '#{pid}'"; }
# The place of the record of tmux session $1, found by the session and not by id: a resume may give the agent a new id.
record_place() { on_box "sed -n 's/.*\"place\":\"\\([^\"]*\\)\".*/\\1/p' \$(grep -l '\"tmux_session\":\"$1\"' $DIR/claude-code-*.json | head -n 1)"; }
# The session id in that record.
record_id() { on_box "grep -l '\"tmux_session\":\"$1\"' $DIR/claude-code-*.json | head -n 1 | sed 's/.*claude-code-//; s/[.]json\$//'"; }

say "1. Claude Code sessions in tmux, each with a recorded session"
step "1a. a main session, a session in a folder named like a command, a split-pane window, and two sessions to close" \
  on_box "rm -f /tmp/ozbox-fmt-probe; mkdir -p '$HOSTILE_DIR' && tmux new-session -d -s proof -c /work/repos claude && tmux new-session -d -s fmt \"cd '$HOSTILE_DIR' && exec claude\" && tmux new-session -d -s panes -c /work/repos claude && tmux split-window -t panes -c /work/repos claude && tmux new-session -d -s ended -c /work/repos claude && tmux new-session -d -s killed -c /work/repos claude"
by_hand "attach to each of proof, fmt, panes (both panes), ended and killed; send ONE short message in each so a session id exists. In 'ended', then type /exit and close that window. Detach from tmux when done."
check "a record exists for every live session (5: proof, fmt, panes x2, killed; ended was /exit-ed)" \
  box_has_line "5" "ls $DIR/claude-code-*.json | wc -l"
check "a record is mode 0600 in a 0700 folder" \
  box_has_line "700 600" "echo \$(stat -c %a $DIR) \$(stat -c %a \$(ls $DIR/claude-code-*.json | head -n 1))"
check "no record holds prompt text" on_box "! grep -l -i 'prompt' $DIR/*.json"
# (this check fails falsely on a box where someone ran `ozboxd hooks install`, which adds the asks on purpose)
check "the boot install added no ask to Claude Code's settings (no PreToolUse hook of Oz Box)" \
  on_box "! grep -q '\"name\": \"ozboxd hook\"' \$HOME/.claude/settings.json"
step "1b. close one session the way a person does and kill another's window; wait for the once-a-minute check" \
  on_box "tmux kill-window -t killed; sleep 75"
check "the ended and the killed sessions left no record (S1): exactly 4 remain" box_has_line "4" "ls $DIR/claude-code-*.json | wc -l"
say "   a nested claude must not replace the pane's record (S18), and settings.json is written once (S17):"
by_hand "in 'proof', ask the agent to run 'claude -p hello' through its Bash tool (a second Claude Code in the same pane), wait for it to finish, then detach."
check "the nested session did not add or replace a record: still exactly 4" box_has_line "4" "ls $DIR/claude-code-*.json | wc -l"
check "settings.json is not a re-sorted file: Claude Code starts without a warning (by hand: no 'settings' warning was shown) and has the four record hooks once each" \
  box_has_line "4" "grep -o '\"session-hook\"' \$HOME/.claude/settings.json | wc -l"
if [[ "$EXECUTE" == "1" ]]; then
  SETTINGS_BEFORE="$(on_box "sha256sum \$HOME/.claude/settings.json | cut -d' ' -f1")"
else
  SETTINGS_BEFORE=""
fi
if [[ "$EXECUTE" == "1" ]]; then
  BOOT_BEFORE="$(boot_id)"; PID_BEFORE="$(tmux_pid)"
  ID_MAIN="$(record_id proof)"
  PLACE_BEFORE="$(record_place proof)"
  say "   before: boot id $BOOT_BEFORE, tmux server pid $PID_BEFORE, main session $ID_MAIN, place $PLACE_BEFORE"
  [[ -n "$BOOT_BEFORE" && -n "$PID_BEFORE" && -n "$ID_MAIN" && -n "$PLACE_BEFORE" ]] || { say "FAILED: could not read the state before the resize" >&2; exit 1; }
else
  BOOT_BEFORE="" PID_BEFORE="" ID_MAIN="" PLACE_BEFORE=""
fi
say "2. A supervised run (a long one), started through the dashboard or: ozbox run start ... (note its id; by hand)"

STARTED="$(date +%s)"
step "3. In-place resize (stop, change type, start)" "$OZBOX" -y resize "$BOX" --size "$SIZE"
wait_for_new_boot() {
  local _
  for _ in $(seq 1 90); do
    local now
    now="$(boot_id 2>/dev/null || true)"
    if [[ -n "$now" && "$now" != "$BOOT_BEFORE" ]]; then BOOT_AFTER="$now"; return 0; fi
    sleep 10
  done
  return 1
}
BOOT_AFTER=""
step "4. Wait for the box to answer with a NEW boot id (a resize that did nothing never gets one)" wait_for_new_boot
ANSWERED="$(date +%s)"
check "the box booted again (boot id changed)" boot_changed
step "4b. Wait for the box user's manager to settle, then 30 s for the agents to start" \
  on_box "systemctl --user is-system-running --wait >/dev/null 2>&1; sleep 30"

say "5. After the restart"
if [[ "$EXECUTE" == "1" ]]; then
  PID_AFTER="$(tmux_pid)"
  say "   tmux server pid after: $PID_AFTER (before $PID_BEFORE)"
  check "the tmux server pid changed (a new tmux server)" differs "$PID_AFTER" "$PID_BEFORE"
fi
check "the resume service ran this boot and logged a reopened session (the unit always exits 0, so its status proves nothing)" \
  box_nonempty "journalctl --user -u ozbox-session-resume.service -b --no-pager | grep 'reopened with its own resume'"
check "four sessions were reopened, not more and not fewer (ended and killed did not come back)" \
  box_has_line "4" "journalctl --user -u ozbox-session-resume.service -b --no-pager | grep -c 'reopened with its own resume'"
check "proof is back and its pane is running claude" box_has_line "proof:claude" "tmux list-panes -a -F '#{session_name}:#{pane_current_command}' | grep '^proof:'"
check "fmt is back and its pane is running claude" box_has_line "fmt:claude" "tmux list-panes -a -F '#{session_name}:#{pane_current_command}' | grep '^fmt:'"
check "panes is back with both panes running claude" box_has_line "2" "tmux list-panes -a -F '#{session_name}:#{pane_current_command}' | grep -c '^panes:claude'"
check "ended did not come back" on_box "! tmux has-session -t ended 2>/dev/null"
check "killed did not come back" on_box "! tmux has-session -t killed 2>/dev/null"
check "proof is in the recorded folder" box_has_line "/work/repos" "tmux display-message -p -t proof '#{pane_current_path}'"
if [[ "$EXECUTE" == "1" ]]; then
  # --resume may give the agent a new id, so the old id is looked for as the process argument and the record is found by session
  check "a 'claude --resume $ID_MAIN' process exists" box_nonempty "pgrep -af '[c]laude.* --resume $ID_MAIN'"
  PLACE_AFTER="$(record_place proof 2>/dev/null || true)"
  say "   record place after: $PLACE_AFTER (before $PLACE_BEFORE; the server part is pid:start)"
  check "the record moved to the new server" differs "$PLACE_AFTER" "$PLACE_BEFORE"
  check "the record names the new tmux server's pid" [ "${PLACE_AFTER%%:*}" = "$PID_AFTER" ]
else
  check "a 'claude --resume <the recorded id>' process exists" true
  check "the record moved to the new server" true
fi
say "   a folder named like a command (S2):"
check "the probe file was not made: the folder name was never run" on_box "[ ! -e /tmp/ozbox-fmt-probe ]"
check "fmt is in that folder" box_has_line "$HOSTILE_DIR" "tmux display-message -p -t fmt '#{pane_current_path}'"
say "   memory guard (S5, with ADR 0045 on the box):"
check "the tmux server is in its own scope, not in the resume service" \
  box_nonempty "cat /proc/\$(tmux display-message -p '#{pid}')/cgroup | grep 'tmux-spawn-ozbox-resume-'"
check "the tmux server is not in ozbox-session-resume.service" on_box "! grep -q 'ozbox-session-resume.service' /proc/\$(tmux display-message -p '#{pid}')/cgroup"
note_check "that scope has the soft memory limit and OOMPolicy=continue of ADR 0045" \
  on_box "u=\$(grep -o 'tmux-spawn-ozbox-resume-[0-9]*.scope' /proc/\$(tmux display-message -p '#{pid}')/cgroup | head -n 1); systemctl --user show -p MemoryHigh -p OOMPolicy \"\$u\" | tee /dev/stderr | grep -q 'OOMPolicy=continue'"

say "6. Idempotence: a second run of the unit does nothing"
if [[ "$EXECUTE" == "1" ]]; then
  WINDOWS_BEFORE="$(on_box 'tmux list-windows -a | wc -l')"
  PID_BEFORE_RESTART="$(tmux_pid)"
  on_box 'systemctl --user restart ozbox-session-resume.service; sleep 10' || true
  WINDOWS_AFTER="$(on_box 'tmux list-windows -a | wc -l')"
  check "the window count is unchanged after restarting the unit ($WINDOWS_BEFORE)" test "$WINDOWS_BEFORE" = "$WINDOWS_AFTER"
  check "the tmux server survived the unit's restart" test "$(tmux_pid)" = "$PID_BEFORE_RESTART"
else
  step "6a. restart the unit" on_box 'systemctl --user restart ozbox-session-resume.service'
  check "the window count is unchanged after restarting the unit" true
  check "the tmux server survived the unit's restart" true
fi

say "   settings.json after a second boot (S17):"
if [[ "$EXECUTE" == "1" ]]; then
  note_check "settings.json is byte-identical to before the restart (Claude Code may have rewritten it itself; then compare the hooks, not the bytes)" \
    test "$(on_box "sha256sum \$HOME/.claude/settings.json | cut -d' ' -f1")" = "$SETTINGS_BEFORE"
fi
check "the four record hooks are still there exactly once" box_has_line "4" "grep -o '\"session-hook\"' \$HOME/.claude/settings.json | wc -l"

say "6b. An agent that died and left a shell loses its record after three minutes (S18); a live one does not"
step "6b. kill the claude process of the fmt window (its pane keeps a shell), wait 5 minutes" \
  on_box "pkill -9 -P \$(tmux display-message -p -t fmt '#{pane_pid}'); sleep 300"
check "fmt's record is gone and the others' are still there" box_has_line "3" "ls $DIR/claude-code-*.json | wc -l"
say "6c. The tmux server ends while the box runs: its records go, and a shutdown guard never mattered here (S18)"
step "6c. tmux kill-server, wait 90 s" on_box "tmux kill-server; sleep 90"
check "no record is left for a server that ended in this boot" box_has_line "0" "ls $DIR/claude-code-*.json 2>/dev/null | wc -l"
say "6d. The off switch (S20)"
check "with the switch file present the boot step says it is off and changes nothing" \
  box_nonempty "mkdir -p \$HOME/.config/ozbox && touch \$HOME/.config/ozbox/session-resume.off && ozboxd session-resume | grep 'turned off'"
step "6d. remove the switch again" on_box "rm -f \$HOME/.config/ozbox/session-resume.off"
by_hand "with a Claude Code session already running, restart ozboxd.service and watch for Claude Code's hooks-changed review prompt in /hooks; it may appear once (ADR 0049) and must not loop. Then, in the journal, look for the line 'the cleanup of closed windows has been skipped' after ten minutes: it must NOT appear on a healthy box (S21)."
by_hand "optional: 'systemctl --user disable ozbox-session-resume.service', restart ozboxd.service as an administrator, and confirm the link in ~/.config/systemd/user/default.target.wants did not come back."

say "7. By hand: the supervised run shows as interrupted/paused (its own recovery, not this feature); a clean resize kept the records (they were read above); a git push in a tmux Claude session is not asked about; ssm-user and root have no ~/.claude made by Oz Box."
say "8. Record the timings in your notes: stop to answering, answering to the resumed window (the benchmark's resume metric)."
if [[ "$EXECUTE" == "1" ]]; then
  say "   resize to answering: $((ANSWERED - STARTED)) s"
fi
if [[ "$FAILED" != "0" ]]; then say "PROOF FAILED" >&2; exit 1; fi
say "done"
