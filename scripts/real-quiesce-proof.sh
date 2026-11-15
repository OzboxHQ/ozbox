#!/usr/bin/env bash
# Real-box proof of "quiesce before a resize" (ADR 0049, slice 2): a Claude Code tmux session, a supervised run and a dirty git
# repository, then an in-place resize. It passes only when the session is back, the run ended and was reported, the snapshot
# ref is there, and the repository's working tree, index, stash, branch and remotes are exactly as they were.
#
#   OZBOX_REAL_PROOF=1 scripts/real-quiesce-proof.sh --profile <aws-profile> --box <existing box>             prints the steps (default)
#   OZBOX_REAL_PROOF=1 scripts/real-quiesce-proof.sh --profile <aws-profile> --box <existing box> --execute   runs them
#
# It RESIZES the box you name (stop, change type, start), which bills and ends every process on it, so it refuses without both
# the variable and --execute. Use a box you can lose work on, on a size that is NOT already the target size. Needs: aws (v2) with
# the Session Manager plugin, ssh, an ozbox binary, a terminal, and Claude Code signed in on the box. The box's agent must be a
# build that has /v1/quiesce (it checks). Write the timings in your own notes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="" BOX="" REGION="us-east-1" SIZE="M" EXECUTE=0
OZBOX="${OZBOX_BIN:-$ROOT/target/debug/ozbox}"
FAILED=0
REPO='/work/repos/quiesce-proof'
SOCK='/run/ozboxd/ozboxd.sock'

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
step() { say "== $1"; shift; if [[ "$EXECUTE" == "1" ]]; then "$@"; else say "  [dry-run] $*"; fi; }
by_hand() {
  say "== BY HAND: $1"
  if [[ "$EXECUTE" == "1" ]]; then read -r -p "   press Enter when done (Ctrl-C to abandon): " _; else say "  [dry-run] pause for a person"; fi
}
box_has_line() { local want="$1"; shift; on_box "$@" | grep -qxF -- "$want"; }
box_nonempty() { [[ -n "$(on_box "$@")" ]]; }
boot_id() { on_box 'cat /proc/sys/kernel/random/boot_id'; }
state_of_repo() {
  # everything the person owns in the repo, in one line each, so before and after can be compared byte for byte
  on_box "cd '$REPO' && sha256sum .git/index && git stash list && git status --porcelain && git rev-parse HEAD && git symbolic-ref HEAD && git remote -v && git branch --list && for f in a.txt untracked.txt; do sha256sum \$f; done"
}

say "1. A dirty repository: a modified file, an untracked file, a staged file, a stash entry, a remote, an ignored file"
step "1a. make it" on_box "rm -rf '$REPO' && mkdir -p '$REPO' && cd '$REPO' && git init -q -b main && printf 'ignored.log\n' > .gitignore && echo one > a.txt && echo s > b.txt && git add -A && git -c user.name=p -c user.email=p@example.com commit -q -m init && echo two >> a.txt && git -c user.name=p -c user.email=p@example.com stash push -q -m mine && echo three >> a.txt && echo new > untracked.txt && echo noise > ignored.log && echo staged > staged.txt && git add staged.txt && git remote add origin https://example.invalid/x.git"
if [[ "$EXECUTE" == "1" ]]; then REPO_BEFORE="$(state_of_repo)"; else REPO_BEFORE=""; fi

say "2. A Claude Code session in tmux, and a supervised run that ignores a polite request"
step "2a. the session" on_box "tmux new-session -d -s qproof -c /work/repos claude"
by_hand "attach to qproof, send ONE short message so a session id exists, then detach."
step "2b. a supervised run: a shell that traps SIGTERM and keeps going (it must be reported as stopped after the wait), and a polite one" \
  on_box "curl -s --unix-socket $SOCK -X POST http://x/v1/runs -d '{\"argv\":[\"sh\",\"-c\",\"trap \\\"\\\" TERM; sleep 600\"]}' && curl -s --unix-socket $SOCK -X POST http://x/v1/runs -d '{\"argv\":[\"sleep\",\"600\"]}'"
check "the box's agent has the quiesce service" box_nonempty "curl -s --unix-socket $SOCK http://x/v1/quiesce | grep '\"state\"'"
if [[ "$EXECUTE" == "1" ]]; then BOOT_BEFORE="$(boot_id)"; else BOOT_BEFORE=""; fi

say "3. The resize. Read what the command says before it asks: it must list the 2 runs and the session, and say 'Sessions come back; running programs end.'"
if [[ "$EXECUTE" == "1" ]]; then
  OUT="$(mktemp)"
  "$OZBOX" -y resize "$BOX" --size "$SIZE" --strict-checkpoint 2>&1 | tee "$OUT" || FAILED=1
  check "the command said sessions come back and running programs end" grep -q 'Sessions come back; running programs end' "$OUT"
  check "it listed 2 supervised runs" grep -q '2 supervised run(s)' "$OUT"
  check "it reported the run that ignored the request as stopped" grep -q 'did not end within the wait and was stopped' "$OUT"
  check "it reported the polite run as ended when asked" grep -q 'ended when asked' "$OUT"
  check "it reported where the work was saved" grep -q 'saved uncommitted work in quiesce-proof as refs/ozbox/wip/' "$OUT"
  rm -f "$OUT"
else
  step "3. resize" "$OZBOX" -y resize "$BOX" --size "$SIZE" --strict-checkpoint
fi
wait_for_new_boot() {
  local _
  for _ in $(seq 1 90); do
    local now
    now="$(boot_id 2>/dev/null || true)"
    if [[ -n "$now" && "$now" != "$BOOT_BEFORE" ]]; then return 0; fi
    sleep 10
  done
  return 1
}
step "4. wait for a NEW boot id, then for the user manager and the agents" wait_for_new_boot
on_box "systemctl --user is-system-running --wait >/dev/null 2>&1; sleep 30" || true

say "5. After"
check "the Claude Code session is back, running claude" box_has_line "qproof:claude" "tmux list-panes -a -F '#{session_name}:#{pane_current_command}' | grep '^qproof:'"
check "the snapshot ref is there, and is a commit" box_nonempty "cd '$REPO' && git for-each-ref refs/ozbox/wip/ --format='%(objecttype)' | grep -x commit"
check "the snapshot holds the modified, the untracked and the staged files, and not the ignored one" \
  box_has_line "3" "cd '$REPO' && r=\$(git for-each-ref refs/ozbox/wip/ --format='%(refname)' | tail -n 1) && git ls-tree -r --name-only \$r | grep -cxE 'a.txt.*|untracked.txt|staged.txt' | head -n 1"
check "the ignored file is not in it" on_box "cd '$REPO' && r=\$(git for-each-ref refs/ozbox/wip/ --format='%(refname)' | tail -n 1) && ! git ls-tree -r --name-only \$r | grep -qx ignored.log"
if [[ "$EXECUTE" == "1" ]]; then
  REPO_AFTER="$(state_of_repo)"
  check "working tree, index, stash, branch, HEAD and remotes are byte-identical to before" test "$REPO_BEFORE" = "$REPO_AFTER"
fi
check "no run is still going" box_has_line "0" "curl -s --unix-socket $SOCK http://x/v1/runs | grep -o '\"state\":\"running\"' | wc -l"
check "the machine's own stop wrote no visible wip/ branch (it takes the hidden snapshot, not the older pushing checkpoint)" box_has_line "0" "cd '$REPO' && git for-each-ref refs/heads/wip/ | wc -l"
check "and nothing was pushed: no remote-tracking ref, no push in the daemon's log since the boot" box_has_line "0" "cd '$REPO' && git for-each-ref refs/remotes | wc -l"
check "the daemon's stop line says it took a hidden snapshot" on_box "journalctl -u ozboxd --no-pager -b -1 2>/dev/null | grep -q 'a hidden snapshot; nothing visible is written and nothing is pushed'"
check "the documented restore copies the snapshot into a separate folder and leaves the repository alone" on_box "cd '$REPO' && rm -rf /tmp/qrecovered && mkdir /tmp/qrecovered && r=\$(git for-each-ref refs/ozbox/wip/ --format='%(refname)' | tail -n 1) && before=\$(git status --porcelain | md5sum) && git archive \$r | tar -x -C /tmp/qrecovered && grep -q three /tmp/qrecovered/a.txt && [ -f /tmp/qrecovered/untracked.txt ] && [ \"\$before\" = \"\$(git status --porcelain | md5sum)\" ]; rc=\$?; rm -rf /tmp/qrecovered; exit \$rc"
check "a second quiesce of the same state saves nothing new (the same ref)" \
  box_has_line "1" "cd '$REPO' && curl -s --unix-socket $SOCK -X DELETE http://x/v1/quiesce >/dev/null; curl -s --unix-socket $SOCK -X POST http://x/v1/quiesce -d '{\"grace_s\":1}' >/dev/null; sleep 5; git for-each-ref refs/ozbox/wip/ | wc -l"
by_hand "confirm that Claude Code in qproof was sent nothing: its conversation shows no message you did not type (the window shows the resume offer only)."
if [[ "$FAILED" != "0" ]]; then say "PROOF FAILED" >&2; exit 1; fi
say "done. Record: stop to answering, and how long the quiesce took, in your own notes."
