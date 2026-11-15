#!/usr/bin/env bash
# Real-box proof of the box memory guard (ADR 0045). Run ONCE, ON A FRESH S BOX, by a person: this is the release gate. It is not
# run by CI and not by the agents that wrote it: it deliberately takes the box to a real out-of-memory kill, twice.
#
#   1. make a fresh S box:       ozbox create memproof --size S ; ozbox ide memproof ; ozbox tunnel setup cloudflare --on-box memproof
#      then, in the box's web IDE, open a terminal and leave `sleep 4321` running in it (step I looks for it)
#   2. run this ON the box, as the box user, from a login session (`ozbox ssh memproof`), not from inside the web IDE:
#        OZBOX_MEMORY_PROOF=1 bash real-box-memory-proof.sh
#   3. paste the output into your notes; destroy the box:  ozbox destroy memproof
#
# It refuses unless OZBOX_MEMORY_PROOF=1. It prints PASS or FAIL per step and EXITS NON-ZERO if any step FAILED: a gate that
# cannot fail is a comment. A step that cannot run (the web IDE is not set up, the terminal is missing) is a FAIL, never a skip.
# The first review (2026-11-13) found the first version of this script would have passed on a box where the incident still
# happened, so every step below says what it would have caught:
#
#   A  compressed swap on /dev/zram*, no swap anywhere else, systemd-oomd off
#   B  the memory controller is delegated to the box user's manager
#   C  protected scores: tunnel and IDE units at their scores, the system tunnel's cloudflared child too; a login session is
#      never protected; a capped job at 300
#   D  the soft limit reaches a tmux scope (the pane really runs in a `tmux-spawn-` scope), and so does OOMPolicy=continue
#   E  a hog sized ABOVE the capped scope's memory.max + memory.swap.max is killed (137 exactly, never 1), oom_kill counted
#   F  an uncapped hog of INCOMPRESSIBLE data is throttled at the soft limit, a memory_pressure incident is raised, units survive
#   G  a live install through the root helper restarts nothing and reaches the box user's manager (M1); the helper refresh works
#   H  the secrets service has memory.swap.max = 0 and its protected score
#   I  an IDE terminal's processes (really in the IDE's cgroup) are at 200 (M3); the IDE's main process AND its editor server
#      are at -500 (N3)
#   J  a daemon run sized above its own cap (max + swap) is killed alone, 137 and an oom_kill: ozboxd keeps its main process
#   K  THE INCIDENT: an uncapped hog in a tmux pane under a real global out-of-memory kill; the sentinel beside it, the pane's
#      scope and every unit survive (H1), and the same inside the web IDE's own cgroup
#   L  after all of that: every unit has the main process it had, the SSM agent is still running, no unit is failed
#   M  timings for your notes (never pass or fail)
set -u

if [ "${OZBOX_MEMORY_PROOF:-}" != "1" ]; then
  echo "refusing to run: this fills the box's memory on purpose. Run it on a fresh, disposable S box, with OZBOX_MEMORY_PROOF=1." >&2
  exit 2
fi
if [ "$(id -u)" = 0 ]; then
  echo "refusing to run as root: run it as the box user in a login session (ozbox ssh), the way the incident happened." >&2
  exit 2
fi

fails=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
note() { echo "NOTE  $*"; }
step() { echo; echo "== $*"; }
ozbox_bin="${OZBOX_BIN:-ozbox}"
uid="$(id -u)"
user_sctl() { systemctl --user "$@"; }
work="$(mktemp -d)"
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  tmux kill-session -t memproof 2>/dev/null
  tmux kill-session -t memincident 2>/dev/null
  [ -n "${sentinel_ide:-}" ] && kill "$sentinel_ide" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

# The units to watch: whichever of Oz Box's own and the hand-made names exist on this box. A unit counts with its MAIN PID: a
# unit that was restarted and came back is a unit the guard failed to keep alive.
sys_units="ozbox-cloudflared.service ozbox-code-connector.service ozbox-secrets.service ozboxd.service"
usr_units="oz-cloudflared.service oz-code-server.service ozbox-ide.service ozbox-cloudflared.service"
ssm_units="snap.amazon-ssm-agent.amazon-ssm-agent.service amazon-ssm-agent.service"
snap() {
  for u in $sys_units; do systemctl is-active --quiet "$u" 2>/dev/null && echo "sys:$u:$(systemctl show -p MainPID --value "$u")"; done
  for u in $usr_units; do user_sctl is-active --quiet "$u" 2>/dev/null && echo "usr:$u:$(user_sctl show -p MainPID --value "$u")"; done
}
before="$(snap | sort)"
echo "units active before (unit:main pid): $(echo "$before" | tr '\n' ' ')"
echo "$before" | grep -q 'sys:ozboxd.service' || fail "ozboxd is not running: the box has no daemon to protect"
echo "$before" | grep -q 'usr:\(oz-code-server\|ozbox-ide\)\.service' || fail "the web IDE is not running (ozbox ide memproof): steps I and K prove nothing without it"
echo "$before" | grep -q 'cloudflared\|code-connector' || fail "no tunnel is running (ozbox tunnel setup cloudflare --on-box memproof)"
units_unchanged() { # $1 = where we are
  local after
  after="$(snap | sort)"
  if [ "$before" = "$after" ]; then pass "$1: every unit that was up is up, with the same main process"; else fail "$1: units changed: before [$(echo "$before" | tr '\n' ' ')] after [$(echo "$after" | tr '\n' ' ')]"; fi
}
ssm_unit=""
for u in $ssm_units; do systemctl is-active --quiet "$u" 2>/dev/null && ssm_unit="$u" && break; done
ssm_pid="$([ -n "$ssm_unit" ] && systemctl show -p MainPID --value "$ssm_unit")"
# an AWS box has the SSM agent (it is how the box is reached): not finding it there is a FAIL, elsewhere a NOTE
on_aws=0
grep -qi amazon /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/bios_vendor 2>/dev/null && on_aws=1
if [ -n "$ssm_unit" ]; then echo "the SSM agent: $ssm_unit pid $ssm_pid"
elif [ "$on_aws" = 1 ]; then fail "this is an AWS box and no SSM agent unit is running: the box is unreachable through Session Manager, and the steps that check it would pass on nothing"
else note "no SSM agent unit found on this box (not an AWS box)"; fi
ssm_alive() { # $1 = where we are
  if [ -z "$ssm_unit" ]; then [ "$on_aws" = 1 ] && fail "$1: no SSM agent on an AWS box"; return 0; fi
  if systemctl is-active --quiet "$ssm_unit"; then
    pass "$1: the SSM agent is still running"
    [ "$(systemctl show -p MainPID --value "$ssm_unit")" = "$ssm_pid" ] || note "$1: the SSM agent was restarted (it restarts itself); it is unprotected on purpose in this release"
  else
    fail "$1: the SSM agent is NOT running: the box would be unreachable through Session Manager"
  fi
}
pressure_incidents() { curl -s --unix-socket /run/ozboxd/ozboxd.sock http://localhost/v1/incidents 2>/dev/null | grep -o 'memory_pressure' | wc -l; }

# The hog: it takes memory with data that does not compress (a byte per page compresses to nothing and makes zram look far
# better than it will with a real build), and it is never allowed to run longer than its deadline: a hog that is not killed
# exits 0, and every step that expects a kill treats 0 as a failure.
cat >"$work/hog.py" <<'PY'
import os, sys, time
want, deadline = int(sys.argv[1]), float(sys.argv[2])
if want < 0:
    # sized from this process's OWN cgroup: above memory.max + memory.swap.max, so a healthy cap cannot hold it (a hog that fits
    # in RAM plus swap is throttled, not killed, and exits 0). No limit set counts as the box's total.
    cg = open("/proc/self/cgroup").read().strip().split(":", 2)[2]
    total = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    def lim(f):
        try:
            v = open("/sys/fs/cgroup" + cg + "/" + f).read().strip()
        except OSError:
            return total
        return total if v == "max" else int(v)
    want = lim("memory.max") + lim("memory.swap.max") + (1 << 30)
    print("hog wants %d bytes" % want, flush=True)
chunk, held, t0 = 64 << 20, [], time.time()
while sum(map(len, held)) < want and time.time() - t0 < deadline:
    held.append(os.urandom(chunk))
    time.sleep(0.02)
time.sleep(max(0.0, deadline - (time.time() - t0)))
PY
# Runs a hog sized above its own cap and reads its scope's oom_kill counter BEFORE the scope can go away. TERM is ignored: when the
# kernel kills the hog, systemd stops the scope and sends TERM to the wrapper, which would otherwise turn the expected 137 into 143
# (or lose the counter). $1 = hog.py, $2 = where to write the counter and the hog's status.
cat >"$work/capwrap.sh" <<'SH'
#!/bin/sh
trap '' TERM
cg=$(cut -d: -f3 /proc/self/cgroup)
python3 "$1" -1 150
r=$?
echo "$(grep ^oom_kill /sys/fs/cgroup$cg/memory.events) status=$r" >"$2"
exit $r
SH
chmod +x "$work/capwrap.sh"
cat >"$work/state.py" <<'PY'
import json, sys
rows = [r for r in json.load(sys.stdin).get("runs", []) if r.get("id") == sys.argv[1]]
print("gone" if not rows else "%s %s" % (rows[0].get("state", ""), rows[0].get("exit_code")))
PY
total_b=$(($(awk '/MemTotal/{print $2}' /proc/meminfo) * 1024))
zram_b="$(cat /sys/block/zram0/disksize 2>/dev/null || echo 0)"

step "A  compressed swap, and nothing else"
$ozbox_bin host-guard memory status || true
swaps="$(tail -n +2 /proc/swaps)"
if echo "$swaps" | grep -q '^/dev/zram'; then pass "swap is on /dev/zram"; else fail "no zram swap (the kernel lacks the module: add linux-modules-extra-aws to the PACKER IMAGE, never to first boot)"; fi
if echo "$swaps" | grep -v '^/dev/zram' | grep -q .; then fail "swap on a disk: $(echo "$swaps" | grep -v '^/dev/zram')"; else pass "no swap on a disk"; fi
if [ "$(cat /proc/sys/vm/swappiness)" = 100 ]; then
  pass "vm.swappiness=100"
else
  fail "vm.swappiness=$(cat /proc/sys/vm/swappiness)"
fi
if grep -q '\[zstd\]' /sys/block/zram0/comp_algorithm 2>/dev/null; then pass "zstd"; else note "algorithm: $(cat /sys/block/zram0/comp_algorithm 2>/dev/null)"; fi
if systemctl is-active --quiet systemd-oomd 2>/dev/null; then
  fail "systemd-oomd is active: with swap present it would add swap-based kills of its own"
else
  pass "systemd-oomd is not active"
fi

step "B  the memory controller reaches the box user's manager"
if grep -qw memory "/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers" 2>/dev/null; then pass "memory is delegated"; else fail "memory is NOT delegated to user@$uid.service (the drop-in applies at the manager's next start)"; fi

step "C  protected scores"
sleep 35 # one turn of the 30-second timer, for a unit that restarted
for u in $sys_units; do
  pid="$(systemctl show -p MainPID --value "$u" 2>/dev/null)"
  [ -n "$pid" ] && [ "$pid" != 0 ] && echo "$u pid $pid oom_score_adj=$(cat /proc/"$pid"/oom_score_adj)"
done
tun_bad=0
for u in $usr_units; do
  pid="$(user_sctl show -p MainPID --value "$u" 2>/dev/null)"
  if [ -n "$pid" ] && [ "$pid" != 0 ]; then
    echo "$u pid $pid oom_score_adj=$(cat /proc/"$pid"/oom_score_adj)"
    case "$u" in *cloudflared*) [ "$(cat /proc/"$pid"/oom_score_adj)" = -900 ] || tun_bad=1 ;; *) [ "$(cat /proc/"$pid"/oom_score_adj)" = -500 ] || tun_bad=1 ;; esac
  fi
done
# the system tunnel runs cloudflared as a CHILD of `ozbox secrets exec`: the child must carry the unit's -900 too
if systemctl is-active --quiet ozbox-cloudflared.service 2>/dev/null; then
  cfpids=""
  while read -r p; do
    [ "$(cat /proc/"$p"/comm 2>/dev/null)" = cloudflared ] && cfpids="$cfpids $p"
  done < <(cat /sys/fs/cgroup/system.slice/ozbox-cloudflared.service/cgroup.procs 2>/dev/null)
  if [ -z "$cfpids" ]; then fail "the system tunnel is active but no cloudflared process is in its cgroup"
  else
    for p in $cfpids; do
      echo "cloudflared (system tunnel) pid $p oom_score_adj=$(cat /proc/"$p"/oom_score_adj)"
      if [ "$(cat /proc/"$p"/oom_score_adj)" = -900 ]; then
        pass "the system tunnel's cloudflared process $p is at -900"
      else
        fail "the system tunnel's cloudflared process $p is at $(cat /proc/"$p"/oom_score_adj)"
      fi
    done
  fi
else
  note "the system tunnel unit is not active (a user-level tunnel, or none): its child was not checked"
fi
if [ "$tun_bad" = 0 ]; then
  pass "the user units are at their scores (tunnel -900, IDE main -500)"
else
  fail "a user unit is not at its score"
fi
ozboxd_pid="$(systemctl show -p MainPID --value ozboxd.service)"
if [ "$(cat /proc/"$ozboxd_pid"/oom_score_adj)" = -900 ]; then
  pass "ozboxd is at -900"
else
  fail "ozboxd is at $(cat /proc/"$ozboxd_pid"/oom_score_adj)"
fi
echo "this shell (a login session) is at $(cat /proc/self/oom_score_adj): must be 0 or above, never inherited -900"
if [ "$(cat /proc/self/oom_score_adj)" -ge 0 ]; then
  pass "a login session is not protected"
else
  fail "this login session inherited a protected score"
fi
run_score="$($ozbox_bin capped -- cat /proc/self/oom_score_adj 2>/dev/null || echo ?)"
if [ "$run_score" = 300 ]; then
  pass "ozbox capped puts its command at 300"
else
  fail "ozbox capped command score: $run_score"
fi

step "D  the soft limit and OOMPolicy reach a tmux scope (and the pane really is in one)"
# shellcheck disable=SC2016 # the single quotes are deliberate: the inner shell expands these
$ozbox_bin capped -- sh -c 'cg=$(cut -d: -f3 /proc/self/cgroup); for f in memory.max memory.high memory.swap.max; do echo "$f=$(cat /sys/fs/cgroup$cg/$f)"; done'
tmux new-session -d -s memproof 'sleep 600' 2>/dev/null
pane_pid="$(tmux list-panes -t memproof -F '#{pane_pid}' 2>/dev/null | head -1)"
tcg="$(cut -d: -f3 /proc/"${pane_pid:-0}"/cgroup 2>/dev/null)"
echo "the tmux pane's cgroup: $tcg"
case "$tcg" in
  *tmux-spawn-*)
    pass "the pane runs in its own tmux-spawn- scope"
    case "$(cat "/sys/fs/cgroup$tcg/memory.high" 2>/dev/null)" in max | "") fail "the tmux scope has no soft limit (the prefix drop-in did not apply to a transient scope)" ;; *) pass "the tmux scope has the soft limit: memory.high=$(cat "/sys/fs/cgroup$tcg/memory.high")" ;; esac
    pol="$(user_sctl show "$(basename "$tcg")" -p OOMPolicy --value 2>/dev/null)"
    if [ "$pol" = continue ]; then
      pass "the tmux scope has OOMPolicy=continue"
    else
      fail "the tmux scope has OOMPolicy=$pol (a killed build would stop the whole scope: H1)"
    fi
    ;;
  *) fail "the pane is NOT in a tmux-spawn- scope ($tcg): it would inherit the SSH session's scope, and this proof would pass for the wrong reason" ;;
esac
tmux kill-session -t memproof 2>/dev/null
for u in oz-code-server.service ozbox-ide.service; do
  if user_sctl is-active --quiet "$u" 2>/dev/null; then
    if [ "$(user_sctl show "$u" -p OOMPolicy --value)" = continue ]; then
      pass "$u has OOMPolicy=continue"
    else
      fail "$u has OOMPolicy=$(user_sctl show "$u" -p OOMPolicy --value)"
    fi
  fi
done

step "E  a hog sized above the capped scope's memory + swap is killed (137, never 1) and only it"
# --max-gib 3 gives MemoryMax=3 GiB and a swap limit of the same size, so a 4 GiB hog would only be throttled and exit 0. The hog
# sizes itself from its own cgroup (memory.max + memory.swap.max + 1 GiB) with data that does not compress.
rc=0
$ozbox_bin capped --max-gib 3 -- sh "$work/capwrap.sh" "$work/hog.py" "$work/capped.out" >/dev/null 2>&1 || rc=$?
echo "capped exit status: $rc; $(cat "$work/capped.out" 2>/dev/null)"
if [ "$rc" = 137 ]; then
  pass "the hog ended with exactly 137 (killed)"
else
  fail "the hog's status was $rc (not 137: it fitted under its cap, was stopped by the scope's TERM, or the scope failed to start)"
fi
if grep -Eq 'oom_kill [1-9]' "$work/capped.out" 2>/dev/null; then
  pass "the scope counted the oom_kill"
else
  fail "the scope's memory.events shows no oom_kill"
fi
units_unchanged "after the capped hog"

step "F  an uncapped hog of incompressible data: throttled at the soft limit, a pressure incident raised, nothing killed"
inc_before="$(pressure_incidents)"
sess="$(cut -d: -f3 /proc/self/cgroup)"
high="$(cat "/sys/fs/cgroup$sess/memory.high" 2>/dev/null)"
echo "this session's cgroup $sess: memory.high=$high"
case "$high" in
  max | "") fail "this session has no soft limit (prefix drop-ins do not apply to it): the throttle cannot be shown" ;;
  *)
    # past the soft limit but short of the box: the kernel throttles and reclaims into zram, and kills nothing
    python3 "$work/hog.py" $((high + 1073741824)) 55 &
    hog=$!
    sleep 60
    wait "$hog"
    rc=$?
    if [ "$rc" = 0 ]; then
      pass "the hog was throttled, not killed (it ran to its deadline)"
    else
      fail "the hog ended with status $rc"
    fi
    ;;
esac
inc_after="$(pressure_incidents)"
echo "memory_pressure incidents: $inc_before -> $inc_after"
if [ "$inc_after" -gt "$inc_before" ]; then
  pass "a memory_pressure incident was raised (the alert path sends it to chat: check the chat now)"
else
  fail "no memory_pressure incident: PSI never crossed the threshold (see /proc/pressure/memory), or the daemon is not running"
fi
units_unchanged "after the throttled fill"

step "G  a live install through the root helper restarts nothing and reaches the box user's manager"
# What moves when the manager reloads is NOT certain: UnitsLoadFinishTimestampMonotonic is, as far as I know, set only when the
# manager starts, so a reload would leave it where it was and this step would fail on a healthy box. systemd 255 added
# UnitsLoadTimestampMonotonic (the last load, reloads included): use it when it exists, and print both so the notes show which
# one moved. Before the run, confirm by hand on the box: read the property, `systemctl --user daemon-reload`, read it again.
sdver="$(systemctl --version | awk 'NR==1{print $2}')"
load_ts() {
  local v=""
  if [ "${sdver:-0}" -ge 255 ]; then v="$(user_sctl show -p UnitsLoadTimestampMonotonic --value 2>/dev/null)"; fi
  [ -n "$v" ] || v="$(user_sctl show -p UnitsLoadFinishTimestampMonotonic --value 2>/dev/null)"
  echo "$v"
}
echo "systemd $sdver: UnitsLoadTimestampMonotonic=$(user_sctl show -p UnitsLoadTimestampMonotonic --value 2>/dev/null) UnitsLoadFinishTimestampMonotonic=$(user_sctl show -p UnitsLoadFinishTimestampMonotonic --value 2>/dev/null)"
ctx_before="$(load_ts)"
pids_before="$(snap | sort)"
out="$(/usr/local/bin/ozbox-admin-request host-guard memory install 2>&1)"; rc=$?
echo "$out" | head -4
if [ "$rc" = 0 ]; then
  pass "the helper installed the memory guard"
else
  fail "the helper refused: $(echo "$out" | head -2 | tr '\n' ' ')"
fi
sleep 3
ctx_after="$(load_ts)"
if [ -n "$ctx_before" ] && [ -n "$ctx_after" ] && [ "$ctx_after" -gt "$ctx_before" ]; then pass "the box user's manager was reloaded by the live install (M1)"; else fail "the box user's manager was NOT reloaded by the live install (load time $ctx_before -> $ctx_after): a tmux scope made now would miss the soft limit"; fi
if [ "$pids_before" = "$(snap | sort)" ]; then
  pass "no service restarted"
else
  fail "a service restarted during the live install"
fi
tmux new-session -d -s memproof 'sleep 600' 2>/dev/null
tcg="$(cut -d: -f3 /proc/"$(tmux list-panes -t memproof -F '#{pane_pid}' 2>/dev/null | head -1)"/cgroup 2>/dev/null)"
case "$(cat "/sys/fs/cgroup$tcg/memory.high" 2>/dev/null)" in max | "") fail "a pane opened after the live install has no soft limit" ;; *) pass "a pane opened after the live install has the soft limit" ;; esac
tmux kill-session -t memproof 2>/dev/null
out="$(/usr/local/bin/ozbox-admin-request host-guard helper refresh 2>&1)"; rc=$?
echo "$out" | head -3
echo "root helper revision on disk: $(grep -m1 '^helper_rev=' /usr/local/sbin/ozbox-admin.sh); refresh log: $(tail -n 2 /var/log/ozbox-helper-refresh.log 2>/dev/null | tr '\n' '|')"
# the refresh installs a strictly newer revision only; on a box whose helper is already this release's, the answer is "already"
# (rc 0) and an older program's refusal is rc != 0 with "was not changed": neither rolls the helper back
if [ "$rc" = 0 ] && grep -q 'helper refresh' /usr/local/sbin/ozbox-admin.sh; then
  pass "the root helper was refreshed from the installed release, and carries the refresh itself"
else
  fail "the helper refresh did not work: $(echo "$out" | head -2 | tr '\n' ' ')"
fi
out="$(/usr/local/bin/ozbox-admin-request host-guard memory install 2>&1)"
if echo "$out" | grep -q 'status=ok'; then
  pass "the refreshed helper still installs the guard"
else
  fail "the refreshed helper could not install the guard: $(echo "$out" | head -2 | tr '\n' ' ')"
fi

step "H  the secrets service: no swap at all, and its protected score"
swapmax="$(cat /sys/fs/cgroup/system.slice/ozbox-secrets.service/memory.swap.max 2>/dev/null)"
if [ "$swapmax" = 0 ]; then
  pass "ozbox-secrets.service has memory.swap.max = 0"
else
  fail "ozbox-secrets.service memory.swap.max = ${swapmax:-unreadable} (its pages could reach zram)"
fi
spid="$(systemctl show -p MainPID --value ozbox-secrets.service)"
if [ "$(cat /proc/"$spid"/oom_score_adj 2>/dev/null)" = -900 ]; then
  pass "ozbox-secrets.service is at -900"
else
  fail "ozbox-secrets.service is at $(cat /proc/"$spid"/oom_score_adj 2>/dev/null)"
fi

step "I  an IDE terminal's processes are raised to 200; the IDE's main process and its editor server stay at -500"
ide_unit_i=""
for u in oz-code-server.service ozbox-ide.service; do user_sctl is-active --quiet "$u" 2>/dev/null && ide_unit_i="$u" && break; done
tpid=""
for p in $(pgrep -f 'sleep 4321'); do
  # the sleep must really be in the IDE's cgroup (a tmux pane's sleep is also at 200, and would pass for the wrong reason)
  if grep -q "$ide_unit_i" /proc/"$p"/cgroup 2>/dev/null; then tpid="$p"; break; fi
done
if [ -z "$ide_unit_i" ]; then
  fail "no web IDE unit is running"
elif [ -z "$tpid" ]; then
  fail "no 'sleep 4321' found INSIDE the IDE's cgroup ($ide_unit_i): open a terminal in the web IDE, run \`sleep 4321\` in it, and run this again"
else
  pass "'sleep 4321' (pid $tpid) is in the IDE's cgroup"
  sleep 35 # one turn of the timer
  if [ "$(cat /proc/"$tpid"/oom_score_adj)" = 200 ]; then
    pass "a process of an IDE terminal is at 200, the same as a tmux pane"
  else
    fail "an IDE terminal's process is at $(cat /proc/"$tpid"/oom_score_adj): a build there would be picked AFTER the agent (M3)"
  fi
fi
for u in oz-code-server.service ozbox-ide.service; do
  pid="$(user_sctl show -p MainPID --value "$u" 2>/dev/null)"
  if [ -n "$pid" ] && [ "$pid" != 0 ]; then
    if [ "$(cat /proc/"$pid"/oom_score_adj)" = -500 ]; then
      pass "$u main process is at -500"
    else
      fail "$u main process is at $(cat /proc/"$pid"/oom_score_adj)"
    fi
    echo "the process tree under $u (for your notes):"
    ps -o pid,ppid,oom_score_adj,args --forest -u "$(id -un)" 2>/dev/null | head -40
    # the editor server: a direct child of the main process, node, with no --type= argument (code-server's main process is a
    # wrapper that starts it). When there is no such child the main process IS the server and was checked above.
    server=""
    for c in $(pgrep -P "$pid"); do
      tr '\0' ' ' </proc/"$c"/cmdline 2>/dev/null | grep -q -- '--type=' && continue
      case "$(basename "$(readlink /proc/"$c"/exe 2>/dev/null)")" in node | code-server) server="$c"; break ;; esac
    done
    if [ -n "$server" ]; then
      if [ "$(cat /proc/"$server"/oom_score_adj)" = -500 ]; then
        pass "$u editor server (pid $server, the main process's child) is at -500"
      else
        fail "$u editor server (pid $server) is at $(cat /proc/"$server"/oom_score_adj): the process that must survive is unprotected (N3)"
      fi
    else
      note "$u has no separate editor-server child: its main process is the server (checked above)"
    fi
  fi
done

step "J  a daemon run that passes its default cap dies alone; ozboxd keeps its main process"
ozboxd_before="$(systemctl show -p MainPID --value ozboxd.service)"
sock=/run/ozboxd/ozboxd.sock
# the hog sizes itself above THIS run's own memory.max + memory.swap.max (a hog that fits under them is throttled, never killed),
# through the wrapper that reads the scope's oom_kill counter before the scope goes away
body="$(python3 -c 'import json,sys; print(json.dumps({"argv":["sh",sys.argv[1],sys.argv[2],sys.argv[3]],"labels":{"proof":"memory-guard"}}))' "$work/capwrap.sh" "$work/hog.py" "$work/run.out")"
resp="$(curl -s --unix-socket "$sock" -X POST -H 'content-type: application/json' -d "$body" http://localhost/v1/runs)"
rid="$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' 2>/dev/null)"
if [ -z "$rid" ]; then
  fail "the daemon did not start the run: $resp"
else
  for _ in $(seq 1 320); do
    state="$(curl -s --unix-socket "$sock" http://localhost/v1/runs 2>/dev/null | python3 "$work/state.py" "$rid" 2>/dev/null)"
    case "$state" in running* | queued*) sleep 0.5 ;; *) break ;; esac
  done
  echo "the run ended: $state"
  case "$state" in
    "" | running* | queued*) fail "the run did not end within its deadline: $state" ;;
    *" 137") pass "the run was killed (137) inside its own scope" ;;
    *) fail "the run ended with '$state', not 137: it fitted under its cap, or the scope stopped the wrapper" ;;
  esac
  echo "the run's scope said: $(cat "$work/run.out" 2>/dev/null)"
  if grep -Eq 'oom_kill [1-9]' "$work/run.out" 2>/dev/null; then
    pass "the run's scope counted an oom_kill"
  else
    fail "the run's scope shows no oom_kill (or the wrapper left no record: the run may not have been able to write $work/run.out)"
  fi
fi
if [ "$(systemctl show -p MainPID --value ozboxd.service)" = "$ozboxd_before" ]; then
  pass "ozboxd kept its main process"
else
  fail "ozboxd was restarted by a run's kill (OOMPolicy of the daemon's unit)"
fi
units_unchanged "after the daemon run"

step "K  THE INCIDENT: an uncapped hog in a tmux pane under a real out-of-memory kill"
# The guard's soft limit would throttle this hog before the box ran out (step F shows it does), which is the first line. The
# incident needs the second one: so for THIS scope only the soft limit is lifted, and the box really runs out of memory.
want=$((total_b + 2147483648))
cat >"$work/incident.sh" <<'SH'
#!/bin/sh
# $1 = hog.py, $2 = bytes, $3 = where to write the sentinel's pid and the hog's status
sleep 600 &
echo $! >"$3.sentinel"
python3 "$1" "$2" 170
echo $? >"$3.status"
sleep 600
SH
chmod +x "$work/incident.sh"
tmux new-session -d -s memincident "$work/incident.sh" "$work/hog.py" "$want" "$work/inc"
sleep 3
pane_pid="$(tmux list-panes -t memincident -F '#{pane_pid}' 2>/dev/null | head -1)"
icg="$(cut -d: -f3 /proc/"${pane_pid:-0}"/cgroup 2>/dev/null)"
case "$icg" in
  *tmux-spawn-*)
    pass "the incident pane is in its own tmux-spawn- scope ($(basename "$icg"))"
    user_sctl set-property --runtime "$(basename "$icg")" MemoryHigh=infinity 2>/dev/null || note "could not lift the soft limit on this scope: the throttle may stop the hog before the box runs out"
    for _ in $(seq 1 200); do [ -s "$work/inc.status" ] && break; sleep 1; done
    st="$(cat "$work/inc.status" 2>/dev/null)"
    echo "the hog's status: ${st:-never ended}"
    if [ "$st" = 137 ]; then
      pass "the kernel killed the hog (137)"
    else
      fail "the hog's status was '${st:-none}': the box did not reach an out-of-memory kill, so this step proved nothing (or something else was the victim)"
    fi
    spid="$(cat "$work/inc.sentinel" 2>/dev/null)"
    if [ -n "$spid" ] && kill -0 "$spid" 2>/dev/null; then
      pass "the sentinel in the SAME pane is alive (the agent beside a killed build survives)"
    else
      fail "the sentinel in the pane died with the hog: the whole scope was stopped (H1)"
    fi
    if user_sctl is-active --quiet "$(basename "$icg")"; then
      pass "the pane's scope is still active"
    else
      fail "the pane's scope was stopped by systemd"
    fi
    ;;
  *) fail "the incident pane is not in a tmux-spawn- scope ($icg)" ;;
esac
tmux kill-session -t memincident 2>/dev/null
units_unchanged "after the incident"
ssm_alive "after the incident"

echo "-- the same inside the web IDE's own cgroup"
ide_unit="$(echo "$before" | grep -o 'usr:\(oz-code-server\|ozbox-ide\)\.service' | head -1 | cut -d: -f2)"
ide_main="$(user_sctl show -p MainPID --value "$ide_unit" 2>/dev/null)"
if [ -z "$ide_unit" ]; then
  fail "no web IDE unit to test"
else
  # a process moved into the IDE's cgroup (the box user owns it: the delegated subtree), from a scope under the user manager
  idecg="/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/app.slice/$ide_unit"
  # shellcheck disable=SC2016 # the single quotes are deliberate: the inner shell expands these
  systemd-run --user --scope --quiet -- bash -c '
    sleep 600 & s=$!
    echo $s >"$3.idesentinel"
    if ! echo $s >"$1/cgroup.procs" 2>/dev/null; then echo "cannot-enter" >"$3.idestatus"; exit 0; fi
    python3 "$2" "$4" 170 &
    h=$!
    echo $h >"$1/cgroup.procs" 2>/dev/null
    wait $h; echo $? >"$3.idestatus"
  ' bash "$idecg" "$work/hog.py" "$work/inc" "$want"
  ist="$(cat "$work/inc.idestatus" 2>/dev/null)"
  sentinel_ide="$(cat "$work/inc.idesentinel" 2>/dev/null)"
  echo "the IDE-cgroup hog's status: ${ist:-none}"
  case "$ist" in
    cannot-enter) fail "could not move a process into the IDE's cgroup (no write access): the IDE-terminal case was not exercised" ;;
    137) pass "the kernel killed the hog inside the IDE's cgroup (137)" ;;
    *) fail "the IDE-cgroup hog's status was '${ist:-none}': no out-of-memory kill happened" ;;
  esac
  if [ "$(user_sctl show -p MainPID --value "$ide_unit")" = "$ide_main" ] && user_sctl is-active --quiet "$ide_unit"; then
    pass "$ide_unit kept its main process (OOMPolicy=continue)"
  else
    fail "$ide_unit was stopped or restarted by a kill inside its cgroup (H1)"
  fi
  if [ -n "$sentinel_ide" ] && kill -0 "$sentinel_ide" 2>/dev/null; then
    pass "the sentinel in the IDE's cgroup is alive"
  else
    fail "the sentinel in the IDE's cgroup died"
  fi
fi
units_unchanged "after the IDE incident"

step "L  after every kill: the units, the SSM agent, nothing failed"
ssm_alive "at the end"
failed="$(systemctl --failed --no-legend 2>/dev/null | grep -i 'ozbox\|snap.amazon' | head -3)"
if [ -z "$failed" ]; then
  pass "no unit of the box is in a failed state"
else
  fail "failed units: $failed"
fi
user_failed="$(user_sctl --failed --no-legend 2>/dev/null | head -3)"
if [ -z "$user_failed" ]; then
  pass "no unit of the box user's manager is failed"
else
  fail "failed user units: $user_failed"
fi

step "M  timings for your notes (the benchmark shape is 4 vCPU / 8 GiB / 40 GB; S is 4 / 16, so label this as NOT comparable)"
echo "memory $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo); cpus $(nproc); swap in use: $(awk 'NR>1{u+=$4} END{print u+0}' /proc/swaps) KiB; zram disksize $zram_b"
( time (cd "$(mktemp -d)" && git init -q . && for i in $(seq 1 200); do echo "$i" >f"$i"; done && git add -A && git -c user.email=a@b -c user.name=x commit -qm x) ) 2>&1 | tail -3
echo "the release gate also needs, on the 4 vCPU / 8 GiB shape once that size exists: the Mastra cold install, the Better-Auth build and the OpenClaw build, and STREAM Triad, each with the guard on and with it off (peak memory.peak and wall time of each). Until that size exists, S numbers are labelled not comparable."

echo
if [ "$fails" = 0 ]; then echo "ALL STEPS PASSED"; else echo "$fails STEP(S) FAILED"; fi
exit "$([ "$fails" = 0 ] && echo 0 || echo 1)"
