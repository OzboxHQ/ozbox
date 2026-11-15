#!/usr/bin/env bash
# Oz Box benchmark suite, first version ("ozbox-subset-v1"). Runs ON a box, as the box user, and writes one result file.
#
# NOT part of CI. It needs a real box and costs money; it is a release step (docs/releasing.md, "The benchmark gate").
#
# What it is: a documented SUBSET of what the starslingdev/hpc-sandbox-benchmarks leaderboard measures, with Oz Box's own
# parameters. Its numbers are NOT the leaderboard's numbers until the upstream adapter exists; never publish
# them as comparable to it. They are comparable to this suite's own earlier runs on the same shape, which is what the gate
# uses them for.
#
# Honesty rules, enforced here:
#   - an item whose tool or pin is missing is "unsupported" with the reason, never 0;
#   - an item that ran and failed is "failed" with the reason, never 0;
#   - a box that is not the benchmark shape is labelled so ("comparable": false) and the gate refuses it.
#
# Usage (on the box):
#   scripts/benchmark/suite.sh --out results.json [--variant cold|warm] [--guard on|off|unknown] [--runs 3]
#
#   --variant  cold: a freshly created box, nothing cached. warm: a resumed or image-cached box. A warm result is a separate
#              variant and is never compared with, or passed off as, a cold one.
#   --guard    whether the box memory guard (ADR 0045, caps heavy runs at RAM minus RAM/8) was on. Run the suite with it on
#              AND off: it changes what a heavy run may use on an 8 GiB box.
#   --runs     repetitions on this box (default 3); the value is the median. A leaderboard-grade result is the median over
#              several independently created boxes: collect one file per box and `gate.mjs merge` them.
#
# Pins and tools (environment; an unset one makes its item "unsupported"):
#   BENCH_MASTRA_REPO, BENCH_MASTRA_REF            clone URL and pinned commit of the repo for "Mastra: cold install"
#   BENCH_BETTER_AUTH_REPO, BENCH_BETTER_AUTH_REF  the same for "Better-Auth: build"
#   BENCH_INSTALL_CMD   default "pnpm install --frozen-lockfile"      BENCH_BUILD_CMD   default "pnpm build"
#   BENCH_GIT_REPO, BENCH_GIT_REF                  a repo to run the Git common operations on (cloned, then timed locally)
#   BENCH_STREAM_BIN    a compiled STREAM binary, or BENCH_STREAM_SRC a stream.c to compile with gcc
#   BENCH_WORK_DIR      scratch area (default /work/.bench); it is removed afterwards
# fio must be installed for the disk item.
set -uo pipefail

OUT=""; VARIANT="cold"; GUARD="unknown"; RUNS=3
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?--out needs a path}"; shift 2 ;;
    --variant) VARIANT="${2:?}"; shift 2 ;;
    --guard) GUARD="${2:?}"; shift 2 ;;
    --runs) RUNS="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "suite.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$OUT" ] || { echo "suite.sh: --out is required" >&2; exit 2; }
case "$VARIANT" in cold|warm) ;; *) echo "suite.sh: --variant is cold or warm" >&2; exit 2 ;; esac
case "$GUARD" in on|off|unknown) ;; *) echo "suite.sh: --guard is on, off or unknown" >&2; exit 2 ;; esac
case "$RUNS" in ''|*[!0-9]*|0) echo "suite.sh: --runs must be a positive number" >&2; exit 2 ;; esac

WORK="${BENCH_WORK_DIR:-/work/.bench}"
INSTALL_CMD="${BENCH_INSTALL_CMD:-pnpm install --frozen-lockfile}"
BUILD_CMD="${BENCH_BUILD_CMD:-pnpm build}"
mkdir -p "$WORK" || { echo "suite.sh: cannot create $WORK" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", b-a}'; }
jstr() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n\t' '  ' | cut -c1-300; }
median() { sort -g | awk '{a[NR]=$1} END{if(NR==0)exit 1; if(NR%2)print a[(NR+1)/2]; else printf "%.3f\n",(a[NR/2]+a[NR/2+1])/2}'; }

METRICS=""
# emit ID LABEL UNIT DIRECTION STATUS VALUE N_OK N_TOTAL REASON
emit() {
  local v="null"; [ -n "$6" ] && v="$6"
  local item
  item=$(printf '{"id":"%s","label":"%s","unit":"%s","direction":"%s","status":"%s","value":%s,"n_ok":%s,"n_total":%s,"reason":"%s"}' \
    "$1" "$2" "$3" "$4" "$5" "$v" "$7" "$8" "$(jstr "$9")")
  METRICS="${METRICS:+$METRICS,}$item"
}
unsupported() { emit "$1" "$2" "$3" "$4" unsupported "" 0 0 "$5"; }

# measure ID LABEL UNIT DIRECTION -- fn : run fn RUNS times; fn prints one number (or fails with a reason on stderr).
measure() {
  local id="$1" label="$2" unit="$3" dir="$4"; shift 5
  local vals="" ok=0 reason="" i out
  for i in $(seq 1 "$RUNS"); do
    if out=$("$@" 2>"$WORK/err"); then
      vals="$vals$out"$'\n'; ok=$((ok+1))
    else
      reason="run $i: $(head -c 200 "$WORK/err")"
    fi
  done
  if [ "$ok" -eq 0 ]; then
    emit "$id" "$label" "$unit" "$dir" failed "" 0 "$RUNS" "${reason:-failed}"
  else
    local med; med=$(printf '%s' "$vals" | grep -v '^$' | median)
    if [ "$ok" -lt "$RUNS" ]; then
      emit "$id" "$label" "$unit" "$dir" partial "$med" "$ok" "$RUNS" "$reason"
    else
      emit "$id" "$label" "$unit" "$dir" ok "$med" "$ok" "$RUNS" ""
    fi
  fi
}

# ---- the box's shape: what the leaderboard calls resource-matched is 4 vCPU, RAM within 10% of 8 GiB ----
VCPUS=$(nproc)
MEM_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
MEM_GIB=$(awk -v k="$MEM_KB" 'BEGIN{printf "%.2f", k/1048576}')
WORK_GB=$(df -BG --output=size /work 2>/dev/null | tail -1 | tr -dc '0-9')
REASONS=""
[ "$VCPUS" -eq 4 ] || REASONS="${REASONS:+$REASONS; }vCPUs are $VCPUS, not 4"
awk -v m="$MEM_GIB" 'BEGIN{exit !(m>=8*0.9 && m<=8*1.1)}' || REASONS="${REASONS:+$REASONS; }memory is $MEM_GIB GiB, not within 10% of 8"
{ [ -n "$WORK_GB" ] && [ "$WORK_GB" -ge 36 ] && [ "$WORK_GB" -le 44 ]; } || REASONS="${REASONS:+$REASONS; }/work is ${WORK_GB:-unknown} GB, not about 40"
if [ -z "$REASONS" ]; then COMPARABLE=true; else COMPARABLE=false; fi

# ---- items ----
rand_write() {
  local f="$WORK/fio.dat"
  fio --name=randwrite --filename="$f" --rw=randwrite --bs=4k --direct=1 --ioengine=libaio --iodepth=32 \
      --size=1G --runtime=30 --time_based --group_reporting --output-format=json >"$WORK/fio.json" || return 1
  rm -f "$f"
  # The write section's bytes per second, reported as MB/s (10^6 bytes), as the leaderboard prints it. The read section
  # comes first in fio's JSON and is empty, so only the line after "write" counts.
  awk '/"write"[[:space:]]*:/{w=1} w && /"bw_bytes"/{gsub(/[^0-9.]/,"",$0); printf "%.2f\n", $0/1000000; exit}' "$WORK/fio.json" | grep . || { echo "no bandwidth in fio output" >&2; return 1; }
}
if command -v fio >/dev/null 2>&1; then
  measure fio_randwrite_4k_direct "rand write 4KB O_DIRECT" "MB/s" higher -- rand_write
else
  unsupported fio_randwrite_4k_direct "rand write 4KB O_DIRECT" "MB/s" higher "fio is not installed on this box"
fi

triad() {
  local bin="${BENCH_STREAM_BIN:-}"
  if [ -z "$bin" ]; then bin="$WORK/stream"; gcc -O3 -fopenmp -DSTREAM_ARRAY_SIZE=80000000 -o "$bin" "$BENCH_STREAM_SRC" || return 1; fi
  "$bin" | awk '/^Triad:/{print $2}' | grep . || { echo "no Triad line in STREAM output" >&2; return 1; }
}
if [ -n "${BENCH_STREAM_BIN:-}" ] || { [ -n "${BENCH_STREAM_SRC:-}" ] && command -v gcc >/dev/null 2>&1; }; then
  measure stream_triad "STREAM Triad" "MB/s" higher -- triad
else
  unsupported stream_triad "STREAM Triad" "MB/s" higher "no STREAM binary (BENCH_STREAM_BIN) or source with gcc (BENCH_STREAM_SRC)"
fi

# clone REPO REF DIR
clone_pinned() { git clone --quiet "$1" "$3" && git -C "$3" checkout --quiet "$2"; }

mastra_install() {
  local d="$WORK/mastra.$$.$RANDOM"
  clone_pinned "$BENCH_MASTRA_REPO" "$BENCH_MASTRA_REF" "$d" || return 1
  # cold: an empty package store and cache, so nothing from an earlier run helps.
  local s e; export npm_config_store_dir="$d/.store" npm_config_cache="$d/.cache" PNPM_HOME="$d/.pnpm"
  s=$(now); (cd "$d" && eval "$INSTALL_CMD" >"$WORK/install.log" 2>&1) || { tail -c 200 "$WORK/install.log" >&2; rm -rf "$d"; return 1; }
  e=$(now); rm -rf "$d"; elapsed "$s" "$e"
}
if [ -n "${BENCH_MASTRA_REPO:-}" ] && [ -n "${BENCH_MASTRA_REF:-}" ]; then
  measure mastra_cold_install "Mastra: cold install" "s" lower -- mastra_install
else
  unsupported mastra_cold_install "Mastra: cold install" "s" lower "BENCH_MASTRA_REPO and BENCH_MASTRA_REF (the pinned commit) are not set"
fi

better_auth_build() {
  local d="$WORK/ba.$$.$RANDOM" s e
  clone_pinned "$BENCH_BETTER_AUTH_REPO" "$BENCH_BETTER_AUTH_REF" "$d" || return 1
  export npm_config_store_dir="$d/.store" npm_config_cache="$d/.cache" PNPM_HOME="$d/.pnpm"
  (cd "$d" && eval "$INSTALL_CMD" >"$WORK/install.log" 2>&1) || { tail -c 200 "$WORK/install.log" >&2; rm -rf "$d"; return 1; }
  s=$(now); (cd "$d" && eval "$BUILD_CMD" >"$WORK/build.log" 2>&1) || { tail -c 200 "$WORK/build.log" >&2; rm -rf "$d"; return 1; }
  e=$(now); rm -rf "$d"; elapsed "$s" "$e"
}
if [ -n "${BENCH_BETTER_AUTH_REPO:-}" ] && [ -n "${BENCH_BETTER_AUTH_REF:-}" ]; then
  measure better_auth_build "Better-Auth: build" "s" lower -- better_auth_build
else
  unsupported better_auth_build "Better-Auth: build" "s" lower "BENCH_BETTER_AUTH_REPO and BENCH_BETTER_AUTH_REF (the pinned commit) are not set"
fi

git_ops() {
  local d="$WORK/git.$$.$RANDOM" s e
  git clone --quiet "$BENCH_GIT_REPO" "$d" && git -C "$d" checkout --quiet "$BENCH_GIT_REF" || return 1
  cd "$d" || return 1
  git config user.email bench@example.invalid; git config user.name bench
  s=$(now)
  git status --porcelain >/dev/null && git log --oneline >/dev/null && git diff HEAD~1 --stat >/dev/null \
    && git branch bench-b && git checkout --quiet bench-b && echo bench >bench.txt && git add -A \
    && git commit --quiet -m bench && git checkout --quiet - && git blame -- "$(git ls-files | head -1)" >/dev/null \
    || { rm -rf "$d"; return 1; }
  e=$(now); cd "$WORK" && rm -rf "$d"; elapsed "$s" "$e"
}
if [ -n "${BENCH_GIT_REPO:-}" ] && [ -n "${BENCH_GIT_REF:-}" ]; then
  measure git_common_ops "Git common operations" "s" lower -- git_ops
else
  unsupported git_common_ops "Git common operations" "s" lower "BENCH_GIT_REPO and BENCH_GIT_REF are not set"
fi

# Spawn time, resume time and USD per hour are not measured on the box: lifecycle.sh measures them from the computer that
# creates it, and gate.mjs merges the two files. Listed here so a result without them says so.
unsupported spawn "Spawn (create to ready)" "s" lower "measured by lifecycle.sh from the creating computer"
unsupported resume "Resume (resume to ready)" "s" lower "measured by lifecycle.sh from the creating computer"
unsupported usd_per_hour "USD per hour" "USD" lower "given to lifecycle.sh by the person running it"

IMAGE=$(cat /etc/ozbox-image-version 2>/dev/null || echo unknown)
cat >"$OUT" <<JSON
{"schema":1,"suite":"ozbox-subset-v1","variant":"$VARIANT","guard":"$GUARD","runs":$RUNS,
 "created_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","image":"$(jstr "$IMAGE")",
 "shape":{"vcpus":$VCPUS,"mem_gib":$MEM_GIB,"work_gb":${WORK_GB:-null}},
 "comparable":$COMPARABLE,"comparable_reasons":"$(jstr "$REASONS")",
 "metrics":[$METRICS]}
JSON
echo "suite.sh: wrote $OUT (variant $VARIANT, guard $GUARD, comparable $COMPARABLE)"
