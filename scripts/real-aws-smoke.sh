#!/usr/bin/env bash
# Real-AWS smoke test: builds the isolated network, runs one S box through its whole life and tears everything down.
#
#   create -> verify -> pause -> resume -> grow the disk (and check the filesystem grew) -> snapshot -> destroy
#   -> destroy the network -> list anything still tagged ozbox-managed (must be none)
#
# It creates REAL, BILLED resources (an EC2 instance and a NAT gateway bill by the hour; the run takes about 20 minutes),
# so it refuses to run unless you say so twice:
#
#   OZBOX_REAL_SMOKE=1 scripts/real-aws-smoke.sh --profile <aws-profile> [--region us-east-1] [--image ami-...]
#       prints every step and changes nothing (the default)
#   OZBOX_REAL_SMOKE=1 scripts/real-aws-smoke.sh --profile <aws-profile> --execute
#       runs it for real
#
# Needs: aws (v2) with the Session Manager plugin, tofu, ssh, ssh-keygen, and an ozbox binary (cargo build -p ozbox-cli).
# The profile needs the permissions in infra/aws/operator-policy.json. Nothing is written to your ~/.ssh or your ozbox
# config: both live in a temporary directory that is removed at the end.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE=""
REGION="us-east-1"
IMAGE=""
OZBOX="${OZBOX_BIN:-$ROOT/target/debug/ozbox}"
EXECUTE=0

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --region) REGION="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --ozbox) OZBOX="${2:-}"; shift 2 ;;
    --execute) EXECUTE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "${OZBOX_REAL_SMOKE:-}" != "1" ]]; then
  echo "refusing to run: this creates real, billed cloud resources. Set OZBOX_REAL_SMOKE=1 to say you mean it." >&2
  exit 2
fi
if [[ -z "$PROFILE" ]]; then
  echo "refusing to run: pass --profile <aws-profile> (an explicit profile, never the ambient credentials)." >&2
  exit 2
fi
if [[ ! "$PROFILE" =~ ^[A-Za-z0-9._@-]+$ || ! "$REGION" =~ ^[a-z0-9-]+$ ]]; then
  echo "refusing to run: the profile and region must be plain words." >&2
  exit 2
fi

STAMP="$(date +%m%d%H%M%S)"
RUN_ID="smoke-$STAMP"
BOX="$RUN_ID"
NETWORK_DIR="$ROOT/infra/tofu/modules/aws-network"
WORK=""
KEY_SSH_DIR=""
NETWORK_UP=0
BOX_UP=0
FAILED=0
TIMINGS=()

export AWS_PROFILE="$PROFILE"
export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"
export AWS_PAGER=""

awsx() { aws --profile "$PROFILE" --region "$REGION" "$@"; }

say() { printf '%s\n' "$*"; }

# A timed step. In a dry run it only prints the command.
step() {
  local label="$1" start end
  shift
  say "== $label"
  if [[ "$EXECUTE" != "1" ]]; then
    say "  [dry-run] $*"
    return 0
  fi
  start="$(date +%s)"
  if "$@"; then
    end="$(date +%s)"
    TIMINGS+=("$(printf '%-52s %5ss' "$label" "$((end - start))")")
  else
    end="$(date +%s)"
    TIMINGS+=("$(printf '%-52s %5ss  FAILED' "$label" "$((end - start))")")
    FAILED=1
    say "FAILED: $label" >&2
    return 1
  fi
}

# A check: the run is marked failed when it does not hold, but the run carries on so everything is torn down.
check() {
  local what="$1"
  shift
  if [[ "$EXECUTE" != "1" ]]; then
    say "  [dry-run] check: $what"
    return 0
  fi
  if "$@"; then
    say "  ok: $what"
  else
    say "  FAILED: $what" >&2
    FAILED=1
  fi
  return 0
}

retry() {
  local tries="$1" pause="$2" i
  shift 2
  for ((i = 1; i <= tries; i++)); do
    if "$@"; then
      return 0
    fi
    sleep "$pause"
  done
  return 1
}

identity_ok() { awsx sts get-caller-identity --query Account --output text >/dev/null; }

box_instance_id() {
  awsx ec2 describe-instances \
    --filters "Name=tag:ozbox-box,Values=$BOX" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text
}

# One field of the box's instance description (a JMESPath query), as text.
instance_field() { awsx ec2 describe-instances --instance-ids "$(box_instance_id)" --query "$1" --output text; }

# Push the dedicated key (valid for 60 seconds), then run one command on the box over Session Manager SSH.
box_ssh() {
  OZBOX_SSH_DIR="$KEY_SSH_DIR" "$OZBOX" connect "$BOX" --ssh --push-key >/dev/null
  ssh -i "$KEY_SSH_DIR/ozbox_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts" \
    -o ConnectTimeout=30 \
    -o "ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region $REGION --profile $PROFILE" \
    "ozbox@$(box_instance_id)" -- "$@"
}

box_ssh_contains() {
  local out
  out="$(box_ssh "$1" 2>/dev/null || true)"
  [[ "$out" == *"$2"* ]]
}

ssm_online() {
  local st
  st="$(awsx ssm describe-instance-information --filters "Key=InstanceIds,Values=$(box_instance_id)" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
  [[ "$st" == "Online" ]]
}

ssh_ready() { box_ssh true >/dev/null 2>&1; }

work_gib() { box_ssh "df -B1G --output=size /work | tail -n 1 | tr -d ' G'"; }

work_at_least() {
  local n
  n="$(work_gib 2>/dev/null || echo 0)"
  [[ "$n" =~ ^[0-9]+$ && "$n" -ge "$1" ]]
}

no_public_ip() {
  local ip
  ip="$(instance_field 'Reservations[].Instances[].PublicIpAddress')"
  [[ -z "$ip" || "$ip" == "None" ]]
}

no_ingress_rules() {
  local sg n
  sg="$(instance_field 'Reservations[].Instances[].SecurityGroups[].GroupId')"
  [[ -n "$sg" ]] || return 1
  # shellcheck disable=SC2086 # one or more group ids, separated by whitespace
  n="$(awsx ec2 describe-security-groups --group-ids $sg --query 'length(SecurityGroups[].IpPermissions[])' --output text)"
  [[ "$n" == "0" ]]
}

imds_v2_required() { [[ "$(instance_field 'Reservations[].Instances[].MetadataOptions.HttpTokens')" == "required" ]]; }

instance_stopped() { [[ "$(instance_field 'Reservations[].Instances[].State.Name')" == "stopped" ]]; }

sshd_loopback_only() {
  local listeners
  listeners="$(box_ssh "ss -H -ltn 'sport = :22' | awk '{print \$4}'")"
  [[ -n "$listeners" ]] && ! grep -Eq '^(0\.0\.0\.0|\*|\[::\]):' <<<"$listeners"
}

snapshot_exists() {
  local n
  n="$(awsx ec2 describe-snapshots --owner-ids self --filters "Name=tag:ozbox-box,Values=$BOX" \
    --query 'length(Snapshots)' --output text)"
  [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 ]]
}

verify_box() {
  check "no public IP address" no_public_ip
  check "zero ingress rules on the security group" no_ingress_rules
  check "IMDSv2 is required" imds_v2_required
  check "Session Manager reports the box online" retry 36 5 ssm_online
  check "SSH over Session Manager works with a pushed key" retry 60 5 ssh_ready
  check "cloud-init is done" box_ssh_contains "cloud-init status --wait" "done"
  check "/work is its own ext4 mount" box_ssh_contains "findmnt -n -o FSTYPE /work" "ext4"
  check "/work is about 20 GB" work_at_least 18
  check "sshd listens on loopback only" sshd_loopback_only
}

summary() {
  if [[ "${#TIMINGS[@]}" -gt 0 ]]; then
    say ""
    say "Timings"
    printf '  %s\n' "${TIMINGS[@]}"
  fi
}

list_leftovers() {
  {
    awsx resourcegroupstaggingapi get-resources --tag-filters "Key=ozbox-managed,Values=true" "Key=smoke-run,Values=$RUN_ID" \
      --query 'ResourceTagMappingList[].ResourceARN' --output text
    awsx resourcegroupstaggingapi get-resources --tag-filters "Key=ozbox-box,Values=$BOX" \
      --query 'ResourceTagMappingList[].ResourceARN' --output text
  } | tr '\t' '\n' | sed '/^$/d' | sort -u
}

no_leftovers() {
  local found
  found="$(list_leftovers)"
  if [[ -n "$found" ]]; then
    local line
    while IFS= read -r line; do
      say "    still tagged ozbox-managed: $line" >&2
    done <<<"$found"
    return 1
  fi
}

teardown_box() {
  "$OZBOX" -y destroy "$BOX" --no-final-snapshot
  BOX_UP=0
}

delete_snapshots() {
  local raw id
  local -a ids
  raw="$(awsx ec2 describe-snapshots --owner-ids self --filters "Name=tag:ozbox-box,Values=$BOX" \
    --query 'Snapshots[].SnapshotId' --output text)"
  [[ -n "$raw" ]] || return 0
  read -r -a ids <<<"$raw"
  for id in "${ids[@]}"; do
    awsx ec2 delete-snapshot --snapshot-id "$id"
  done
}

network_apply() {
  NETWORK_UP=1
  tofu -chdir="$NETWORK_DIR" init -input=false >/dev/null
  tofu -chdir="$NETWORK_DIR" apply -input=false -auto-approve -state="$WORK/network.tfstate" \
    -var "name=$RUN_ID" -var "region=$REGION" -var "labels={\"smoke-run\"=\"$RUN_ID\"}" >/dev/null
}

network_destroy() {
  tofu -chdir="$NETWORK_DIR" destroy -input=false -auto-approve -state="$WORK/network.tfstate" \
    -var "name=$RUN_ID" -var "region=$REGION" -var "labels={\"smoke-run\"=\"$RUN_ID\"}" >/dev/null
  NETWORK_UP=0
}

box_create() {
  BOX_UP=1
  "$OZBOX" -y create "$BOX" --size S --disk 20 --region "$REGION" --image "$IMAGE" --label "smoke-run=$RUN_ID"
}

# Whatever happens, try not to leave billed resources behind.
cleanup() {
  local code=$?
  if [[ "$EXECUTE" == "1" ]]; then
    set +e
    if [[ "$BOX_UP" == "1" ]]; then
      say "cleanup: destroying the box" >&2
      teardown_box
      delete_snapshots
    fi
    if [[ "$NETWORK_UP" == "1" ]]; then
      say "cleanup: destroying the network" >&2
      network_destroy
    fi
    if [[ -n "$WORK" ]]; then rm -rf "$WORK"; fi
    summary
  fi
  exit "$code"
}
trap cleanup EXIT

say "Oz Box real-AWS smoke test ($RUN_ID, profile $PROFILE, region $REGION)"
if [[ "$EXECUTE" == "1" ]]; then
  for tool in aws tofu ssh ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
  done
  [[ -x "$OZBOX" ]] || { echo "no ozbox binary at $OZBOX (cargo build -p ozbox-cli, or pass --ozbox)" >&2; exit 2; }
  WORK="$(mktemp -d)"
  KEY_SSH_DIR="$WORK/ssh"
  mkdir -p "$KEY_SSH_DIR"
  step "credentials work (the account id is not printed)" identity_ok
  if [[ -z "$IMAGE" ]]; then
    IMAGE="$(awsx ssm get-parameter --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
      --query Parameter.Value --output text)"
  fi
else
  say "DRY RUN: nothing is created. Re-run with --execute to do it for real."
  WORK="<temporary directory>"
  KEY_SSH_DIR="<temporary directory>/ssh"
  [[ -n "$IMAGE" ]] || IMAGE="<Ubuntu 24.04 image from the public SSM parameter>"
fi

step "network: create the isolated VPC, subnets and NAT gateway" network_apply

if [[ "$EXECUTE" == "1" ]]; then
  SUBNET="$(tofu -chdir="$NETWORK_DIR" output -state="$WORK/network.tfstate" -raw private_subnet_id)"
  cat >"$WORK/config.toml" <<TOML
provider = "aws"

[aws]
region = "$REGION"
image = "$IMAGE"
subnet_id = "$SUBNET"
profile = "$PROFILE"
TOML
  export OZBOX_CONFIG="$WORK/config.toml"
else
  say "  [dry-run] write a temporary ozbox config pointing at the new private subnet"
fi

step "box: create an S box with a 20 GB /work disk" box_create
say "== verify the new box"
verify_box

step "pause" "$OZBOX" -y pause "$BOX"
check "the instance is stopped" instance_stopped
step "resume" "$OZBOX" -y resume "$BOX"
check "Session Manager reports the box online again" retry 36 5 ssm_online
check "/work is mounted again after the stop and start" retry 60 5 box_ssh_contains "findmnt -n -o FSTYPE /work" "ext4"

step "resize: grow the /work disk to 30 GB" "$OZBOX" -y resize "$BOX" --disk 30
step "the filesystem grows by itself (df shows about 30 GB, no restart)" retry 30 10 work_at_least 28

step "snapshot" "$OZBOX" -y snapshot "$BOX"
check "the snapshot exists and is tagged to the box" snapshot_exists

step "destroy the box" teardown_box
step "delete the smoke snapshots" delete_snapshots
step "network: destroy" network_destroy
say "== leftovers"
check "nothing is left tagged ozbox-managed (retrying while AWS settles)" retry 12 15 no_leftovers

say ""
if [[ "$EXECUTE" == "1" ]]; then
  if [[ "$FAILED" == "0" ]]; then
    say "SMOKE TEST PASSED"
  else
    say "SMOKE TEST FAILED" >&2
    exit 1
  fi
else
  say "Dry run complete. Nothing was created."
fi
