#!/usr/bin/env bash
# Installs the small base an Oz Box image carries (web IDE, remote desktop with Firefox, Google Chrome for the browser
# tools on amd64, tunnel, git, tmux, ssh).
# Everything else is a tool the person picks later from the catalog. Runs once, as root, during the Packer build.
# Every downloaded artefact is pinned by version and verified by sha256 before it is used.
set -euo pipefail

: "${OZBOX_ARCH:?}" "${OZBOX_IMAGE_VERSION:?}"
: "${CODE_SERVER_VERSION:?}" "${CODE_SERVER_SHA256:?}"
: "${KASMVNC_VERSION:?}" "${KASMVNC_SHA256:?}"
: "${CLOUDFLARED_VERSION:?}" "${CLOUDFLARED_SHA256:?}"
: "${OZBOXD_SHA256:?}" "${OZBOX_CLI_SHA256:?}"
# The first-boot hash of this commit (scripts/first-boot-hash.sh): one part of the disk generation (ADR 0038).
: "${OZBOX_FIRST_BOOT_SHA256:?}"
# The build hash of this recipe (scripts/packer-build-hash.sh): the other part the package map cannot show.
: "${OZBOX_BUILD_SHA256:?}"

export DEBIAN_FRONTEND=noninteractive

case "$OZBOX_ARCH" in
  amd64|arm64) ;;
  *) echo "unsupported arch: $OZBOX_ARCH" >&2; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Wait for the base image's own first-boot apt activity to finish.
cloud-init status --wait >/dev/null 2>&1 || true

# fetch URL DEST SHA256: download, then refuse anything whose checksum differs.
fetch() {
  local url="$1" dest="$2" sha="$3"
  curl --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 --output "$dest" "$url"
  echo "$sha  $dest" | sha256sum --check --strict -
}

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg xz-utils acl \
  tmux python3 git openssh-server restic \
  unattended-upgrades auditd audispd-plugins

# ---- code-server (official release .deb) ----
fetch "https://github.com/coder/code-server/releases/download/v${CODE_SERVER_VERSION}/code-server_${CODE_SERVER_VERSION}_${OZBOX_ARCH}.deb" \
  "$work/code-server.deb" "$CODE_SERVER_SHA256"
apt-get install -y "$work/code-server.deb"

# ---- KasmVNC (official release .deb, built for Ubuntu 24.04) ----
fetch "https://github.com/kasmtech/KasmVNC/releases/download/v${KASMVNC_VERSION}/kasmvncserver_ubuntu_noble_${KASMVNC_VERSION}_${OZBOX_ARCH}.deb" \
  "$work/kasmvnc.deb" "$KASMVNC_SHA256"
apt-get install -y "$work/kasmvnc.deb"

# ---- cloudflared (official release .deb) ----
fetch "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-${OZBOX_ARCH}.deb" \
  "$work/cloudflared.deb" "$CLOUDFLARED_SHA256"
apt-get install -y "$work/cloudflared.deb"
# The tunnel is configured per box at runtime; the image must not start one on its own.
systemctl disable cloudflared 2>/dev/null || true

# ---- Firefox from Mozilla's apt repository (Ubuntu's own package is a snap) ----
# The signing key is accepted only if its fingerprint matches the one Mozilla publishes.
mozilla_fpr="35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3"
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "$work/mozilla.asc" https://packages.mozilla.org/apt/repo-signing-key.gpg
actual_fpr="$(gpg --show-keys --with-colons "$work/mozilla.asc" | awk -F: '/^fpr:/ {print $10; exit}')"
if [ "$actual_fpr" != "$mozilla_fpr" ]; then
  echo "Mozilla signing key fingerprint mismatch: $actual_fpr" >&2
  exit 1
fi
gpg --dearmor <"$work/mozilla.asc" >/etc/apt/keyrings/packages.mozilla.org.gpg
echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.gpg] https://packages.mozilla.org/apt mozilla main" \
  >/etc/apt/sources.list.d/mozilla.list
printf 'Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n' >/etc/apt/preferences.d/mozilla
apt-get update
apt-get install -y firefox

# ---- The SSM agent (AWS): the only way in. Ubuntu's AWS images ship it as a snap; make sure it is there. ----
if [ "${PACKER_BUILDER_TYPE:-}" = "amazon-ebs" ]; then
  snap list amazon-ssm-agent >/dev/null 2>&1 || snap install amazon-ssm-agent --classic
  systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
fi

# ---- Default tools: GitHub CLI and Claude Code, from their vendors' signed package sources ----
# The same checks the tool installer makes: the key is accepted only if every primary key in the file is one the vendor
# publishes a fingerprint for. The file names match the installer's, so Remove on the Tools page cleans up completely.
add_apt_repo() {
  local name="$1" key_url="$2" pinned="$3" uri="$4" suite="$5" comps="$6" host ext keyfile fp ok
  curl --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 --output "$work/$name.key" "$key_url"
  ok=1
  for fp in $(gpg --batch --show-keys --with-colons "$work/$name.key" | awk -F: '/^pub:/ {want=1} /^sub:|^ssb:|^sec:/ {want=0} /^fpr:/ && want {print toupper($10); want=0}'); do
    case " $pinned " in *" $fp "*) ;; *) ok=0 ;; esac
  done
  if [ "$ok" != 1 ] || [ -z "$(gpg --batch --show-keys --with-colons "$work/$name.key" | awk -F: '/^fpr:/')" ]; then
    echo "$name signing key does not match the published fingerprint" >&2
    exit 1
  fi
  if head -c 14 "$work/$name.key" | grep -q 'BEGIN PGP'; then ext=asc; else ext=gpg; fi
  keyfile="/etc/apt/keyrings/ozbox-$name.$ext"
  install -d -m 0755 /etc/apt/keyrings
  install -m 0644 "$work/$name.key" "$keyfile"
  printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n' "$uri" "$suite" "$comps" "$keyfile" \
    >"/etc/apt/sources.list.d/ozbox-$name.sources"
  host="${uri#https://}"; host="${host%%/*}"
  printf 'Unattended-Upgrade::Origins-Pattern:: "site=%s";\n' "$host" >"/etc/apt/apt.conf.d/52ozbox-$name"
}
# GitHub CLI: key fingerprints from https://github.com/cli/cli/blob/trunk/docs/install_linux.md
add_apt_repo github-cli https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  "2C6106201985B60E6C7AC87323F3D4EA75716059 7F38BBB59D064DBCB3D84D725612B36462313325" \
  https://cli.github.com/packages stable main
# Claude Code: key fingerprint from https://code.claude.com/docs/en/setup (stable channel)
add_apt_repo claude-code https://downloads.claude.ai/keys/claude-code.asc \
  "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE" \
  https://downloads.claude.ai/claude-code/apt/stable stable main
apt-get update
apt-get install -y --no-install-recommends gh claude-code

# ---- Google Chrome for the browser on the box (ADR 0037) ----
# Google's own signed apt repository: Ubuntu's Chromium is a snap, and a snap cannot be confined the way the browser
# worker needs. Chrome is proprietary (Google's terms), unlike the rest of this image; the docs say so. The key is accepted
# only if every primary key is one Google publishes (https://www.google.com/linuxrepositories/). Google ships amd64 only,
# so an arm64 image carries no browser and the browser tools say "no Chromium is installed". The version installed and
# the sha256 of the exact package are recorded in /etc/ozbox/image-release and the package list (the release manifest).
if [ "$(dpkg --print-architecture)" = "amd64" ]; then
  add_apt_repo google-chrome https://dl.google.com/linux/linux_signing_key.pub \
    "4CCA1EAF950CEE4AB83976DCA040830F7FAC5991 EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796" \
    https://dl.google.com/linux/chrome/deb stable main
  # Google's package adds its own repository file on install; ours (key pinned, deb822) is the one kept.
  printf 'repo_add_once="false"\nrepo_reenable_on_distupgrade="false"\n' >/etc/default/google-chrome
  apt-get update
  apt-get install -y --no-install-recommends --download-only google-chrome-stable
  chrome_deb="$(ls /var/cache/apt/archives/google-chrome-stable_*.deb | head -n 1)"
  chrome_sha256="$(sha256sum "$chrome_deb" | awk '{print $1}')"
  apt-get install -y --no-install-recommends google-chrome-stable
  rm -f /etc/apt/sources.list.d/google-chrome.list
  chrome_version="$(dpkg-query -W -f='${Version}' google-chrome-stable)"
  google-chrome-stable --version >/dev/null
else
  chrome_version="none"; chrome_sha256="none"
fi

# ---- The box daemon: the image and its agent are one release ----
# Built in the same workflow run, from the same commit, and uploaded by Packer. Without it ozboxd.service (written by
# first-boot configuration, guarded by ConditionPathExists) never starts and the box can never answer.
ozboxd_upload=/tmp/ozboxd-upload
[ -f "$ozboxd_upload" ] || { echo "the box daemon was not uploaded to $ozboxd_upload" >&2; exit 1; }
echo "$OZBOXD_SHA256  $ozboxd_upload" | sha256sum --check --strict -
install -m 0755 -o root -g root "$ozboxd_upload" /usr/local/bin/ozboxd
rm -f "$ozboxd_upload"
/usr/local/bin/ozboxd --version >/dev/null

# The `ozbox` program, root-owned: the secrets units run it as the secrets user, so the box user must not be able to
# replace it. Same build, same commit, same hash discipline as the daemon.
ozbox_upload=/tmp/ozbox-upload
[ -f "$ozbox_upload" ] || { echo "the ozbox program was not uploaded to $ozbox_upload" >&2; exit 1; }
echo "$OZBOX_CLI_SHA256  $ozbox_upload" | sha256sum --check --strict -
install -m 0755 -o root -g root "$ozbox_upload" /usr/local/bin/ozbox
rm -f "$ozbox_upload"
/usr/local/bin/ozbox --version >/dev/null

# ---- The box user, with a fixed id ----
# The /work disk outlives the system disk, so the files in the box user's home must keep the same owner on every image.
# 1500 is also what the first-boot configuration (infra/cloud-init/box.yaml.tftpl) gives the user on a stock machine, so
# an Oz image and a stock Ubuntu box agree. The home is on /work, which is not mounted yet: nothing is created there.
OZBOX_UID=1500
OZBOX_GID=1500
if getent passwd "$OZBOX_UID" >/dev/null || getent group "$OZBOX_GID" >/dev/null; then
  echo "id $OZBOX_UID is already taken in the base image; the box user cannot be pinned to it" >&2
  exit 1
fi
groupadd --gid "$OZBOX_GID" ozbox
useradd --uid "$OZBOX_UID" --gid "$OZBOX_GID" --home-dir /work/home/ozbox --no-create-home \
  --shell /bin/bash --comment "Oz Box user" ozbox
passwd --lock ozbox
# Linger, so the box user's own services (`systemd --user`: web IDE, desktop, dashboard) start at boot and survive logout.
# systemd is not running during the build, so this is the file `loginctl enable-linger` creates; first-boot configuration
# runs the command too, which is what covers a box that was made without this line.
install -d -m 0755 /var/lib/systemd/linger
: >/var/lib/systemd/linger/ozbox
# The user manager's home is on /work, which is mounted after the system starts. Without this the manager can reach its
# target before the home exists and start none of the enabled units (they work when started by hand). On a new system disk
# /work is not in /etc/fstab yet, so the mount dependency has nothing to wait for: the condition holds the box user's
# manager back until /work is a mount point, and first boot (ozbox-user-manager.sh) starts it once /work is mounted and
# owned. Every later boot waits for the mount and starts it with the system. First boot writes the same drop-in.
install -d /etc/systemd/system/user@.service.d "/etc/systemd/system/user@${OZBOX_UID}.service.d"
printf '[Unit]\nRequiresMountsFor=/work\nAfter=work.mount\n' >/etc/systemd/system/user@.service.d/10-ozbox-work.conf
printf '[Unit]\nRequiresMountsFor=/work\nAfter=work.mount\nConditionPathIsMountPoint=/work\n' \
  >"/etc/systemd/system/user@${OZBOX_UID}.service.d/10-ozbox-work.conf"
# The box user's manager gets the memory and cpu controllers delegated by ONE file with ONE writer: the memory guard's
# 10-ozbox-memory.conf, which `ozbox host-guard memory install` writes at first boot (before this manager starts) and at every
# upgrade. Runs are transient units of that manager (ADR 0038), and a unit's limits only hold with the controllers (ADR 0045).
# Nothing here or in ozbox-user-manager.sh writes a second drop-in for it.

# ---- Hardening ----
systemctl enable unattended-upgrades auditd
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
  >/etc/apt/apt.conf.d/20auto-upgrades

# sshd: no passwords, loopback only. The ssh.socket drop-in is needed because Ubuntu uses socket activation.
install -d /etc/ssh/sshd_config.d /etc/systemd/system/ssh.socket.d
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nListenAddress 127.0.0.1\n' \
  >/etc/ssh/sshd_config.d/10-ozbox.conf
printf '[Socket]\nListenStream=\nListenStream=127.0.0.1:22\n' >/etc/systemd/system/ssh.socket.d/10-ozbox.conf

# The ingress account (ADR 0029): the one way a person's computer reaches the box's secrets service, with its own forced
# command and a key file outside every directory the box user can write. The image carries it with no key; a key arrives at
# first boot (the ozbox-ingress label) or, on AWS, through EC2 Instance Connect.
/usr/local/bin/ozbox secrets ingress-setup ""

# ---- The secrets user and the ptrace rule (ADR 0018) ----
# The encrypted secret store and the programs that open a secret belong to a system account with no login. The box user
# is not in its group, and Yama keeps it from attaching to processes it did not start.
groupadd --system ozbox-secrets
useradd --system --gid ozbox-secrets --home-dir /var/lib/ozbox-secrets --no-create-home \
  --shell /usr/sbin/nologin --comment "Oz Box secrets" ozbox-secrets
passwd --lock ozbox-secrets
install -d -m 0700 -o ozbox-secrets -g ozbox-secrets /var/lib/ozbox-secrets
printf 'kernel.yama.ptrace_scope = 1\nfs.suid_dumpable = 0\n' >/etc/sysctl.d/10-ozbox-yama.conf

# ---- The browser's own user (ADR 0037, amendment 4) ----
# The browser worker, its Chromium and its profiles run as this account, not as the box user an agent's shell runs as. The id
# is fixed because its folders are on /work, which outlives the system disk. First boot makes the folders and the launcher
# (`ozbox browser-setup`): /work is not mounted here.
OZBOX_BROWSER_ID=1501
if getent passwd "$OZBOX_BROWSER_ID" >/dev/null || getent group "$OZBOX_BROWSER_ID" >/dev/null; then
  echo "id $OZBOX_BROWSER_ID is already taken in the base image; the browser user cannot be pinned to it" >&2
  exit 1
fi
groupadd --system --gid "$OZBOX_BROWSER_ID" ozbox-browser
useradd --system --gid ozbox-browser --uid "$OZBOX_BROWSER_ID" --home-dir /work/ozbox-browser/private/home --no-create-home \
  --shell /usr/sbin/nologin --comment "Oz Box browser" ozbox-browser
passwd --lock ozbox-browser

# What this image contains, for the release manifest (package names and versions; the full dpkg database for the SBOM).
# Written before the release record, because the disk generation below is computed from it.
install -d /etc/ozbox
dpkg-query -W -f='${binary:Package}\t${Version}\n' >/etc/ozbox/packages.txt
cp /var/lib/dpkg/status /etc/ozbox/dpkg-status
chmod 0644 /etc/ozbox/packages.txt /etc/ozbox/dpkg-status

# The disk generation (ADR 0038): one hash over everything that cannot change on a running machine (the kernel, the package
# map, the first boot, this recipe, the units, the accounts, sshd and the rest of /etc). It is computed after the last
# account, unit and /etc file this script writes: anything written below this line is not in it. The image workflow records the same value in the signed manifest, and
# a box compares it with its target's to tell a live update from a replace. The parts are kept for the manifest.
disk_parts="$(ROOT=/ OZBOX_FIRST_BOOT_SHA256="$OZBOX_FIRST_BOOT_SHA256" OZBOX_BUILD_SHA256="$OZBOX_BUILD_SHA256" sh /tmp/ozbox-disk-generation.sh)"
rm -f /tmp/ozbox-disk-generation.sh
printf '%s\n' "$disk_parts" >/etc/ozbox/disk-parts
chmod 0644 /etc/ozbox/disk-parts
disk_generation="$(printf '%s\n' "$disk_parts" | sed -n 's/^disk_generation=//p')"
printf '%s' "$disk_generation" | grep -Eq '^[0-9a-f]{64}$'

# Record which image this is, for support and for ozboxd.
printf '%s\n' "$OZBOX_IMAGE_VERSION" >/etc/ozbox/image-version
# What `ozbox upgrade` reads over SSH to say at once that an image has no agent, and what first-boot configuration reads
# to know it is on an Oz image (it then installs nothing).
printf 'image_version=%s\nozboxd_sha256=%s\nozbox_sha256=%s\nsource_commit=%s\nchrome_version=%s\nchrome_deb_sha256=%s\ndisk_generation=%s\n' \
  "$OZBOX_IMAGE_VERSION" "$OZBOXD_SHA256" "$OZBOX_CLI_SHA256" "${OZBOX_SOURCE_COMMIT:-unknown}" "$chrome_version" "$chrome_sha256" "$disk_generation" >/etc/ozbox/image-release
chmod 0644 /etc/ozbox/image-release

# ---- Clean up so the image is small and carries no machine identity ----
apt-get clean
rm -rf /var/lib/apt/lists/*
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /etc/ssh/ssh_host_*
# the build's own journal so far (/var is not part of the disk generation, which was computed above from /etc and the rest)
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
echo "provision: done"
