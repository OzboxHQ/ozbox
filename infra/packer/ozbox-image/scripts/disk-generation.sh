#!/bin/sh
# Prints the disk generation of an Oz image (ADR 0038): one SHA-256 over everything that cannot change on a running
# machine, and the parts it is made of, as `key=value` lines:
#
#   kernel=<sha256 of the installed kernel packages and versions>
#   packages=<sha256 of the package map (name and version of every package)>
#   first_boot=<the first-boot hash, given by the workflow>
#   build=<the build hash of the image recipe (scripts/packer-build-hash.sh), given by the workflow>
#   units=<sha256 of every systemd unit and drop-in the image writes, and which units are enabled>
#   accounts=<sha256 of the users and groups: name, ids, home, shell and group members, never a password or a key>
#   sshd=<sha256 of the sshd configuration (never a host key: those are made at first boot)>
#   config=<sha256 of everything else that sets the machine up: all of /etc except a short named list, the linger marks
#           and the snaps present (apt sources, keyrings, pinning, sysctl, /etc/default, the snap SSM agent)>
#   disk_generation=<sha256 over the eight lines above, in that order>
#
# Two images that print the same `disk_generation` differ only in the signed programs, so a running machine of one can
# become the other by swapping those programs. The build runs this as root at the end of provisioning (after the package
# map is written to $ROOT/etc/ozbox/packages.txt); a test runs it against a folder of fixtures.
#
# Deny by default: a file under /etc that is not on the short allow-list below (what a machine makes or changes by itself)
# moves the generation. A wrong guess therefore costs a replace (the safe direction), never a live update onto a disk that
# lacks the change.
#
# Environment: ROOT (default /), OZBOX_FIRST_BOOT_SHA256 and OZBOX_BUILD_SHA256 (required, SHA-256s).
# Deterministic: C locale, sorted, file contents only (no times, owners or inode numbers).
set -eu
export LC_ALL=C
root="${ROOT:-/}"
root="${root%/}"
first_boot="${OZBOX_FIRST_BOOT_SHA256:-}"
build="${OZBOX_BUILD_SHA256:-}"
for pair in "OZBOX_FIRST_BOOT_SHA256=$first_boot" "OZBOX_BUILD_SHA256=$build"; do
  name="${pair%%=*}"
  value="${pair#*=}"
  case "$value" in
    *[!0-9a-f]* | "") echo "disk-generation: $name must be a lower-case SHA-256" >&2; exit 1 ;;
  esac
  if [ "${#value}" -ne 64 ]; then
    echo "disk-generation: $name must be a lower-case SHA-256" >&2
    exit 1
  fi
done
packages="$root/etc/ozbox/packages.txt"
if [ ! -s "$packages" ]; then
  echo "disk-generation: $packages is missing or empty; write the package map first" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash() { sha256sum | cut -d' ' -f1; }
else
  hash() { shasum -a 256 | cut -d' ' -f1; }
fi

# the installed kernel: every kernel image package with its version
kernel="$(grep -E '^linux-image-' "$packages" | sort | hash)"
# the package map: every package and its version
packages_hash="$(sort "$packages" | hash)"

# units: the content of each file below /etc/systemd/system, and each enablement link with where it points
units="$(
  if [ -d "$root/etc/systemd/system" ]; then
    cd "$root/etc/systemd/system"
    {
      find . -type f | sort | while IFS= read -r f; do
        printf 'file %s %s\n' "$f" "$(hash <"$f")"
      done
      find . -type l | sort | while IFS= read -r l; do
        printf 'link %s %s\n' "$l" "$(readlink "$l")"
      done
    }
  fi | hash
)"

# accounts: name, ids, home and shell, and every group's members; nothing secret (no password hash, no key). Adding the box
# user to a group, or changing a shell, is a change to the disk.
accounts="$(
  {
    if [ -f "$root/etc/passwd" ]; then cut -d: -f1,3,4,6,7 "$root/etc/passwd" | sed 's/^/user /'; fi
    if [ -f "$root/etc/group" ]; then cut -d: -f1,3,4 "$root/etc/group" | sed 's/^/group /'; fi
  } | sort | hash
)"

# sshd: the main file and the drop-ins
sshd="$(
  {
    for f in "$root/etc/ssh/sshd_config" "$root/etc/ssh/sshd_config.d"/*.conf; do
      if [ -f "$f" ]; then
        printf 'file %s %s\n' "${f#"$root"}" "$(hash <"$f")"
      fi
    done
  } | hash
)"

# config: all of /etc except what a machine makes or changes by itself (the allow-list). Each entry is a path and a content
# hash, or a link and where it points. This is where the sysctl rules, the apt sources, keyrings and pinning, the
# unattended-upgrade switches and /etc/default live.
etc_skip() {
  case "$1" in
    ./machine-id | ./hostname | ./hosts | ./resolv.conf | ./mtab | ./.pwd.lock | ./ld.so.cache) return 0 ;;
    ./shadow | ./shadow- | ./gshadow | ./gshadow- | ./passwd- | ./group- | ./subuid- | ./subgid-) return 0 ;;
    ./ssh/ssh_host_*) return 0 ;;
    ./netplan/50-cloud-init.yaml | ./cloud/build.info) return 0 ;;
    # the image own record and lists: they carry the version and are derived from what is hashed elsewhere
    ./ozbox | ./ozbox/*) return 0 ;;
  esac
  return 1
}
config="$(
  {
    if [ -d "$root/etc" ]; then
      (
        cd "$root/etc"
        find . \( -type f -o -type l \) | sort | while IFS= read -r f; do
          if etc_skip "$f"; then continue; fi
          if [ -L "$f" ]; then
            printf 'link %s %s\n' "$f" "$(readlink "$f")"
          else
            printf 'file %s %s\n' "$f" "$(hash <"$f")"
          fi
        done
      )
    fi
    # accounts that keep running after a logout (the box user linger mark)
    if [ -d "$root/var/lib/systemd/linger" ]; then
      (cd "$root/var/lib/systemd/linger" && find . -type f -o -type l | sort | sed 's/^/linger /')
    fi
    # the snaps present, with their revisions (the SSM agent comes from a snap, outside dpkg)
    if [ -d "$root/var/lib/snapd/snaps" ]; then
      (cd "$root/var/lib/snapd/snaps" && find . -name '*.snap' | sort | sed 's/^/snap /')
    fi
  } | hash
)"

generation="$(
  printf 'kernel=%s\npackages=%s\nfirst_boot=%s\nbuild=%s\nunits=%s\naccounts=%s\nsshd=%s\nconfig=%s\n' \
    "$kernel" "$packages_hash" "$first_boot" "$build" "$units" "$accounts" "$sshd" "$config" | hash
)"

printf 'kernel=%s\npackages=%s\nfirst_boot=%s\nbuild=%s\nunits=%s\naccounts=%s\nsshd=%s\nconfig=%s\ndisk_generation=%s\n' \
  "$kernel" "$packages_hash" "$first_boot" "$build" "$units" "$accounts" "$sshd" "$config" "$generation"
