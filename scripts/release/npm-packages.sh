#!/usr/bin/env bash
# Reads packaging/npm-packages.txt and tests or checks the packages listed there.
#
#   npm-packages.sh list                     the package directories, one per line (nothing when the list is empty)
#   npm-packages.sh smoke <dir>              npm pack, install the tarball in a clean directory, run the line's smoke command
#   npm-packages.sh dry-run                  smoke every listed package; a no-op while the list is empty
#   npm-packages.sh check-version <dir> <v>  the package's version is <v> and the package is public
#
# OZBOX_NPM_LIST names another list file (the tests use it).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
list="${OZBOX_NPM_LIST:-$root/packaging/npm-packages.txt}"

entries() { # prints "dir<TAB>smoke" for each real line
  [ -f "$list" ] || return 0
  local line dir cmd
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '' | '#'*) continue ;; esac
    if [[ "$line" == *" :: "* ]]; then
      dir="${line%% :: *}"
      cmd="${line#* :: }"
    else
      dir="$line"
      cmd=""
    fi
    dir="${dir%"${dir##*[![:space:]]}"}"
    printf '%s\t%s\n' "$dir" "$cmd"
  done <"$list"
}

dir_ok() { # a plain relative path inside the repository, no traversal
  case "$1" in
    '' | /* | *..* | *[!A-Za-z0-9._/-]*) return 1 ;;
  esac
}

smoke_of() {
  local d c
  while IFS=$'\t' read -r d c; do
    if [ "$d" = "$1" ]; then
      printf '%s' "$c"
      return 0
    fi
  done < <(entries)
  return 1
}

cmd_list() {
  local d c
  while IFS=$'\t' read -r d c; do
    dir_ok "$d" || {
      echo "npm-packages: not a plain directory: $d" >&2
      exit 1
    }
    printf '%s\n' "$d"
  done < <(entries)
}

cmd_smoke() {
  local dir="$1" cmd
  dir_ok "$dir" || {
    echo "npm-packages: not a plain directory: $dir" >&2
    exit 1
  }
  cmd="$(smoke_of "$dir")" || {
    echo "npm-packages: $dir is not in $list" >&2
    exit 1
  }
  [ -n "$cmd" ] || {
    echo "npm-packages: $dir has no smoke command (add ' :: <command>' to its line)" >&2
    exit 1
  }
  (
    # a subshell, so the scratch directory is removed on every way out and the trap does not outlive this function
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/ozbox-npm-smoke.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    mkdir "$tmp/pack" "$tmp/clean"
    (cd "$root/$dir" && npm pack --pack-destination "$tmp/pack" --silent >/dev/null)
    tarball="$(find "$tmp/pack" -name '*.tgz' | head -n 1)"
    [ -n "$tarball" ] || {
      echo "npm-packages: npm pack produced no tarball for $dir" >&2
      exit 1
    }
    echo "npm-packages: packed $(basename "$tarball"), installing it in a clean directory"
    cd "$tmp/clean"
    npm init -y >/dev/null
    npm install --no-audit --no-fund "$tarball" >/dev/null
    bash -c "$cmd"
  )
  echo "npm-packages: $dir smoke ok"
}

cmd_dry_run() {
  local d any=0
  while IFS= read -r d; do
    any=1
    cmd_smoke "$d"
  done < <(cmd_list)
  [ "$any" -eq 1 ] || echo "npm-packages: no packages are listed in $list; nothing to do"
}

cmd_check_version() {
  local dir="$1" want="$2" got priv
  dir_ok "$dir" || exit 1
  got="$(node -p "require('$root/$dir/package.json').version")"
  priv="$(node -p "String(require('$root/$dir/package.json').private === true)")"
  [ "$priv" = "false" ] || {
    echo "npm-packages: $dir is private and cannot be published" >&2
    exit 1
  }
  [ "$got" = "$want" ] || {
    echo "npm-packages: $dir is version $got but the release is $want" >&2
    exit 1
  }
}

case "${1:-}" in
  list) cmd_list ;;
  smoke) cmd_smoke "${2:?directory}" ;;
  dry-run) cmd_dry_run ;;
  check-version) cmd_check_version "${2:?directory}" "${3:?version}" ;;
  *)
    echo "usage: npm-packages.sh list | smoke <dir> | dry-run | check-version <dir> <version>" >&2
    exit 2
    ;;
esac
