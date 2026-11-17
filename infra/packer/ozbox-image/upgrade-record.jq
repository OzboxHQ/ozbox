# The `upgrade` record of the image manifest (ADR 0038). The release job runs this file, and a test runs the same file
# against hostile input, so what is checked is what ships.
#
# Arguments: $first_boot and $build (the hashes of this commit), $policy (the tracked upgrade-policy.json, slurped) and
# $parts (the per-architecture part files, slurped).
#
# The record is the computed generation and parts plus EXACTLY the two `/work` format keys of the policy file and the
# `secrets_keys` it declares (the store keys this release's secrets service opens by itself; ADR 0029 Amendment 18). The policy
# is never merged whole: a `disk_generation`, a `disk_parts` or a `live_from` in that file must change nothing, because
# `live_from` is what turns live updates on, and it is written by the release that ships the live updater (ADR 0038,
# "Rules that hold before any release turns live updates on").
($parts | map({(.arch): .disk}) | add) as $d
| {disk_generation: ($d | map_values(.disk_generation)),
   disk_parts: ({first_boot: $first_boot, build: $build}
     + (["kernel","packages","units","accounts","sshd","config"]
        | map(. as $k | {key: $k, value: ($d | map_values(.[$k]))}) | from_entries))}
  + ($policy[0] | {work_format, work_format_reads, secrets_keys})
