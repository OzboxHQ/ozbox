# Which Oz Box images in ONE region fall outside the retention window (ADR 0052). Pure: input in, a decision out; the shell
# script next to it makes every AWS call. A test runs this same file against fixtures and hostile input.
#
# Input  (`jq -n`):  --slurpfile images <describe-images --owners self output>
#                    --slurpfile snaps  <describe-snapshots --owner-ids self output>
#                    --arg owner <the publishing account id>   --arg released <the version just released>
#                    --argjson keep <how many versions stay (3)>   --argjson now <the time now, epoch seconds>
# Output: {keep_versions, delete: [{image_id, name, version, snapshots}], snapshots_left, ignored}
#
# An image is OURS only if every one of these holds, and anything else is IGNORED, never deleted:
#   - its owner is $owner (so an image shared with this account, or copied from another, is never touched);
#   - it carries the tag ozbox-managed=true;
#   - its ozbox-image tag is a release version (0.3.0, 0.3.0-rc.1);
#   - its name starts with "ozbox-".
# Versions are compared as numbers (0.10.0 is after 0.9.0), and a pre-release comes before its release. The window is the
# released version, anything newer than it, the newest $keep release versions up to it, and the newest version of each of the
# last $keep minors (a minor with many patches cannot push every older minor out). Pre-releases never count toward the
# window and are removed only after their own release has shipped and 14 days have passed. So the version just released, and anything at or above it, is never
# selected; and if the released version is not among the images, nothing is selected at all (a build that did not make it
# is no reason to delete the past).
# A snapshot is selected only if it is itself tagged ozbox-managed=true.

def vkey:
  (split("-") | .[0] as $core | (.[1:] | join("-")) as $pre
   | [ ($core | split(".") | map(tonumber)),
       (if $pre == "" then 1 else 0 end),
       ($pre | if . == "" then [] else split(".") | map(if test("^[0-9]+$") then [0, tonumber] else [1, .] end) end) ]);

def tagmap: (.Tags // []) | map({(.Key): .Value}) | add // {};
def is_version: type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+(-[a-z0-9.]+)?$");

($images[0].Images // []) as $all
| ($snaps[0].Snapshots // []) as $allsnaps
| ($allsnaps | map({key: .SnapshotId, value: (tagmap)}) | from_entries) as $snaptags
| ($all | map(select(
      .OwnerId == $owner
      and (tagmap["ozbox-managed"] == "true")
      and (tagmap["ozbox-image"] | is_version)
      and ((.Name // "") | startswith("ozbox-"))
    ) | . + {version: tagmap["ozbox-image"]})) as $ours
| ($ours | map(.version) | unique | sort_by(vkey) | reverse) as $versions
| if ($released | is_version | not) then error("the released version is not a release version")
  elif ($versions | index($released)) == null
  then error("the released version \($released) is not among the images in this region, so nothing is selected")
  else
    ($versions | map(select(vkey > ($released | vkey)))) as $newer
    | ($versions | map(select(vkey <= ($released | vkey)))) as $older
    # pre-releases never count toward the window; one goes only after its own release has shipped AND the grace period has
    # passed (a person on a beta is given time to move), and stays while no release of its number exists
    | ($older | map(select(contains("-") | not))) as $finals
    | ($ours | map(select(.version | contains("-") | not)
        | {key: .version, value: ((.CreationDate // empty) | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601)})
        | group_by(.key) | map({key: .[0].key, value: (map(.value) | max)}) | from_entries) as $shipped_at
    | ($older | map(select(contains("-") and . != $released)
        | select(($shipped_at[split("-")[0]] // null) as $t | $t != null and ($t + 14 * 86400) <= $now))) as $expired_pre
    | ($older | map(select(contains("-") and . != $released)) - $expired_pre) as $kept_pre
    | ($finals[: $keep]) as $recent
    # the newest build of each of the last $keep minors, so a patch-heavy minor cannot push every older minor out
    | ($finals | group_by(split(".")[:2] | join(".")) | map(max_by(vkey)) | sort_by(vkey) | reverse | .[: $keep]) as $minors
    | ($newer + [$released] + $recent + $minors + $kept_pre | unique | sort_by(vkey) | reverse) as $keep_versions
    | {
        keep_versions: $keep_versions,
        delete: ($ours | map(select(.version as $v | $keep_versions | index($v) | not))
          | map({image_id: .ImageId, name: .Name, version: .version,
                 snapshots: ([.BlockDeviceMappings[]? | .Ebs.SnapshotId? | select(. != null)]
                             | map(select($snaptags[.]["ozbox-managed"] == "true"))),
                 snapshots_not_ours: ([.BlockDeviceMappings[]? | .Ebs.SnapshotId? | select(. != null)]
                             | map(select($snaptags[.]["ozbox-managed"] != "true")))})),
        ignored: (($all | length) - ($ours | length))
      }
    | .snapshots_left = ([.delete[].snapshots_not_ours[]])
    | .delete |= map(del(.snapshots_not_ours))
  end
