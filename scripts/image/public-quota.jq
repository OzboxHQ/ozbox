# Which public Oz Box versions must become PRIVATE so a release fits the account's public-image quota, in ONE region (ADR 0052).
# Pure: input in, a decision out; make-room.sh next to it makes every AWS call, and a test runs this same file on fixtures.
#
# Input  (`jq -n`):  --slurpfile images <describe-images --owners self, public images only>
#                    --arg owner <the publishing account id>   --arg version <the version being published>
#                    --argjson quota <public images allowed in the region>
#                    --argjson ids <the image ids the release must have public in this region (from its manifest)>
# Output: {public, quota, need, excess, fits, make_private_versions, make_private: [{image_id, name, version}], untouchable}
#
# `need` is the release's images that are not public yet (a half-public release needs fewer). Whole versions are made private,
# every architecture together, OLDEST first, and only as many as are needed: the newest previous version stays public unless the
# quota forces it. An image is a candidate only if it is OURS (owner is $owner, tagged ozbox-managed=true, a release-version
# ozbox-image tag, a name that starts with "ozbox-") and its version is OLDER than the one being published; the version being
# published, anything newer, and every image that is not ours are never selected. `fits` is false when freeing every candidate
# would still not be enough (`untouchable` is how many public images this process will never change).

def vkey:
  (split("-") | .[0] as $core | (.[1:] | join("-")) as $pre
   | [ ($core | split(".") | map(tonumber)),
       (if $pre == "" then 1 else 0 end),
       ($pre | if . == "" then [] else split(".") | map(if test("^[0-9]+$") then [0, tonumber] else [1, .] end) end) ]);

def tagmap: (.Tags // []) | map({(.Key): .Value}) | add // {};
def is_version: type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+(-[a-z0-9.]+)?$");

($images[0].Images // []) as $pub
| ($pub | length) as $count
| ($pub | map(.ImageId)) as $pubids
| ($ids - $pubids | length) as $need
| ($pub | map(select(
      .OwnerId == $owner
      and (tagmap["ozbox-managed"] == "true")
      and (tagmap["ozbox-image"] | is_version)
      and ((.Name // "") | startswith("ozbox-"))
    ) | . + {version: tagmap["ozbox-image"]})) as $ours
| ($version | is_version) as $ok
| if ($ok | not) then error("the version being published is not a release version") else . end
| ($ours | map(.version) | unique | map(select(. != $version and (vkey < ($version | vkey)))) | sort_by(vkey)) as $candidates
| ($count + $need - $quota) as $excess
| [ $candidates[] as $v | {v: $v, n: ($ours | map(select(.version == $v)) | length)} ] as $c
| (reduce $c[] as $x ({freed: 0, take: []};
     if .freed >= $excess then . else {freed: (.freed + $x.n), take: (.take + [$x.v])} end)) as $r
| {
    public: $count, quota: $quota, need: $need,
    excess: ([$excess, 0] | max),
    fits: ($r.freed >= $excess),
    make_private_versions: $r.take,
    make_private: [ $ours[] | select(.version as $v | $r.take | index($v))
                    | {image_id: .ImageId, name: .Name, version: .version} ],
    untouchable: ($count - ($ours | map(select(.version as $v | $candidates | index($v))) | length))
  }
