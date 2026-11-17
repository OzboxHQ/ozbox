//! The operator's AWS role may put a first tag on a disk only when the disk is created, and may change tags only on a resource
//! that already carries `ozbox-managed=true`. So the system disk of a box must be tagged when it is made, and a plan must never
//! try to tag an existing one in place: a box made by an earlier version has a system disk with no tags at all, and that tag call
//! is refused part way through an apply. This reads the module's source, so a change that drops either rule fails here.

#![allow(clippy::unwrap_used)]

use std::path::Path;

fn main_tf() -> String {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/tofu/modules/aws-box");
    std::fs::read_to_string(dir.join("main.tf")).unwrap()
}

/// The text of one `{ ... }` block that starts at `needle` (comments are not code: a line comment is dropped first).
fn block<'a>(text: &'a str, needle: &str) -> &'a str {
    let start = text.find(needle).unwrap_or_else(|| panic!("no {needle}"));
    let mut depth = 0usize;
    for (i, c) in text[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[start..start + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced {needle}");
}

fn without_comments(text: &str) -> String {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_system_disk_is_tagged_as_ours_when_it_is_created() {
    let code = without_comments(&main_tf());
    let instance = block(&code, "resource \"aws_instance\" \"box\"");
    let root = block(instance, "root_block_device {");
    // The provider refuses a block's own `tags` together with `volume_tags` and applies them with a later call that the operator's
    // role cannot make for a disk that exists, so the launch's tag specification is the one that works.
    assert!(
        !root.contains("tags"),
        "root_block_device must not carry tags (they conflict with volume_tags and are applied too late): {root}"
    );
    assert!(
        instance.contains("volume_tags") && instance.contains("local.root_volume_tags"),
        "the system disk must be created with the box's tags (ozbox-managed first) as the launch's volume_tags"
    );
}

/// A block's own `tags` are applied by the provider after the machine runs, which the operator's role cannot do for a volume
/// that exists; the launch's own volume tag specification (`volume_tags`) is what AWS applies while it creates the disk, so a box
/// made or replaced by an upgrade has a system disk its pre-upgrade snapshot can be taken of. It is for creation only.
#[test]
fn the_launch_tags_the_volumes_it_creates_and_never_relabels_them_afterwards() {
    let code = without_comments(&main_tf());
    let instance = block(&code, "resource \"aws_instance\" \"box\"");
    assert!(
        instance.contains("volume_tags") && instance.contains("local.root_volume_tags"),
        "the launch must carry volume_tags, so the disk is ozbox-managed when AWS creates it"
    );
    let lifecycle = block(instance, "lifecycle {");
    assert!(
        lifecycle.contains("volume_tags"),
        "volume_tags is for creation only: it must be in ignore_changes, or a plan relabels the attached /work volume"
    );
    assert!(
        code.contains("root_volume_tags = merge(local.tags, {")
            && code.contains("\"ozbox-managed\""),
        "the tags a disk is created with start from the box's own (ozbox-managed first)"
    );
}

#[test]
fn an_existing_system_disk_is_never_tagged_in_place() {
    let code = without_comments(&main_tf());
    let instance = block(&code, "resource \"aws_instance\" \"box\"");
    let lifecycle = block(instance, "lifecycle {");
    assert!(
        lifecycle.contains("root_block_device[0].tags"),
        "ignore_changes must name the system disk's tags, or a box made before they existed plans a tag call its operator role cannot make"
    );
}
