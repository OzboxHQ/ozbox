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
    let root = block(&code, "root_block_device {");
    assert!(
        root.contains("tags") && root.contains("local.tags"),
        "the system disk must be created with the box's tags (ozbox-managed first): {root}"
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
