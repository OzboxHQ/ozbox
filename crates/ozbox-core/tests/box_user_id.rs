//! The box user's numeric id is fixed in two places that must agree: the Packer provisioning script (the Oz image) and
//! the first-boot configuration (a stock machine, and the fallback on the image). `/work` outlives the system disk, so a
//! different id on a new image would hand the user's files to a stranger. The cloud-init adoption block remains for
//! disks written before the id was fixed.

use std::path::Path;

fn read(rel: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_default()
}

/// The number after `<key>` on the first line that has it.
fn number_after(text: &str, key: &str) -> Option<u32> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(key))
        .and_then(|rest| {
            rest.trim()
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        })
}

#[test]
fn the_image_and_the_first_boot_configuration_pin_the_same_id() {
    let packer = read("infra/packer/ozbox-image/scripts/provision.sh");
    let cloud = read("infra/cloud-init/box.yaml.tftpl");
    assert!(
        !packer.is_empty() && !cloud.is_empty(),
        "the files were not found"
    );
    let uid = number_after(&packer, "OZBOX_UID=");
    let gid = number_after(&packer, "OZBOX_GID=");
    assert!(uid.is_some(), "provision.sh pins no OZBOX_UID");
    assert_eq!(
        uid, gid,
        "the image gives the box user's group the same number"
    );
    assert_eq!(
        uid,
        number_after(&cloud, "uid: "),
        "cloud-init's users entry must use the id the image uses"
    );
    // the fallback that creates the user in the work-setup script uses it too
    assert!(
        cloud.contains(&format!("--uid {}", uid.unwrap_or(0))),
        "the work-setup script's fallback useradd must pin the same id"
    );
    // and the adoption of an older disk's ids is still there
    assert!(cloud.contains("usermod -u \"$disk_uid\" ozbox"));
}

#[test]
fn the_image_creates_the_user_with_the_pinned_ids() {
    let packer = read("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(packer.contains("groupadd --gid \"$OZBOX_GID\" ozbox"));
    assert!(packer.contains("useradd --uid \"$OZBOX_UID\" --gid \"$OZBOX_GID\""));
}
