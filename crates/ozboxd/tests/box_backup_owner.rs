//! The dashboard server owns the backup schedule, so a box that is created or rebuilt (an upgrade builds a new system
//! disk from the same first-boot file) must start with its own schedule explicitly off. Both on would back `/work` up
//! twice. This reads the real first-boot file, renders the one setting file in it and parses it with the daemon's own
//! loader, so a change to either side fails here.
#![allow(clippy::unwrap_used)]

use ozboxd::config::Config;

fn box_config() -> String {
    let path = format!(
        "{}/../../infra/cloud-init/box.yaml.tftpl",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let start = text.find("  - path: /etc/ozbox/ozboxd.toml").unwrap();
    let body = &text[start..];
    let content = body.find("    content: |\n").unwrap() + "    content: |\n".len();
    let rest = &body[content..];
    // The block is indented by six spaces; it ends at the next list item of write_files.
    let end = rest.find("\n  - path:").unwrap_or(rest.len());
    rest[..end]
        .lines()
        .map(|l| l.strip_prefix("      ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("${box_name}", "dev-1")
        .replace("${provider}", "aws")
        .replace("${work_encrypted}", "true")
        .replace("${runs_max_active}", "6")
}

#[test]
fn a_new_or_rebuilt_box_starts_with_its_own_backup_schedule_explicitly_off() {
    let toml = box_config();
    let config = Config::from_toml(&toml).unwrap();
    assert!(
        !config.backup.enabled,
        "the box's own timer must be off while the server owns the schedule"
    );
    // Explicit, not merely the daemon's default: a change of the default must not turn a second schedule on.
    let explicit = toml
        .lines()
        .any(|l| l.trim() == "enabled = false" && !l.trim_start().starts_with('#'));
    assert!(
        explicit,
        "the first-boot file must say `enabled = false` itself:\n{toml}"
    );
}

#[test]
fn the_first_boot_file_caps_agent_runs_at_the_number_the_adapter_passes() {
    let config = Config::from_toml(&box_config()).unwrap();
    assert_eq!(config.runs.max_active, 6);
}

#[test]
fn the_daemons_own_default_is_off_too() {
    assert!(!Config::from_toml("").unwrap().backup.enabled);
}
