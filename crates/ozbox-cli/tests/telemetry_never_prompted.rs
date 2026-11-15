//! Telemetry is never prompted for: it is off unless a person runs `ozbox telemetry on`. The commands that walk a person
//! through setup (init, and the confirmation helpers it uses) must not mention telemetry at all, so a future change cannot
//! add an "help us improve" question without failing here.
#![allow(clippy::expect_used)]

fn code_only(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn setup_flows_never_mention_telemetry() {
    for (name, src) in [
        ("init_cli.rs", include_str!("../src/init_cli.rs")),
        ("init.rs", include_str!("../src/init.rs")),
    ] {
        assert!(
            !code_only(src).to_lowercase().contains("telemetry"),
            "{name} must not prompt for or mention telemetry"
        );
    }
}

#[test]
fn the_only_automatic_path_reads_the_off_switch_first() {
    let src = include_str!("../src/telemetry_cli.rs");
    let body = src
        .split("pub fn after_command")
        .nth(1)
        .expect("after_command exists");
    let enabled = body.find(".enabled").expect("checks the setting");
    let send = body.find("telemetry::send").expect("sends");
    assert!(
        enabled < send,
        "the setting is checked before anything is sent"
    );
}
