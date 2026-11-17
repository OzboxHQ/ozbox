//! `ozbox build-info`: the program says which dashboard it embedded. The release build RUNS this and compares the hash
//! with the one it computed, because searching a binary for a hash is unreliable (the compiler may store the constant in
//! pieces), so this output is the contract those checks rely on.

use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    // no configuration, no state: it must answer on a machine with nothing set up
    let dir = tempfile::tempdir()?;
    let out = Command::new(env!("CARGO_BIN_EXE_ozbox"))
        .env("OZBOX_CONFIG", dir.path().join("none.toml"))
        .env("OZBOX_STATE_DIR", dir.path().join("state"))
        .env("HOME", dir.path())
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    Ok(String::from_utf8(out)?)
}

#[test]
fn it_reports_the_embedded_dashboard_as_json() -> TestResult {
    let v: serde_json::Value = serde_json::from_str(&run(&["--json", "build-info"])?)?;
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    let embedded = v["dashboard"]["embedded"].as_bool().ok_or("embedded")?;
    let hash = v["dashboard"]["sha256"].as_str().ok_or("sha256")?;
    let placeholder = v["placeholder_page"].as_bool().ok_or("placeholder")?;
    if embedded {
        // a real dashboard: a 64-character content hash, and the placeholder page is not in the program
        assert_eq!(hash.len(), 64, "{hash}");
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "{hash}");
        assert!(!placeholder);
    } else {
        assert_eq!(hash, "none");
        assert!(placeholder);
    }
    Ok(())
}

#[test]
fn the_hash_it_reports_is_the_one_build_rs_recorded() -> TestResult {
    // the same value `ozbox serve` reports in /v1/info
    let v: serde_json::Value = serde_json::from_str(&run(&["--json", "build-info"])?)?;
    assert_eq!(v["dashboard"]["sha256"], env!("OZBOX_DASHBOARD_SHA256"));
    Ok(())
}

#[test]
fn the_plain_output_carries_the_same_facts() -> TestResult {
    let t = run(&["build-info"])?;
    assert!(
        t.contains(&format!("ozbox {}", env!("CARGO_PKG_VERSION"))),
        "{t}"
    );
    assert!(t.contains("dashboard sha256: "), "{t}");
    assert!(t.contains("placeholder page compiled in: "), "{t}");
    Ok(())
}
