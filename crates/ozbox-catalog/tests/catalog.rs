#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use ozbox_catalog::plan::build_plan;
use ozbox_catalog::{embedded, Action, Arch, Catalog, Op, PlanError, PlanRequest, Privilege};

fn ids(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_embedded_catalog_is_valid_and_complete() {
    let c = embedded().unwrap();
    assert!(c.tools.len() >= 40);
    // Every group is used and every owner-listed tool is present, installable or marked with a reason.
    for want in [
        "vscode-desktop",
        "neovim",
        "nano",
        "micro",
        "zed-remote",
        "claude-code",
        "codex",
        "gemini-cli",
        "aider",
        "opencode",
        "thunar-xfce",
        "yazi",
        "node",
        "pnpm",
        "bun",
        "deno",
        "python",
        "uv",
        "rust",
        "go",
        "java",
        "podman",
        "docker",
        "postgresql-client",
        "redis-cli",
        "sqlite",
        "dbeaver",
        "aws-cli",
        "session-manager-plugin",
        "gcloud",
        "azure-cli",
        "supabase-cli",
        "opentofu",
        "packer",
        "kubectl",
        "helm",
        "github-cli",
        "playwright-browsers",
        "jq",
        "ripgrep",
        "fd",
        "htop",
        "btop",
    ] {
        assert!(c.tool(want).is_some(), "missing {want}");
    }
    for g in &c.groups {
        assert!(
            c.tools.iter().any(|t| t.group == g.id),
            "empty group {}",
            g.id
        );
    }
}

#[test]
fn every_bundle_member_exists_and_is_verified() {
    let c = embedded().unwrap();
    for id in ["web", "python-data", "infra", "ai-agents"] {
        let b = c.bundle(id).unwrap();
        for m in &b.tools {
            assert!(c.tool(m).unwrap().verified, "{id}: {m}");
        }
    }
}

#[test]
fn an_unverified_tool_in_a_bundle_is_refused_at_load() {
    let text = include_str!("../../../catalog/catalog.toml").replace(
        r#"tools = ["packer", "helm", "kubectl", "github-cli"]"#,
        r#"tools = ["packer", "docker"]"#,
    );
    let e = Catalog::parse(&text).unwrap_err();
    assert!(e.contains("not verified"), "{e}");
}

#[test]
fn unknown_keys_duplicate_ids_and_missing_reasons_are_refused() {
    let base = include_str!("../../../catalog/catalog.toml");
    assert!(Catalog::parse(&base.replace("size_mb = 2\n", "size_mb = 2\nsurprise = 1\n")).is_err());
    let dup = base.replace("id = \"nano\"", "id = \"neovim\"");
    assert!(Catalog::parse(&dup).unwrap_err().contains("duplicate"));
    let noreason = base.replacen("unverified_reason = ", "x_reason = ", 1);
    assert!(Catalog::parse(&noreason).is_err());
    let badfp = base.replace("D55C0D1AC78A8D8126CB631CFC9CA96ACA026560", "d55c");
    assert!(Catalog::parse(&badfp).unwrap_err().contains("fingerprint"));
    let http = base.replace(
        "https://cli.github.com/packages\"\nsuite",
        "http://cli.github.com/packages\"\nsuite",
    );
    assert!(Catalog::parse(&http).unwrap_err().contains("https"));
}

#[test]
fn every_verified_tool_has_a_way_to_install_on_both_architectures() {
    let c = embedded().unwrap();
    for t in c.tools.iter().filter(|t| t.verified) {
        for arch in [Arch::Amd64, Arch::Arm64] {
            let plan = build_plan(
                &c,
                arch,
                &BTreeSet::new(),
                &PlanRequest {
                    install: vec![t.id.clone()],
                    remove: vec![],
                },
            )
            .unwrap();
            assert!(!plan.is_noop(), "{} on {:?}", t.id, arch);
        }
    }
}

#[test]
fn bundles_expand_and_dependencies_come_first() {
    let c = embedded().unwrap();
    let items = c.expand(&ids(&["bundle:ai-agents", "jq"])).unwrap();
    assert_eq!(
        items,
        ids(&["claude-code", "codex", "gemini-cli", "aider", "jq"])
    );
    assert!(c.expand(&ids(&["bundle:nope"])).is_err());
    let p = build_plan(
        &c,
        Arch::Amd64,
        &BTreeSet::new(),
        &PlanRequest {
            install: items,
            remove: vec![],
        },
    )
    .unwrap();
    let order: Vec<&str> = p.tools.iter().map(|t| t.id.as_str()).collect();
    let pos = |id: &str| order.iter().position(|i| *i == id).unwrap();
    assert!(pos("node") < pos("codex"));
    assert!(pos("python") < pos("uv") && pos("uv") < pos("aider"));
    let dep = p.tools.iter().find(|t| t.id == "node").unwrap();
    assert!(dep.reason.starts_with("required_by:"));
    // Steps are numbered in order and the root ones are only package-manager actions.
    for (i, s) in p.steps.iter().enumerate() {
        assert_eq!(s.index, i);
        if s.privilege == Privilege::Root {
            assert!(matches!(
                s.action,
                Action::AptUpdate
                    | Action::AptInstall { .. }
                    | Action::AptRemove { .. }
                    | Action::AptRepo { .. }
                    | Action::AptRepoRemove { .. }
            ));
        }
    }
}

#[test]
fn planning_is_idempotent_and_deterministic() {
    let c = embedded().unwrap();
    let mut have: BTreeSet<String> = BTreeSet::new();
    let req = PlanRequest {
        install: ids(&["neovim"]),
        remove: vec![],
    };
    let a = build_plan(&c, Arch::Amd64, &have, &req).unwrap();
    let b = build_plan(&c, Arch::Amd64, &have, &req).unwrap();
    assert_eq!(a, b);
    assert_ne!(
        a.hash,
        build_plan(
            &c,
            Arch::Arm64,
            &have,
            &PlanRequest {
                install: ids(&["kubectl"]),
                remove: vec![]
            }
        )
        .unwrap()
        .hash
    );
    have.insert("neovim".into());
    let again = build_plan(&c, Arch::Amd64, &have, &req).unwrap();
    assert!(again.is_noop());
    assert_eq!(again.already_installed, ids(&["neovim"]));
    let gone = build_plan(
        &c,
        Arch::Amd64,
        &BTreeSet::new(),
        &PlanRequest {
            install: vec![],
            remove: ids(&["neovim"]),
        },
    )
    .unwrap();
    assert!(gone.is_noop());
    assert_eq!(gone.not_installed, ids(&["neovim"]));
}

#[test]
fn refusals_are_specific() {
    let c = embedded().unwrap();
    let none = BTreeSet::new();
    let plan = |i: &[&str], r: &[&str], have: &BTreeSet<String>| {
        build_plan(
            &c,
            Arch::Amd64,
            have,
            &PlanRequest {
                install: ids(i),
                remove: ids(r),
            },
        )
    };
    assert!(matches!(
        plan(&["docker"], &[], &none),
        Err(PlanError::Unverified { .. })
    ));
    // An unverified tool in the dependency chain is refused too, never skipped.
    assert!(matches!(
        plan(&["nope"], &[], &none),
        Err(PlanError::Unknown(_))
    ));
    assert!(matches!(
        plan(&["jq"], &["jq"], &none),
        Err(PlanError::Conflict(_))
    ));
    assert!(matches!(plan(&[], &[], &none), Err(PlanError::Empty)));
    let have: BTreeSet<String> = ids(&["node", "pnpm"]).into_iter().collect();
    let e = plan(&[], &["node"], &have).unwrap_err();
    assert_eq!(
        e,
        PlanError::StillRequired {
            id: "node".into(),
            by: "pnpm".into()
        }
    );
    assert!(plan(&[], &["node", "pnpm"], &have).is_ok());
    assert_eq!(
        PlanError::Unverified {
            id: "x".into(),
            reason: "y".into()
        }
        .code(),
        "unverified_tool"
    );
}

#[test]
fn argv_is_built_from_the_catalog_never_a_shell_string() {
    let c = embedded().unwrap();
    let p = build_plan(
        &c,
        Arch::Arm64,
        &BTreeSet::new(),
        &PlanRequest {
            install: ids(&["codex", "github-cli"]),
            remove: vec![],
        },
    )
    .unwrap();
    let npm = p.steps.iter().find_map(|s| match &s.action {
        Action::Exec { argv } if argv[0] == "npm" => Some(argv.clone()),
        _ => None,
    });
    assert_eq!(
        npm.unwrap(),
        ids(&[
            "npm",
            "install",
            "-g",
            "--prefix",
            "{home}/.local",
            "@openai/codex"
        ])
    );
    let repo = p.steps.iter().find_map(|s| match &s.action {
        Action::AptRepo {
            fingerprints, uri, ..
        } => Some((fingerprints.clone(), uri.clone())),
        _ => None,
    });
    let (fps, uri) = repo.unwrap();
    assert_eq!(fps.len(), 2);
    assert!(uri.starts_with("https://"));
    assert!(p.needs_root);
    let node_plan = build_plan(
        &c,
        Arch::Arm64,
        &BTreeSet::new(),
        &PlanRequest {
            install: ids(&["node"]),
            remove: vec![],
        },
    )
    .unwrap();
    let rel = node_plan.steps.iter().find_map(|s| match &s.action {
        Action::Release { arch_name, .. } => Some(arch_name.clone()),
        _ => None,
    });
    assert_eq!(rel.unwrap(), "arm64");
    assert!(!node_plan.needs_root);
    // Removal steps come out as removals.
    let rm = build_plan(
        &c,
        Arch::Amd64,
        &ids(&["neovim"]).into_iter().collect(),
        &PlanRequest {
            install: vec![],
            remove: ids(&["neovim"]),
        },
    )
    .unwrap();
    assert_eq!(rm.tools[0].op, Op::Remove);
    assert!(matches!(rm.steps[0].action, Action::AptRemove { .. }));
}

#[test]
fn default_tools_are_verified_and_baked_into_the_image_exactly_as_the_catalog_says() {
    let c = embedded().unwrap();
    let provision = include_str!("../../../infra/packer/ozbox-image/scripts/provision.sh");
    let defaults: Vec<&ozbox_catalog::Tool> = c.tools.iter().filter(|t| t.default).collect();
    let names: Vec<&str> = defaults.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(names, vec!["claude-code", "github-cli"]);
    for t in defaults {
        assert!(t.verified);
        for d in &t.install {
            if let ozbox_catalog::Step::AptRepo {
                key_url,
                key_fingerprints,
                uri,
                suite,
                packages,
                ..
            } = &d.step
            {
                assert!(provision.contains(key_url.as_str()), "{}: key url", t.id);
                assert!(provision.contains(uri.as_str()), "{}: uri", t.id);
                assert!(provision.contains(suite.as_str()));
                for f in key_fingerprints {
                    assert!(provision.contains(f.as_str()), "{}: fingerprint {f}", t.id);
                }
                for p in packages {
                    assert!(provision.contains(p.as_str()), "{}: package {p}", t.id);
                }
            }
        }
    }
}

// ---- Ollama: a zstd archive pinned to the digests of one release ----------------------------------------------------

/// The digests of `ollama-linux-<arch>.tar.zst` in release v0.40.15, from
/// https://github.com/ollama/ollama/releases/tag/v0.40.15 (the digest GitHub shows for each asset, which that release's own
/// sha256sum.txt lists too).
const OLLAMA_AMD64: &str = "628c018404a4206493efd38e46251c154ede5141b8b8dc85c659b3b027c47379";
const OLLAMA_ARM64: &str = "7f699ead5cdb4ae1ed89b888b148a238af188708800871e1889ab9dcee95f247";

#[test]
fn ollama_is_installable_from_one_pinned_release_on_both_architectures() {
    let c = embedded().unwrap();
    let t = c.tool("ollama").unwrap();
    assert!(t.verified && t.unverified_reason.is_none());
    assert!(t.source.contains("releases/tag/v0.40.15"));
    for (arch, digest, name) in [
        (Arch::Amd64, OLLAMA_AMD64, "amd64"),
        (Arch::Arm64, OLLAMA_ARM64, "arm64"),
    ] {
        let p = build_plan(
            &c,
            arch,
            &BTreeSet::new(),
            &PlanRequest {
                install: ids(&["ollama"]),
                remove: vec![],
            },
        )
        .unwrap();
        // the archive is zstd: the operating system's own zstd program comes first, as a root step from its signed archive
        let kinds: Vec<&str> = p
            .steps
            .iter()
            .map(|s| match &s.action {
                Action::AptUpdate => "update",
                Action::AptInstall { .. } => "apt",
                Action::Release { .. } => "release",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, ["update", "apt", "release"], "{kinds:?}");
        match &p.steps[1].action {
            Action::AptInstall { packages } => assert_eq!(packages, &["zstd".to_string()]),
            other => panic!("{other:?}"),
        }
        match &p.steps[2].action {
            Action::Release {
                base_url,
                asset,
                pinned_sha256,
                extract,
                arch_name,
                checksum_url,
                bins,
                ..
            } => {
                assert_eq!(
                    base_url,
                    "https://github.com/ollama/ollama/releases/download/v0.40.15/"
                );
                assert_eq!(asset, "ollama-linux-{arch}.tar.zst");
                assert_eq!(arch_name, name);
                assert_eq!(pinned_sha256.as_deref(), Some(digest));
                assert_eq!(*extract, ozbox_catalog::model::Extract::TarZst);
                assert!(
                    checksum_url.is_empty(),
                    "nothing is fetched for the checksum"
                );
                assert_eq!(bins[0].path, "bin/ollama");
            }
            other => panic!("{other:?}"),
        }
        assert!(p.needs_root, "the zstd package is installed as root");
    }
}

#[test]
fn a_pinned_checksum_must_be_a_digest_for_every_architecture_and_name_one_exact_file() {
    let base = include_str!("../../../catalog/catalog.toml");
    let bad_hex = base.replace(OLLAMA_ARM64, "7f699ead");
    assert!(Catalog::parse(&bad_hex).unwrap_err().contains("64 hex"));
    let missing = base.replace(&format!("arm64 = \"{OLLAMA_ARM64}\"\n"), "");
    assert!(Catalog::parse(&missing)
        .unwrap_err()
        .contains("every architecture"));
    let wildcard = base.replace("ollama-linux-{arch}.tar.zst", "ollama-linux-*.tar.zst");
    assert!(Catalog::parse(&wildcard).unwrap_err().contains("wildcard"));
    // no pin and no checksum file is no checksum at all
    let none = base.replace(
        &format!(
            "[tool.install.pinned_sha256]\namd64 = \"{OLLAMA_AMD64}\"\narm64 = \"{OLLAMA_ARM64}\"\n"
        ),
        "",
    );
    assert!(Catalog::parse(&none).unwrap_err().contains("checksum"));
}

// ---- OpenTofu: one pinned release, signed by the vendor's release workflow ---------------------------------------------

/// The digests of `tofu_1.13.9_linux_<arch>.tar.gz`, from the release's own `tofu_1.13.9_SHA256SUMS` (whose cosign signature
/// was verified against the release workflow's identity) and equal to the digest GitHub shows for each asset.
const TOFU_AMD64: &str = "b34b327cc1ef07178207b6f2cd1f5276537d3e5b7be316500f6dac50d4c0a857";
const TOFU_ARM64: &str = "5dc196dde75b667e4806d358310ec96742774cd0993c54c1237efee5644b69b8";

#[test]
fn opentofu_is_installable_from_one_pinned_release_on_both_architectures() {
    let c = embedded().unwrap();
    let t = c.tool("opentofu").unwrap();
    assert!(t.verified && t.unverified_reason.is_none());
    assert!(t.source.contains("releases/tag/v1.13.9"));
    for (arch, digest, name) in [
        (Arch::Amd64, TOFU_AMD64, "amd64"),
        (Arch::Arm64, TOFU_ARM64, "arm64"),
    ] {
        let p = build_plan(
            &c,
            arch,
            &BTreeSet::new(),
            &PlanRequest {
                install: ids(&["opentofu"]),
                remove: vec![],
            },
        )
        .unwrap();
        // one download as the box user, nothing as root
        assert_eq!(p.steps.len(), 1, "{:?}", p.steps);
        assert!(!p.needs_root);
        match &p.steps[0].action {
            Action::Release {
                base_url,
                asset,
                pinned_sha256,
                extract,
                arch_name,
                checksum_url,
                bins,
                ..
            } => {
                assert_eq!(
                    base_url,
                    "https://github.com/opentofu/opentofu/releases/download/v1.13.9/"
                );
                assert_eq!(asset, "tofu_1.13.9_linux_{arch}.tar.gz");
                assert_eq!(arch_name, name);
                assert_eq!(pinned_sha256.as_deref(), Some(digest));
                assert_eq!(*extract, ozbox_catalog::model::Extract::TarGz);
                assert!(checksum_url.is_empty());
                assert_eq!(bins[0].name, "tofu");
            }
            other => panic!("{other:?}"),
        }
    }
}

// ---- Playwright: a pinned package, the libraries from the version's own table, the browser as the box user -------------

/// What Playwright 1.65.0's own dependency table lists for Chromium on Ubuntu 24.04: its `tools` (a virtual display and
/// fonts) then its `chromium` libraries, the same set `playwright install-deps chromium` installs. Copied from that
/// version's `playwright-core` (the table is identical for x64 and arm64), never written from memory.
const PLAYWRIGHT_DEPS: [&str; 33] = [
    "xvfb",
    "fonts-noto-color-emoji",
    "fonts-unifont",
    "libfontconfig1",
    "libfreetype6",
    "xfonts-cyrillic",
    "xfonts-scalable",
    "fonts-liberation",
    "fonts-ipafont-gothic",
    "fonts-wqy-zenhei",
    "fonts-tlwg-loma-otf",
    "fonts-freefont-ttf",
    "libasound2t64",
    "libatk-bridge2.0-0t64",
    "libatk1.0-0t64",
    "libatspi2.0-0t64",
    "libcairo2",
    "libcups2t64",
    "libdbus-1-3",
    "libdrm2",
    "libgbm1",
    "libglib2.0-0t64",
    "libnspr4",
    "libnss3",
    "libpango-1.0-0",
    "libx11-6",
    "libxcb1",
    "libxcomposite1",
    "libxdamage1",
    "libxext6",
    "libxfixes3",
    "libxkbcommon0",
    "libxrandr2",
];

#[test]
fn playwright_installs_libraries_as_root_from_a_fixed_list_then_the_package_and_browser_as_the_box_user(
) {
    let c = embedded().unwrap();
    let t = c.tool("playwright-browsers").unwrap();
    assert!(t.verified && t.unverified_reason.is_none());
    for arch in [Arch::Amd64, Arch::Arm64] {
        let have: BTreeSet<String> = ids(&["node"]).into_iter().collect();
        let p = build_plan(
            &c,
            arch,
            &have,
            &PlanRequest {
                install: ids(&["playwright-browsers"]),
                remove: vec![],
            },
        )
        .unwrap();
        let mut libs = None;
        let mut execs: Vec<Vec<String>> = vec![];
        for s in &p.steps {
            match &s.action {
                Action::AptInstall { packages } => libs = Some(packages.clone()),
                Action::Exec { argv } => execs.push(argv.clone()),
                Action::AptUpdate => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(libs.unwrap(), ids(&PLAYWRIGHT_DEPS));
        // the package is pinned to one version, then the browser is downloaded by it, both as the box user
        assert_eq!(execs.len(), 2, "{execs:?}");
        assert_eq!(
            execs[0],
            ids(&[
                "npm",
                "install",
                "-g",
                "--prefix",
                "{home}/.local",
                "playwright@1.65.0"
            ])
        );
        assert_eq!(execs[1], ids(&["playwright", "install", "chromium"]));
        // never the vendor's own root installer, which runs apt for whatever it likes
        assert!(
            !execs.iter().flatten().any(|a| a == "install-deps"),
            "{execs:?}"
        );
        assert!(
            p.needs_root,
            "the libraries are installed from the operating system's archive"
        );
    }
}

#[test]
fn playwright_needs_node_and_removal_clears_the_package_and_the_browser_cache() {
    let c = embedded().unwrap();
    let e = build_plan(
        &c,
        Arch::Amd64,
        &BTreeSet::new(),
        &PlanRequest {
            install: ids(&["playwright-browsers"]),
            remove: vec![],
        },
    )
    .unwrap();
    // node comes first when it is not there yet
    let first_exec = e.steps.iter().find_map(|s| match &s.action {
        Action::Release { .. } => Some("release"),
        Action::Exec { .. } => Some("exec"),
        _ => None,
    });
    assert_eq!(
        first_exec,
        Some("release"),
        "node is installed before the package"
    );
    let have: BTreeSet<String> = ids(&["node", "playwright-browsers"]).into_iter().collect();
    let r = build_plan(
        &c,
        Arch::Amd64,
        &have,
        &PlanRequest {
            install: vec![],
            remove: ids(&["playwright-browsers"]),
        },
    )
    .unwrap();
    let text = format!("{:?}", r.steps);
    assert!(text.contains(".cache/ms-playwright"), "{text}");
    assert!(text.contains("playwright"), "{text}");
}

// ---- the docs page that lists the catalogue ------------------------------------------------------------------------------

#[test]
fn the_docs_page_lists_every_installable_tool_and_none_that_cannot_be_installed() {
    let page = include_str!("../../../docs/tools.md");
    let c = embedded().unwrap();
    for t in &c.tools {
        let cell = format!("| `{}` |", t.id);
        if t.verified {
            assert!(page.contains(&cell), "{} is missing from the page", t.id);
        } else {
            assert!(
                !page.contains(&cell),
                "{} cannot be installed but is listed",
                t.id
            );
        }
    }
}
