//! `ozbox auth init`: the public address and the allow-list for a dashboard on a shared machine, and what
//! `ozbox serve --public-behind-tunnel` loads.

use std::path::{Path, PathBuf};

use crate::cli::AuthCommand;
use crate::messages::t;
use crate::run::CliError;
use crate::serve::auth::config::{AccessCfg, AuthConfig, AuthFile, ClientCfg, UserEntry};
use crate::serve::PublicSetup;

pub(crate) fn default_path() -> Result<PathBuf, CliError> {
    crate::config::Config::path()
        .map(|p| p.with_file_name("auth.toml"))
        .ok_or_else(|| CliError::Msg(t("init.cli_no_home", &[])))
}

/// `id[,label=..][,github=..][,google=..][,access=..]`.
pub fn parse_person(spec: &str) -> Result<UserEntry, String> {
    let mut parts = spec.split(',');
    let id = parts.next().unwrap_or("").trim().to_string();
    let mut u = UserEntry {
        id,
        ..Default::default()
    };
    for p in parts {
        let (k, v) = p.split_once('=').ok_or_else(|| t("auth.bad_person", &[]))?;
        let v = v.trim().to_string();
        match k.trim() {
            "label" => u.label = v,
            "github" => u.github = Some(v),
            "google" => u.google = Some(v),
            "access" => u.access_email = Some(v),
            "role" => {
                u.role = Some(
                    ozbox_core::roles::Role::parse(&v).ok_or_else(|| t("auth.bad_person", &[]))?,
                );
            }
            _ => return Err(t("auth.bad_person", &[])),
        }
    }
    if u.id.is_empty() {
        return Err(t("auth.bad_person", &[]));
    }
    if !crate::serve::auth::config::valid_user_id(&u.id) {
        // the dashboard would refuse it later; say so now, and say what an id is (an email is the usual mistake)
        return Err(if u.id.contains('@') {
            t(
                "auth.person_is_email",
                &[("given", &u.id), ("id", &id_from_email(&u.id))],
            )
        } else {
            t("auth.bad_person_id", &[("given", &u.id)])
        });
    }
    Ok(u)
}

/// A suggested id for someone given by their email: the part before the `@`, in the letters an id may use.
fn id_from_email(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("");
    let mut id = String::new();
    for c in local.chars().flat_map(char::to_lowercase) {
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '-' };
        if !(c == '-' && (id.is_empty() || id.ends_with('-'))) {
            id.push(c);
        }
        if id.len() == 32 {
            break;
        }
    }
    let id = id.trim_end_matches('-').to_string();
    if id.is_empty() {
        "alice".into()
    } else {
        id
    }
}

/// `ozbox auth role <id> <role>`: write a person's role into the dashboard's own state (the strongest place it can be
/// chosen). It refuses a person who is not on the list and a change that would leave no owner.
fn set_role(id: &str, role: &str, file: Option<&Path>) -> Result<(), CliError> {
    use crate::serve::auth::state::AuthState;
    use ozbox_core::roles::{self, Role};
    let role = Role::parse(role)
        .ok_or_else(|| CliError::Msg("the role is owner, member or viewer".to_string()))?;
    let path = match file {
        Some(p) => p.to_path_buf(),
        None => default_path()?,
    };
    let cfg = AuthConfig::load_with_origin(&path, None).map_err(CliError::Msg)?;
    if !cfg.file.users.iter().any(|u| u.id == id) {
        return Err(CliError::Msg(format!(
            "{id} is not on the list in {}",
            path.display()
        )));
    }
    let state_path = path.with_file_name("auth-state.json");
    let mut state = AuthState::try_load(&state_path).map_err(CliError::Msg)?;
    let ids: Vec<String> = cfg.file.users.iter().map(|u| u.id.clone()).collect();
    let mut chosen = std::collections::BTreeMap::new();
    for u in &cfg.file.users {
        if let Some(r) = state.users.get(&u.id).and_then(|s| s.role).or(u.role) {
            chosen.insert(u.id.clone(), r);
        }
    }
    let before = roles::resolve(&ids, &chosen);
    let owners = before.values().filter(|r| **r == Role::Owner).count();
    if before.get(id) == Some(&Role::Owner) && role != Role::Owner && owners <= 1 {
        return Err(CliError::Msg(
            "that would leave the dashboard with no owner: make someone else an owner first"
                .to_string(),
        ));
    }
    state.users.entry(id.to_string()).or_default().role = Some(role);
    state
        .save(&state_path)
        .map_err(|e| CliError::Msg(e.to_string()))?;
    println!(
        "{id} is now {}. Start the dashboard again for it to apply.",
        role.name()
    );
    Ok(())
}

pub fn run(command: &AuthCommand, yes: bool) -> Result<(), CliError> {
    let AuthCommand::Init {
        origin,
        people,
        github_client_id,
        google_client_id,
        access_team,
        access_audience,
        out,
    } = command
    else {
        let AuthCommand::Role { id, role, file } = command else {
            return Ok(());
        };
        return set_role(id, role, file.as_deref());
    };
    let users = people
        .iter()
        .map(|p| parse_person(p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(CliError::Msg)?;
    let file = AuthFile {
        public_origin: origin.trim_end_matches('/').to_string(),
        users,
        github: ClientCfg {
            client_id: github_client_id.clone(),
        },
        google: ClientCfg {
            client_id: google_client_id.clone(),
        },
        access: access_team.as_ref().map(|team| AccessCfg {
            team_domain: team.clone(),
            audience: access_audience.clone().unwrap_or_default(),
        }),
        ..Default::default()
    };
    // Validates everything (the address, the people) before anything is written.
    let cfg = AuthConfig::new(file).map_err(CliError::Msg)?;
    let path = match out {
        Some(p) => p.clone(),
        None => default_path()?,
    };
    if path.exists() && !yes {
        return Err(CliError::Msg(t(
            "auth.exists",
            &[("path", &path.display().to_string())],
        )));
    }
    let text = toml::to_string_pretty(&cfg.file).map_err(|e| CliError::Msg(e.to_string()))?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&path, text).map_err(|e| CliError::Msg(e.to_string()))?;
    println!(
        "{}",
        t("auth.written", &[("path", &path.display().to_string())])
    );
    println!("{}", t("auth.passkey_note", &[]));
    if cfg.file.github.client_id.is_none() {
        println!("{}", t("auth.github_guide", &[("origin", &cfg.rp.origin)]));
    }
    if cfg.file.google.client_id.is_none() {
        println!("{}", t("auth.google_guide", &[("origin", &cfg.rp.origin)]));
    }
    println!("{}", t("auth.next", &[]));
    Ok(())
}

/// The settings for `--public-behind-tunnel` / `--public-url` (the address on the command line replaces the file's),
/// or `None` for the local-token mode.
pub fn public_setup(
    enabled: bool,
    path: Option<&Path>,
    public_url: Option<&str>,
) -> Result<Option<PublicSetup>, String> {
    if !enabled {
        return Ok(None);
    }
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_path().map_err(|e| e.to_string())?,
    };
    if !path.exists() {
        return Err(format!(
            "{} does not exist. Create it with: ozbox auth init --origin https://your-address --person owner",
            path.display()
        ));
    }
    let config = AuthConfig::load_with_origin(&path, public_url)?;
    Ok(Some(PublicSetup {
        config,
        state_path: Some(path.with_file_name("auth-state.json")),
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_role_is_part_of_a_person_and_a_wrong_one_is_refused() {
        use ozbox_core::roles::Role;
        assert_eq!(parse_person("ann").unwrap().role, None);
        assert_eq!(
            parse_person("bo,role=viewer").unwrap().role,
            Some(Role::Viewer)
        );
        assert_eq!(
            parse_person("cy,role=owner,label=Cy").unwrap().role,
            Some(Role::Owner)
        );
        assert!(parse_person("dee,role=admin").is_err());
        // the settings file the command writes carries it, and reads back
        let file = AuthFile {
            public_origin: "https://box.example.com".into(),
            users: vec![
                parse_person("ann").unwrap(),
                parse_person("bo,role=viewer").unwrap(),
            ],
            ..Default::default()
        };
        let text = toml::to_string(&file).unwrap();
        assert!(text.contains("role = \"viewer\""), "{text}");
        let back: AuthFile = toml::from_str(&text).unwrap();
        assert_eq!(back.users[1].role, Some(Role::Viewer));
        assert_eq!(back.users[0].role, None);
        // nobody but viewers: the first person who set it up is the owner, but an explicit demotion of the only owner is refused
        let mut none = file.clone();
        none.users[0].role = Some(Role::Viewer);
        assert!(AuthConfig::new(none).is_err());
    }

    #[test]
    fn an_operator_sets_a_role_in_the_state_and_cannot_remove_the_last_owner() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("auth.toml");
        std::fs::write(
            &file,
            "public_origin = \"https://box.example.com\"\n[[users]]\nid = \"ann\"\n[[users]]\nid = \"bob\"\n",
        )
        .unwrap();
        assert!(
            set_role("zed", "owner", Some(&file)).is_err(),
            "not on the list"
        );
        assert!(set_role("bob", "admin", Some(&file)).is_err(), "not a role");
        assert!(
            set_role("ann", "member", Some(&file)).is_err(),
            "the only owner"
        );
        set_role("bob", "owner", Some(&file)).unwrap();
        set_role("ann", "viewer", Some(&file)).unwrap();
        let state =
            crate::serve::auth::state::AuthState::try_load(&dir.path().join("auth-state.json"))
                .unwrap();
        assert_eq!(
            state.users["ann"].role,
            Some(ozbox_core::roles::Role::Viewer)
        );
        assert_eq!(
            state.users["bob"].role,
            Some(ozbox_core::roles::Role::Owner)
        );
        assert!(
            set_role("bob", "viewer", Some(&file)).is_err(),
            "now the only owner"
        );
    }

    #[test]
    fn people_are_parsed_and_every_catalogue_key_exists() {
        let u = parse_person("owner,label=Alice,github=alice-gh,google=a@example.com").unwrap();
        assert_eq!(u.github.as_deref(), Some("alice-gh"));
        assert!(
            parse_person("").is_err()
                && parse_person("a,nope=1").is_err()
                && parse_person("a,github").is_err()
        );
        let keys = crate::messages::keys();
        for k in [
            "auth.exists",
            "auth.bad_person",
            "auth.person_is_email",
            "auth.bad_person_id",
            "auth.written",
            "auth.next",
            "auth.github_guide",
            "auth.google_guide",
            "auth.passkey_note",
        ] {
            assert!(keys.contains(&k), "{k}");
        }
        assert!(t("auth.github_guide", &[("origin", "https://o")]).contains("Enable Device Flow"));
    }

    /// B4-13: `--person` takes an id, not an email. An email is refused at once (not later, on the box), saying what an id
    /// is and where the email goes instead; any other id the dashboard would refuse is refused here too.
    #[test]
    fn a_person_given_by_email_is_told_to_use_an_id_and_where_the_email_goes() {
        let e = parse_person("Jane.Doe@example.com").unwrap_err();
        assert!(
            e.contains("looks like an email address")
                && e.contains("--person jane-doe,google=Jane.Doe@example.com")
                && e.contains("access=Jane.Doe@example.com")
                && e.contains("Your id on the allow-list"),
            "{e}"
        );
        let e = parse_person("Alice,github=alice-gh").unwrap_err();
        assert!(e.contains("is not a person's id"), "{e}");
        assert!(parse_person(&"a".repeat(33)).is_err());
        // a valid id with the email where it belongs is fine
        let u = parse_person("jane,google=jane@example.com,role=owner").unwrap();
        assert_eq!(u.id, "jane");
        assert_eq!(id_from_email("..@example.com"), "alice");
        assert_eq!(id_from_email(&format!("{}@x", "b".repeat(40))).len(), 32);
    }
}
