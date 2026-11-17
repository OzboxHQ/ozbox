//! Memory and skills as the conversation fabric carries them to other boxes (ADR 0056, amending ADR 0024 and 0025).
//!
//! The hub's memory and skills stores stay the authority. What leaves the hub for a worker is only what an agent there could read
//! on the hub: **approved**, unexpired notes of one wall, and skills a person approved at their installed hash. A proposal from an
//! agent on a worker is filed here as **pending**, credited to that agent's fabric address and naming its box, and a person reviews
//! it exactly as one made on the hub. Nothing here approves, edits or forgets a note, or installs or approves a skill.

use ozbox_core::fabric::walls::{Proposal, SharedNote, SharedSkill, MAX_NOTES_PER_WALL};
use ozbox_core::fabric::FabricError;

use crate::memory::{
    AgentCtx, Caller, Entry, Filter, MemError, Memory, NewEntry, Scope, ScopeKind,
};
use crate::skills::{InstallScope, SkillStore};

/// An agent caller bound to exactly one wall: what the hub sends a worker is what such a caller reads.
fn reader_of(scope: &Scope) -> Caller {
    let mut ctx = AgentCtx {
        person: String::new(),
        run: None,
        terminal: None,
        projects: Vec::new(),
        box_name: None,
        origin: None,
    };
    match scope.kind {
        ScopeKind::Person => ctx.person = scope.name.clone(),
        ScopeKind::Project => ctx.projects.push(scope.name.clone()),
        ScopeKind::Box => ctx.box_name = Some(scope.name.clone()),
    }
    Caller::Agent(ctx)
}

pub fn shared(e: Entry) -> SharedNote {
    SharedNote {
        id: e.id,
        scope: e.scope,
        title: e.title,
        body: e.body,
        tags: e.tags,
        written_by: e.provenance.actor,
        written_box: e.provenance.box_name,
        reviewed_by: e.provenance.reviewed_by,
        reviewed_ms: e.provenance.reviewed_ms,
        revision: e.revision,
        updated_ms: e.updated_ms,
    }
}

/// The approved, unexpired notes of one wall, newest first.
pub fn approved_notes(m: &Memory, scope: &str, now: u64) -> Vec<SharedNote> {
    let Ok(scope) = Scope::parse(scope) else {
        return Vec::new();
    };
    let f = Filter {
        scope: Some(scope.clone()),
        ..Filter::default()
    };
    m.list(&reader_of(&scope), &f, now)
        .unwrap_or_default()
        .into_iter()
        .take(MAX_NOTES_PER_WALL)
        .map(shared)
        .collect()
}

/// The skills a person approved for one wall (`box:` or `project:`), each with its `SKILL.md`.
pub fn approved_skills(s: &SkillStore, scope: &str) -> Vec<SharedSkill> {
    let Ok(install) = InstallScope::parse(scope) else {
        return Vec::new();
    };
    if install == InstallScope::Fleet {
        return Vec::new();
    }
    let scopes = [install];
    s.usable(&scopes)
        .into_iter()
        .filter_map(|u| {
            let text = s.read(&u.name, None, &scopes).ok()?;
            Some(SharedSkill {
                scope: scope.to_string(),
                text_sha256: SharedSkill::text_digest(&text),
                name: u.name,
                description: u.description,
                version: u.version,
                hash: u.hash,
                text,
            })
        })
        .collect()
}

fn fabric_err(e: MemError) -> FabricError {
    match e {
        MemError::Denied(m) => FabricError::Refused(m),
        MemError::Secret(_) => FabricError::Refused(e.to_string()),
        MemError::Limit(m) => FabricError::Limit(m),
        MemError::Invalid(m) => FabricError::Invalid(m),
        MemError::NotFound => FabricError::NotFound("there is no such note".into()),
        MemError::Io(m) => FabricError::Unavailable(m),
    }
}

/// File a worker agent's proposal as pending, credited to its fabric address and box. The proposal's person, box and address were
/// set by the hub from its registry and the channel; the scope must be one that agent could read.
pub fn file_proposal(m: &Memory, p: &Proposal, now: u64) -> Result<String, FabricError> {
    let scope = Scope::parse(&p.note.scope).map_err(fabric_err)?;
    let mut ctx = AgentCtx {
        person: p.person.clone(),
        run: None,
        terminal: None,
        projects: Vec::new(),
        box_name: None,
        origin: Some(p.by.to_string()),
    };
    match scope.kind {
        ScopeKind::Person => {}
        ScopeKind::Project => ctx.projects.push(scope.name.clone()),
        ScopeKind::Box => ctx.box_name = Some(scope.name.clone()),
    }
    // a worker's agent never proposes into another box's wall
    if scope.kind == ScopeKind::Box && scope.name != p.from_box {
        return Err(FabricError::Refused(
            "a box wall takes proposals only from that box".into(),
        ));
    }
    let e = m
        .write(
            &Caller::Agent(ctx),
            &scope,
            NewEntry {
                title: p.note.title.clone(),
                body: p.note.body.clone(),
                tags: p.note.tags.clone(),
                expires_ms: p.note.expires_ms,
            },
            now,
        )
        .map_err(fabric_err)?;
    Ok(e.id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ozbox_core::fabric::walls::NewProposal;
    use ozbox_core::fabric::Address;

    use super::*;
    use crate::memory::State;

    fn proposal(scope: &str, body: &str) -> Proposal {
        Proposal {
            id: "p1".into(),
            by: Address::agent("box-b", "beta"),
            person: "alice".into(),
            from_box: "box-b".into(),
            note: NewProposal {
                scope: scope.into(),
                title: "Invoices round half-even".into(),
                body: body.into(),
                tags: vec!["rounding".into()],
                expires_ms: None,
            },
        }
    }

    #[test]
    fn a_proposal_from_another_box_is_pending_credited_and_shared_only_after_review() {
        let d = tempfile::tempdir().unwrap();
        let m = Memory::open(d.path()).unwrap();
        let id = file_proposal(
            &m,
            &proposal("project:billing", "The ledger rounds half-even."),
            10,
        )
        .unwrap();
        assert!(approved_notes(&m, "project:billing", 11).is_empty());
        let p = m.get(&Caller::Person("alice".into()), &id, 11).unwrap();
        assert_eq!(p.state, State::Pending);
        assert_eq!(p.provenance.actor, "agent:box-b/beta");
        assert_eq!(p.provenance.box_name.as_deref(), Some("box-b"));
        m.approve(&Caller::Person("alice".into()), &id, 12).unwrap();
        let shared = approved_notes(&m, "project:billing", 13);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].written_box.as_deref(), Some("box-b"));
        assert_eq!(shared[0].reviewed_by.as_deref(), Some("alice"));
        // other walls are not touched
        assert!(approved_notes(&m, "project:payroll", 13).is_empty());
        assert!(approved_notes(&m, "person:alice", 13).is_empty());
    }

    #[test]
    fn a_proposal_is_screened_and_cannot_reach_another_boxs_wall() {
        let d = tempfile::tempdir().unwrap();
        let m = Memory::open(d.path()).unwrap();
        let secret = &["gh", "p_", "SENTINELsentinel", "0123456789abcdefXYZ"].concat();
        let e = file_proposal(&m, &proposal("project:billing", secret), 10).unwrap_err();
        assert!(!e.to_string().contains(secret.as_str()));
        assert!(file_proposal(&m, &proposal("box:box-a", "x"), 10).is_err());
        assert!(file_proposal(&m, &proposal("box:box-b", "ok"), 10).is_ok());
    }
}
