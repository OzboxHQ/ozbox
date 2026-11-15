//! Which role each person on the dashboard's list has (see `ozbox_core::roles`).
//!
//! A role is chosen in one of three places, strongest first: the dashboard's own record (an owner changed it, which is
//! an audited act), the settings file's `role` for the person, and the default (the first person is the owner, the rest
//! are members). A dashboard made before roles existed has neither of the first two, so its people get the defaults and
//! the first, who set it up, is the owner: nobody is locked out by upgrading.

use std::collections::BTreeMap;

use ozbox_core::roles::{self, Role};

use super::{Auth, Inner};
use crate::serve::Req;

/// Why a role could not be changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleError {
    /// The person is not on the list.
    Unknown,
    /// It would leave the dashboard with no owner.
    LastOwner,
    /// The change could not be written, so it was not made.
    Save,
}

impl Auth {
    /// The role of every person on the list, in `inner`'s view of the stored roles.
    pub(crate) fn roles_in(&self, inner: &Inner) -> BTreeMap<String, Role> {
        let ids: Vec<String> = self.cfg.file.users.iter().map(|u| u.id.clone()).collect();
        let mut explicit = BTreeMap::new();
        for u in &self.cfg.file.users {
            let chosen = inner.state.users.get(&u.id).and_then(|s| s.role).or(u.role);
            if let Some(r) = chosen {
                explicit.insert(u.id.clone(), r);
            }
        }
        roles::resolve(&ids, &explicit)
    }

    /// The role of every person on the list.
    pub fn roles(&self) -> BTreeMap<String, Role> {
        let inner = self.lock();
        self.roles_in(&inner)
    }

    /// One person's role. Somebody not on the list is a viewer here, for display; what lets or refuses them is
    /// [`Auth::role_opt`], which says they have none.
    pub fn role_of(&self, user: &str) -> Role {
        self.role_opt(user).unwrap_or(Role::Viewer)
    }

    /// One person's role, or `None` for somebody who is not on the list (taken off it, or never on it): they may do
    /// nothing, whatever session or chat link they still hold.
    pub fn role_opt(&self, user: &str) -> Option<Role> {
        self.roles().get(user).copied()
    }

    /// Who is signed in on this request, and their role.
    pub fn who_and_role(&self, req: &Req) -> Option<(String, Role)> {
        let person = self.person(req)?;
        let role = self.role_opt(&person)?;
        Some((person, role))
    }

    /// Is the session stored under `key` alive, and does its person's role let them use the IDE and desktop of a box? Asked
    /// by the code hosts on every request, so a role taken away stops the next one, not only the next sign-in.
    pub fn session_may_use_boxes(&self, key: &str) -> bool {
        if !self.session_alive(key) {
            return false;
        }
        let inner = self.lock();
        let Some(user) = inner.sessions.user_of(key) else {
            return false;
        };
        let Some(role) = self.roles_in(&inner).get(user).copied() else {
            return false;
        };
        roles::allowed(role, ozbox_core::permissions::Action::CommandRun)
    }

    /// Give `user` a role. Returns the role they had. The caller has already checked that the one asking is an owner
    /// and has shown a passkey a moment ago, and records the change in the audit chain.
    pub fn set_role(&self, user: &str, role: Role) -> Result<Role, RoleError> {
        let mut inner = self.lock();
        if !self.cfg.file.users.iter().any(|u| u.id == user) {
            return Err(RoleError::Unknown);
        }
        let before = self.roles_in(&inner);
        let from = before.get(user).copied().unwrap_or(Role::Viewer);
        let owners = before.values().filter(|r| **r == Role::Owner).count();
        if from == Role::Owner && role != Role::Owner && owners <= 1 {
            return Err(RoleError::LastOwner);
        }
        let previous = inner.state.users.get(user).and_then(|u| u.role);
        inner.state.users.entry(user.to_string()).or_default().role = Some(role);
        if self.save_checked(&inner).is_err() {
            // not written, so not made
            if let Some(u) = inner.state.users.get_mut(user) {
                u.role = previous;
            }
            return Err(RoleError::Save);
        }
        Ok(from)
    }

    /// A signed-in session for `user`, for tests that need more than one person without walking each through enrolment:
    /// the cookie value, the CSRF token, and whether a passkey was just shown.
    #[cfg(test)]
    pub(crate) fn test_session(&self, user: &str, fresh: bool) -> (String, String) {
        use super::session::{random_token, Level, Session};
        let now = self.now();
        let csrf = random_token(16).unwrap_or_default();
        let s = Session {
            user: user.to_string(),
            level: Level::Full,
            created_ms: now,
            last_seen_ms: now,
            last_stepup_ms: fresh.then_some(now),
            csrf: csrf.clone(),
            via: "test",
            pending_totp: None,
        };
        let mut inner = self.lock();
        let id = inner
            .sessions
            .create(s, now, self.cfg.idle_ms, self.cfg.absolute_ms)
            .unwrap_or_default();
        (id, csrf)
    }
}
