//! Where a message's link points, for each person it reaches.
//!
//! Just before an alert is handed to the worker, a one-time pointer link (`chat::links`: 24 random bytes, a keyed hash
//! held, ten minutes, that person only) is made for each person among its recipients, for the page the notice opens. A
//! shared place (a Slack channel, a fleet list, a webhook) gets the item's plain address instead, and a dashboard with no
//! public address gets words that name the page. The tokens live only in the outgoing message: they are never stored
//! with the alert, and a retry makes new ones.

use std::collections::BTreeSet;

use super::App;
use crate::channels::routing::{Planned, Target};
use crate::notify::{Alert, Reach};

impl App {
    /// The dashboard's public address: the one this server was started with (or its sign-in origin), else the tunnel's.
    pub(super) fn dashboard_base(&self) -> Option<String> {
        self.chat_public_base().or_else(|| {
            let p = self.access.tunnel_path.as_deref()?;
            let f = crate::tunnel::TunnelFile::load(p).ok()??;
            Some(f.public_url.trim().trim_end_matches('/').to_string()).filter(|u| !u.is_empty())
        })
    }

    /// The people an alert reaches through these deliveries: each routing rule's person, and the person each Telegram
    /// chat it goes to belongs to.
    fn recipients(&self, planned: &[(Planned, u32)]) -> BTreeSet<String> {
        let chats = &self.state.telegram.chats;
        let mut out = BTreeSet::new();
        for (pl, _) in planned {
            if let Some(p) = &pl.person {
                out.insert(p.clone());
            }
            match &pl.target {
                Target::Telegram(id) => {
                    out.extend(
                        chats
                            .iter()
                            .filter(|c| c.id == *id)
                            .filter_map(|c| c.person.clone()),
                    );
                }
                Target::Fleet(c) if c == "telegram" => {
                    out.extend(chats.iter().filter_map(|c| c.person.clone()));
                }
                _ => {}
            }
        }
        out
    }

    /// Make the links for one send of `alert`.
    pub(super) fn reach_alert(&mut self, alert: &mut Alert, planned: &[(Planned, u32)], now: u64) {
        let base = self.dashboard_base();
        let mut reach = Reach {
            base: base.clone(),
            ..Default::default()
        };
        if let (Some(open), Some(_)) = (alert.notice().open, base) {
            for person in self.recipients(planned) {
                if let Some(tok) = self.tg_pointer(&person, &open.path, now) {
                    reach.tokens.insert(person, tok);
                }
            }
        }
        alert.reach = reach;
    }
}
