//! The honest account of `ozbox secrets import`: every entry of the file ends in exactly one bucket, and the buckets add up to
//! the number of entries. Names, line numbers and fixed sentences only; nothing here ever holds or prints a value.

use serde_json::{json, Value};

use crate::messages::t;
use crate::workload::{Duplicate, Rejected};

/// Where one kept entry of the file ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Stored (an applied import).
    Stored,
    /// Would be stored (a preview).
    Ready,
    /// Looks like production and was not allowed.
    HeldBack,
    /// Already stored exactly so (same value, flag and mark): not written again.
    Unchanged,
    /// Not stored, with the words that say why.
    Skipped(String),
}

impl Outcome {
    pub fn word(&self) -> &'static str {
        match self {
            Outcome::Stored => "stored",
            Outcome::Ready => "ready",
            Outcome::HeldBack => "held_back",
            Outcome::Unchanged => "unchanged",
            Outcome::Skipped(_) => "skipped",
        }
    }
}

/// The counts. `ready_or_stored` is "stored" after an applied import and "ready" in a preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub applied: bool,
    pub entries: usize,
    pub ready_or_stored: usize,
    pub held_back: usize,
    /// Kept entries not stored for a reason, plus lines that are not `NAME=value`.
    pub skipped: usize,
    /// Earlier lines of a name that appears again: ignored, the last line is kept.
    pub duplicates: usize,
    pub unchanged: usize,
}

impl Report {
    pub fn new(
        outcomes: &[Outcome],
        duplicates: &[Duplicate],
        rejected: &[Rejected],
        applied: bool,
    ) -> Report {
        let count = |f: &dyn Fn(&Outcome) -> bool| outcomes.iter().filter(|o| f(o)).count();
        let dup: usize = duplicates.iter().map(|d| d.ignored_lines.len()).sum();
        Report {
            applied,
            entries: outcomes.len() + dup + rejected.len(),
            ready_or_stored: count(&|o| matches!(o, Outcome::Stored | Outcome::Ready)),
            held_back: count(&|o| *o == Outcome::HeldBack),
            skipped: count(&|o| matches!(o, Outcome::Skipped(_))) + rejected.len(),
            duplicates: dup,
            unchanged: count(&|o| *o == Outcome::Unchanged),
        }
    }

    /// The buckets always add up to the entries; a false answer is a bug here, never in the file.
    pub fn adds_up(&self) -> bool {
        self.ready_or_stored + self.held_back + self.skipped + self.duplicates + self.unchanged
            == self.entries
    }

    /// One line, e.g. `73 entries: 72 stored, 1 duplicate (line 40 kept, line 12 ignored)`. Empty buckets are left out.
    pub fn line(&self, duplicates: &[Duplicate]) -> String {
        let n = |v: usize| v.to_string();
        let mut parts: Vec<String> = Vec::new();
        let first = if self.applied {
            "secrets.report_stored"
        } else {
            "secrets.report_ready"
        };
        for (key, v) in [
            (first, self.ready_or_stored),
            ("secrets.report_held", self.held_back),
            ("secrets.report_skipped", self.skipped),
            ("secrets.report_unchanged", self.unchanged),
        ] {
            if v > 0 {
                parts.push(t(key, &[("n", &n(v))]));
            }
        }
        if self.duplicates > 0 {
            let detail = if duplicates.len() == 1 {
                format!(" ({})", duplicate_detail(&duplicates[0]))
            } else {
                format!(" ({})", t("secrets.report_dup_see_above", &[]))
            };
            parts.push(format!(
                "{}{}",
                t("secrets.report_duplicate", &[("n", &n(self.duplicates))]),
                detail
            ));
        }
        t(
            "secrets.report_line",
            &[("entries", &n(self.entries)), ("parts", &parts.join(", "))],
        )
    }

    pub fn json(&self) -> Value {
        json!({"applied": self.applied, "entries": self.entries,
            if self.applied { "stored" } else { "ready" }: self.ready_or_stored,
            "held_back": self.held_back, "skipped": self.skipped,
            "duplicates": self.duplicates, "unchanged": self.unchanged,
            "adds_up": self.adds_up()})
    }
}

/// `line 40 kept, line 12 ignored` (several ignored lines: `lines 3 and 12`).
pub fn duplicate_detail(d: &Duplicate) -> String {
    let ignored = d
        .ignored_lines
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>();
    t(
        "secrets.report_dup_detail",
        &[
            ("kept", &d.kept_line.to_string()),
            ("ignored", &ignored.join(", ")),
        ],
    )
}

pub fn duplicates_json(d: &[Duplicate]) -> Value {
    Value::Array(
        d.iter()
            .map(|d| json!({"name": d.name, "kept_line": d.kept_line, "ignored_lines": d.ignored_lines}))
            .collect(),
    )
}

pub fn rejected_json(r: &[Rejected]) -> Value {
    Value::Array(
        r.iter()
            .map(|r| json!({"line": r.line, "reason": r.reason}))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_reads_like_the_account_it_is() {
        let dup = vec![Duplicate {
            name: "A".into(),
            kept_line: 40,
            ignored_lines: vec![12],
        }];
        let mut o = vec![Outcome::Stored; 72];
        o.push(Outcome::Unchanged);
        let r = Report::new(&o, &dup, &[], true);
        assert!(r.adds_up());
        assert_eq!(r.entries, 74);
        assert_eq!(
            r.line(&dup),
            "74 entries: 72 stored, 1 unchanged (already stored with the same value), 1 duplicate (line 40 kept, line 12 ignored)"
        );
        let p = Report::new(&o[..2], &[], &[], false);
        assert_eq!(p.line(&[]), "2 entries: 2 ready to store");
        assert_eq!(p.json()["ready"], 2);
    }
}
