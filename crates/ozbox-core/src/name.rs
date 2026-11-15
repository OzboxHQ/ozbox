use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A box name: 1–40 characters, lowercase letters, digits and single hyphens, starting with a letter.
///
/// It becomes part of hostnames, cloud resource names, tags and secret-store paths, so it is validated once,
/// here, and can be used anywhere without further escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BoxName(String);

impl BoxName {
    pub const MAX_LEN: usize = 40;

    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let name = raw.into();
        let bad = |reason| Error::InvalidName {
            name: name.clone(),
            reason,
        };
        if name.is_empty() || name.len() > Self::MAX_LEN {
            return Err(bad("must be 1 to 40 characters"));
        }
        if !name.starts_with(|c: char| c.is_ascii_lowercase()) {
            return Err(bad("must start with a lowercase letter"));
        }
        if name.ends_with('-') {
            return Err(bad("must not end with a hyphen"));
        }
        if name.contains("--") {
            return Err(bad("must not contain two hyphens in a row"));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(bad(
                "may contain only lowercase letters, digits and hyphens",
            ));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoxName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for BoxName {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<BoxName> for String {
    fn from(value: BoxName) -> Self {
        value.0
    }
}

impl std::str::FromStr for BoxName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for ok in ["a", "main", "worker-1", "test-lane-02"] {
            assert!(BoxName::new(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn rejects_names_that_would_break_hostnames_or_paths() {
        for bad in [
            "", "1box", "Main", "box-", "a--b", "a_b", "a.b", "a/b", "a b", "../x", "$(id)",
        ] {
            assert!(BoxName::new(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(BoxName::new("a".repeat(41)).is_err());
    }
}
