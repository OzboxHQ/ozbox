use thiserror::Error;

/// Every error carries a message a person can act on. Provider errors never include secret values.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid box name {name:?}: {reason}")]
    InvalidName { name: String, reason: &'static str },

    #[error("no box named {0:?}")]
    NotFound(String),

    #[error("a box named {0:?} already exists")]
    AlreadyExists(String),

    #[error("box {name:?} is {state}, so it cannot be {action}")]
    InvalidState {
        name: String,
        state: crate::BoxState,
        action: &'static str,
    },

    /// The provider cannot do this at all (e.g. shrink a VPS disk). Raised while PLANNING, before any change.
    #[error("{provider} cannot {what}: {why}")]
    Unsupported {
        provider: String,
        what: String,
        why: String,
    },

    #[error("the plan is stale: {0}. Plan again before applying.")]
    StalePlan(String),

    #[error("command `{program}` failed (exit {code:?}): {stderr}")]
    Command {
        program: String,
        code: Option<i32>,
        stderr: String,
    },

    #[error("provider error: {0}")]
    Provider(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
