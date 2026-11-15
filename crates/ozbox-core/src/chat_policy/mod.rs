//! The policy of chat control (ADR 0050): what a message from a chat app may make Oz Box do.
//!
//! * [`acts`]: the closed table of acts, and the one parser that turns a message into exactly one of them.
//! * [`decide`]: the one pure function, [`decide::decide`], that returns `Allow`, `Handoff` or `Refuse`.
//! * [`records`]: the pairing window, the link and the delegation a passkey signs, and their digests.
//! * [`admit`]: which Telegram updates are heard, how fresh they must be, and the replay guard.
//!
//! Nothing here reads a clock, a file or the network. The bridge in `ozbox-cli` supplies the facts and does the acts.

pub mod acts;
pub mod admit;
pub mod decide;
pub mod records;

pub use acts::{act_table_json, parse_act, ActId, ChatAct, Needs, Reject, Tier};
pub use decide::{decide, Allowed, ChatChannel, Context, Decision, HandoffReason, Refusal};
