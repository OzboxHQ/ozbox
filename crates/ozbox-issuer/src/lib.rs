//! The off-box issuer for Production secrets (ADR 0029, Amendment 6 section 4 and Amendment 9).
//!
//! A Production value is released by exactly one principal: a small function in the owner's own cloud account, not the box.
//! This crate is that function's logic, written so every outside thing it touches is a trait a test can stand in for:
//!
//! * [`state::StateStore`]: the issuer's own record, with compare-and-set writes (a table with conditional writes);
//! * [`engine::SecretReader`]: reads one secret version with a session that names that one version, for at most 900 seconds
//!   (an assumed role with a session policy);
//! * [`engine::Audit`]: an append-only record of every request, approval and release, written *before* a release goes out.
//!
//! What it holds is **public**: the passkeys' and laptop keys' public halves, the recovery key's, each box's pinned service key
//! and store id. It makes the challenge itself ([`engine::Issuer::request`]), checks the answer itself
//! ([`verify`]), keeps the approval in its own state, and releases a value sealed to the box's service key
//! (`ozbox-seal`). The box relays and attests; it never decides, and it never holds a credential that can read Production.
//!
//! Production approvals (ADR 0042 D1): a passkey is accepted only on an origin listed in
//! [`engine::Config::independent_approval_origins`] (an origin the box does not serve; default none), so until one exists
//! Production is approved by a laptop key that asks the person present, or the recovery key. The laptop's presence is what the
//! owner declares for the key today; proving it from a verified attestation (ADR 0041) is **pending phase 2**.
//!
//! Not here (phase 2): the AWS adapters for the three traits, the function's runtime loop, approval notifications, rotation and
//! the GitHub App token. Nothing in this crate calls a network.

pub mod engine;
pub mod state;
pub mod verify;

/// An approval lasts at most this long, and a read of one secret by the issuer's assumed role lasts at most this long.
pub const MAX_WINDOW_SECS: u64 = 900;
/// A challenge that nobody answered stops being good after this long.
pub const CHALLENGE_TTL_MS: u64 = 5 * 60_000;
