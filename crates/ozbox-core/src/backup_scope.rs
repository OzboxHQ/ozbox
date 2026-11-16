//! What a backup of `/work` never holds, and what a restore never puts back. Shared by the box daemon, which builds the
//! restic commands, and the secrets service, which runs them and refuses any other shape.

/// Never in a backup: the secrets service's private folder on `/work` (its copy of the encrypted store and the audit
/// chain's anchors). The store's key is not there either (it never leaves the system disk), so a snapshot that predates
/// this rule holds ciphertext under a key it does not have; this keeps even the ciphertext out of the repository.
pub const NEVER_BACKED_UP: &[&str] = &["/work/ozbox-secrets-private"];

/// Never restored, from any snapshot, into any target: the private folder (an older backup still holds it), and the audit
/// chain (an older copy put back over the live one would cut its tail off; the chain is backed up as a record, and read
/// from the repository, never restored), and the record root keeps of this box's backup set-up (an old snapshot's copy put
/// back would say backups were set up, or carry settings, that are not this box's now: it is root's file about the box as
/// it is, never something a restore may write). The daemon's restic command and the secrets service's check both read this
/// list, so they change together.
pub const NEVER_RESTORED: &[&str] = &[
    "/work/ozbox-secrets-private",
    "/work/ozbox-audit",
    "/work/ozbox-backup",
];
