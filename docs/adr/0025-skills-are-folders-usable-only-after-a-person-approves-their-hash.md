# 0025 — Skills are folders, usable only after a person approves their exact hash

**Decision.** A skill is a folder with a `SKILL.md` (the open Agent Skills format: a name, a description, optional version and
files). Oz Box adds a catalog, per-scope installs and a review gate.

1. **Content-addressed.** A skill's hash is a SHA-256 over every path and file, each length-prefixed. Installing copies the files
   into a snapshot named by that hash. Approving records `(name, hash, person)`.
2. **Usable means approved at the installed hash, and intact.** A skill is offered to an agent only if it is installed for the
   agent's fleet, box or project, a person approved the hash that is installed, and the snapshot still hashes to that value. A
   change to the source gives a new hash and no approval; a snapshot edited on disk stops matching and stops being usable until
   it is installed again. Approvals nothing refers to are dropped, so a changed skill really starts again unapproved.
3. **The approval is of what was read.** Approving names a hash; if the files changed since the page was loaded the approval is
   refused as stale. A person sees every file first (`ozbox skills approve` prints them and asks).
4. **Only plain text, small, and secret-free.** At most 50 files, 128 KB each, 512 KB in all; text extensions only; no links or
   special files; no path escapes; the same secret screen as memory (ADR 0024).
5. **Agents only read.** The tool host offers `skills_list` and `skills_read`; there is no tool to add, install, approve or
   change a skill. A skill is guidance, not security: the server's limits and approvals hold whatever a skill says.
6. **Shipped skills are ordinary skills.** The ones in the repository's `skills/` folder are compiled into the program and appear
   in the catalog as `bundled`; they are just as unusable until approved. A person's own skills sit in a library folder.

**Why.** A skill is instructions an agent follows with the box's authority. Loading one that a person has not read, or one that
changed after they read it, is the supply-chain failure. Hashing the files makes "the thing I reviewed" exact.

**Cost.** Every edit to a skill needs a new review, which is the point and also friction for someone iterating; the library keeps
the working copy apart from what is installed. Signing by a publisher (so a team can trust an author instead of reading every
file) is not part of this decision.

**Amended by [0051](0051-a-skill-can-be-put-on-a-boxs-own-disk-only-as-the-exact-files-a-person-approved-and-the-box-checks-them-again.md).**
A person can also put an approved skill on a box's own disk, where its coding agents read it, and add skills of their own from the
page. Points 1 to 5 still hold; the file rules now also refuse hidden and direction-changing characters.

**Amended by [0057](0057-one-conversation-fabric-agents-people-groups-and-fleets-post-to-mailboxes-on-the-hub-and-a-message-is-data.md) (2026-11-17, Preview).** A skill a person approved for a box or a project on `main` is usable by that
box's or project's agents on any worker: the hub sends its `SKILL.md` with the approved hash and the text's own digest, and the worker
serves it only when the digest matches. Its other files stay on the hub. Approval stays with a person on the hub.
