# Skills for your agents

A skill is a folder of plain-text guidance an agent follows: how your team cuts a release, how to triage a red test run, how
to draft a reply. Oz Box keeps a library of them, makes a person read and approve the exact files before any agent sees one,
and can put an approved skill on a box's own disk so the coding agents on it (Claude Code, and the programs that read the
shared agents folder) pick it up.

See [how to read the status](README.md#how-to-read-the-status). Everything here is **Preview**: built and covered by the
test suite and by browser tests that run a real dashboard and a real box daemon on one computer, not yet exercised on a real
cloud box. The design is in [ADR 0025](../adr/0025-skills-are-folders-usable-only-after-a-person-approves-their-hash.md) and
[ADR 0051](../adr/0051-a-skill-can-be-put-on-a-boxs-own-disk-only-as-the-exact-files-a-person-approved-and-the-box-checks-them-again.md).

**A skill is content an agent will follow with the authority of the box it runs on.** Read every file, including anything that
talks to the agent. A skill is guidance, not security: a limit the server enforces holds whatever a skill says.

---

## 1. Add a skill of your own

**You want:** your own instructions in the library.

1. Open **Skills** and choose **Add a skill** (an owner sees it; a member or viewer does not).
2. Either **Write one** (a name, a one-line description, a version, an optional licence and the instructions, plus any extra
   files), or **Upload files** (a folder with a `SKILL.md`, or the files themselves).
3. Choose **Add to library**. The review opens straight away.

The same thing from the command line, on the computer that runs the dashboard: `ozbox skills add <folder>` (the folder's name
must match the `name:` in its `SKILL.md`). The page says which folder your skills are kept in.

What a skill may hold: a `SKILL.md` and up to 49 more text files (`md`, `txt`, `json`, `yaml`, `yml`, `toml`, `sh`, `py`, `js`,
`ts`, `rs`, `sql`, `html`, `css`, `csv`), at most 128 KB each and 512 KB in all, in folders at most four deep. Refused: a path
that escapes the folder, a link, a file that is not text, a file that looks like it holds a key or a token, and any hidden or
direction-changing character (so what you read is what the agent reads). Scripts are allowed as text; they are marked in the
review, an agent may run them, and they are never made executable on a box.

**Status:** Preview.

## 2. Review and approve before any agent sees it

**You want:** to be sure what an agent will be told.

Choose **Review and approve**. The sheet shows where the skill came from (shipped with Oz Box, or who added it and how), a note on
what to look for (instructions to ignore rules, to hide what the agent did, to send data somewhere or to run something), and
every file as plain text, with a **Script** mark on files an agent may run. **Approve these files** records you as the reviewer
of exactly those files. Change one byte anywhere and the skill needs approving again.

**Status:** Preview.

## 3. Put an approved skill on a box's disk

**You want:** Claude Code (or another coding agent) on a box to use the skill when you work in a terminal there.

1. **Install**, then **On a box's disk**, then pick a running box and the folders. A box with Claude Code set up offers
   `~/.claude/skills`; Codex, Gemini CLI and OpenCode each document `~/.agents/skills` as a user-level skills folder.
2. Choose **Put on the box**. It is refused until a person approved the exact files, and the box checks them again before it
   writes anything.

What happens on the box: the files are written into a new folder and swapped into place, so an agent never reads half a
skill. A folder of the same name that you made by hand is left alone and the push is refused. **Remove from the box** deletes
only what a push made.

The card then lists each box that holds the skill and says **Matches the library**, **Different from the library** (the library
has moved on), **Changed on the box since it was put there** or **Missing from the box**. The box is asked every time (its
files are hashed again); a box that is stopped or cannot be reached is shown as not known, never as holding nothing. An agent
running as the box user can edit its own skills folder: Oz Box shows that it did, and pushing again puts the approved files
back, but it does not stop the edit.

Only an owner can put a skill on a box, because a skill is guidance a box's agents will follow.

**Status:** Preview.

## 4. Change a skill and keep the old version

**You want:** to iterate without losing what you had.

Add a skill with the same name and the page asks you to confirm it replaces the one in your library (version shown); the new
files are a new version that needs approval, and the old one is kept. **Earlier versions** lists the last twenty with who
added each and how; **Read** shows its files, and **Restore** makes it current again, as a new addition that needs approval.
Two people editing at once cannot overwrite each other silently: a replace names the version it saw, and the library refuses if
it changed.

A skill of your own with the name of one that ships with Oz Box is shown instead of it, and the page says so before you
confirm. **Delete from library** removes a skill of your own and its earlier versions; copies installed or on boxes stay until
you remove them.

**Status:** Preview.

## What is not built

- Signing by a publisher, or a shared skill hub.
- Putting a skill on several boxes in one step, and `ozbox` commands to put a skill on a box (use the dashboard).
- Proof on a real cloud box for every coding agent's folder.
