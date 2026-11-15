# Creatives and media

Writers, designers, video makers, podcasters and studios spend a lot of time on everything around the creative work:
research, drafts, transcripts, file wrangling, exports, applications. An Oz Box gives an AI agent a machine of its own for
that, with a large disk and real compute in your own cloud account, so your laptop stays free and your files stay yours.

See [how to read the status](README.md#how-to-read-the-status). Everything here is **Preview** at most: built and tested, not
yet run end to end by a creative team on a real box.

**Ground rules:** the agent drafts, sorts and converts; you make the creative calls and approve anything published. Your
voice and style live in skills you approve, so the agent follows them and nothing else.

---

## 1. A content calendar in your voice

**You want:** a month of social posts drafted in your brand's voice, ready for you to edit and schedule.

Write your voice and rules once as a skill (`ozbox skills add ./brand-voice`, then `ozbox skills approve brand-voice`), then ask
from chat: *"Draft next month's posts for the launch using brand-voice."*

**Underneath:** the agent follows the approved skill; drafts are saved on the box for you to edit.
**Limits:** it drafts only; publishing is yours.
**Status:** Preview.

## 2. Research packs for writers

**You want:** sources, quotes and facts gathered and checked for a piece you are writing.

**Underneath:** the agent reads the pages you allow (read-only, from hosts you list) and builds a research pack with a link for
every claim.
**Limits:** always check quotes against the source; the pack links each one.
**Status:** Preview.

## 3. Video and podcast production helper

**You want:** transcripts, show notes, chapters, titles and suggested clips for each episode.

Upload the episode to the box and ask from chat: *"Transcribe /work/episodes/ep42.mp4, write show notes and five clip ideas
with timestamps."*

**Underneath:** transcription and drafting run on cloud hardware; a local speech model can keep audio inside your account.
**Limits:** add the transcription tool you prefer to the box (`ozbox tools`); accuracy depends on the audio.
**Status:** Preview.

## 4. Organising a media library

**You want:** thousands of images and clips tagged, renamed consistently and de-duplicated.

**Underneath:** the work runs on the box's own disk (grow it with `ozbox resize --disk`), not your laptop; the agent writes a
plan of renames first and applies it after you approve.
**Limits:** keep a snapshot before a large rename (`ozbox snapshot <box>`).
**Status:** Preview.

## 5. Batch exports and conversions

**You want:** a whole folder resized, converted and exported to several formats while you keep working.

**Underneath:** the box does the heavy lifting; size it up for the job and back down after (`ozbox resize`). A schedule can run
it overnight.
**Limits:** GPU sizes cost more per hour; pause the box when it is idle.
**Status:** Preview.

## 6. Pitch decks and creative briefs

**You want:** your notes turned into a first-draft deck or brief.

**Underneath:** a supervised run following your deck structure as an approved skill; the draft is saved for you to design.
**Limits:** layout and visuals are yours; it drafts the words and structure.
**Status:** Preview.

## 7. Translation and localisation drafts

**You want:** scripts and captions drafted in other languages for a human translator to finish.

**Underneath:** drafts are saved next to the source with a glossary the agent follows (a memory note or a skill).
**Limits:** always have a fluent person review; machine translation misses tone and culture.
**Status:** Preview.

## 8. Portfolio and website updates

**You want:** new projects added to your portfolio site, previewed before anything goes live.

**Underneath:** the agent edits the site's files on the box and shows a preview you open from any device; publishing waits for
your approval.
**Limits:** works best with a site built from files (a static site); site builders with only a web editor are not reachable.
**Status:** Preview.

## 9. Grant, festival and award applications

**You want:** the repetitive parts of applications filled in from your stored bio, credits and project details.

**Today:** the agent drafts every answer from your notes in memory, for you to paste in. Filling and submitting the online forms
for you is not supported yet (the agent's browser tool reads pages; it does not submit forms).
**Status:** Preview (drafting); Planned (filling and submitting online forms with your approval).

## 10. A studio workstation you reach from anywhere

**You want:** one persistent workspace with your tools, files and agent, reachable from a laptop, a tablet or a borrowed
computer.

Open the box's browser desktop (`ozbox desktop <box>`) or its web editor (`ozbox ide <box>`) on your own address behind your
sign-in.

**Underneath:** the box keeps running and keeps your files on its `/work` disk; you pause it when you are done to pay only for
storage.
**Limits:** the browser desktop has not been tried on a real box from a tablet yet.
**Status:** Preview.

See also: [One box](one-box.md), [Coding from anywhere](coding-from-anywhere.md) (the IDE, desktop and your own domain),
[Chat with your agents](chat.md).
