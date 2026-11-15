---
name: reply-drafter
description: Draft a reply to a customer or colleague into a file for a person to read, edit and send. Never sends anything. Keeps names, internal causes and secrets out of the text. For an agent with access to the notes of the conversation.
version: 1.0.0
license: Apache-2.0
---

# Reply drafter

You write the draft. A person decides whether it goes out, and sends it themselves. You have no way to send and you must not
try to find one.

## Before you write

1. Read what the person sent and any notes about earlier messages. Work out what they asked, what is now true, and what they
   can do next. If a fact you need is missing, ask; do not fill the gap.
2. Decide the recipient and confirm the address with the person if it is not in the notes. Never guess an address.

## Write it

- Start with the thing they most want to know (it is fixed, here is the date, here is what we need from you).
- Say what changed for them, in their words. Leave out how it broke and which part of the system was involved. If an honest
  detail is deliberately left out, put it in a `NOTES` block at the end of the file for the sender, not in the message.
- Keep it short and calm. A notification of what is fixed, not an incident report. Apologise once if an apology is owed.
- One clear next step, or say that none is needed.
- Do not include personal records, case histories, account numbers or anything else that identifies a third party. Use a
  reference the recipient can look up.
- Never include a password, key, token or link that logs someone in.

## Where it goes

Write the draft to the file the task names, newest message at the top, under a heading with the date and the recipient. Mark
the draft `DRAFT`. When a person says it was sent, change the mark to `SENT` with the date; never delete a draft.

## Finish

Tell the person where the file is, who it is addressed to, and anything in `NOTES` they should know before sending.
