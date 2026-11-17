# Control your boxes from Telegram

Link your Telegram account to Oz Box with a passkey, decide in the dashboard what a phone may do, and then read the fleet and talk to
a coding agent on the boxes you chose from anywhere. **A chat never approves, denies, stops a run, raises a spending limit or
touches a secret**: it only tells you something is waiting, and you decide that in the dashboard with your passkey.

See [how to read the status](README.md#how-to-read-the-status). **Everything on this page is Preview**: built and covered by tests
against a fake Telegram and a software passkey, **not yet run on a real box with a real phone**. Use a test bot until you have done the
real-phone steps at the bottom. What is not built yet is listed in section 7, so nothing here promises it.

---

## 1. Link your account

**You want:** your own Telegram account to be heard by Oz Box, and nobody else's.

1. In Telegram, make a bot with BotFather (`/newbot`). Turn **group joining off** (`/setjoingroups`) and **privacy mode on**
   (`/setprivacy`). Oz Box refuses to run while its bot can be added to a group, reads every group message or answers inline queries.
2. In **Settings → Apps → Telegram** choose **Add bot token**, paste it (it is saved write-only and never shown again), and switch
   Telegram on.
3. Open your **Account** page and choose **Link an account**.
   1. **Open a pairing window** with your passkey. It lasts ten minutes. Until it is open, the bot says nothing to anyone.
   2. In a private chat with your bot send `/link`. It answers with a short code.
   3. Type the code into the dashboard. It shows the account the bot saw, as the tail of its number and the name Telegram gave. If it
      is not yours, stop.
   4. Confirm with a second passkey. If you want, tick **Enable chat on these boxes** and pick the boxes: one passkey touch then
      confirms the link and that permission together, so neither can be swapped after you touched.

The pairing is the other way round from a code the dashboard hands you: whoever sends a dashboard-made code first would be linked, so
here you open the window and you confirm. Five wrong codes close the window. A link lasts **30 days** and is renewed with a passkey.
A dashboard with **no sign-in cannot link Telegram** (there is no person to bind and no passkey to sign with), and one with **no public
address** can read but cannot delegate anything, because a phone could not be sent to it ("no address: Telegram cannot hand you to the
dashboard").

**Status:** Preview.

## 2. What a chat can do

Every message is read as exactly one act from a closed table, shown in **Settings → Apps → Telegram → What a chat can do**. A word that
is not in the table is refused.

| Kind | Messages | Needs |
|---|---|---|
| Look | `/status`, `/fleet`, `/box list`, `/tasks`, `/log`, `/sessions`, `/whoami`, `/help` | a link |
| Talk to an agent | plain text, `/new <box> <what to do>`, `/pause`, `/resume`, `/switch`, `/detach`, `/attach`, `/adopt` | **chat delegation** for that box |
| Start or pause a box, create or resize one, run one catalogue command | `/box resume`, `/box pause`, `/box extend`, `/box create`, `/box resize`, `/run` | **not in this release**: a delegation to them is not accepted yet |
| Sent to the dashboard | clone, snapshot, destroy a box; anything above what you delegated | a passkey in the dashboard |
| Refused | approve, deny, cancel, `/stop`, `/budget`, secrets, policy, people, roles, links, limits, tunnels, sending outbound messages, pushing to a protected branch, **every act on a Production box** | never |

A message that is not an act is plain text to an agent. A forwarded, quoted or replied-to message is someone else's words and is never
read as a command. A command with a typographic dash or quote in it (a phone keyboard turns `--` into one) is refused rather than
guessed at, and a command for another bot is refused.

**Status:** Preview.

## 3. Allow a phone to talk to agents

**You want:** to steer a coding agent on `main` from a bus.

On your Account page, under the link, choose **Allow chat on boxes**, pick the boxes and the days (7 by default, 30 at most) and
confirm with your passkey. Then `/new main fix the flaky test` from your phone starts a session the way the dashboard's Chat does.

- It is **per box**, never for a Production box, and off for the hub box that runs the dashboard unless you ticked that you know why.
- **Talking to an agent runs code on that box**, inside the chat profile: the agent asks before it does anything beyond reading, and
  every request waits for your passkey in the dashboard. A linked account that holds this permission can make an agent run code there.
  That is the real power you are delegating; keep it for boxes where that is acceptable.
- It lapses after **72 hours unused**, ends on its date, and is judged against your role **every time**: a demotion cuts it at the next
  message.
- A new link with no permission reads only for its first day. A permission made later waits out that first day; one made in the same
  step as the link does not.
- A **member's** permission also needs an owner's passkey, with the member's name in it (Account, "Waiting for your passkey").
- A row in the settings file with no passkey assertion behind it grants nothing, and one edited afterwards is refused: the Account page
  shows it as "Not backed by a passkey".

**Status:** Preview.

## 4. Lock it, cut it, hand off

- **`/lock`** in the chat makes this link read-only until you lift the lock with a passkey. **`/unlink`** cuts it. Anyone linked may
  send either, because they only make Telegram less able. The Account page has **Lock**, **Unlink** and an owner's **Lock every link**.
  A revoke takes effect on the next message, and ends everything delegated to the link.
- When something needs a passkey, the chat sends **one link to the dashboard** and does nothing else. The link is a pointer, not a
  credential: ten minutes, only for you, with the dashboard's own host named in the message, the token in the address's fragment (so no
  tunnel or proxy ever logs it), and opening it changes nothing. The bot deletes that message when the link lapses.
- **An approval or an alert** reaches your chat as one message: what to do first, the box and environment (Production marked),
  who asked, the risk and the expiry, and an **Open in dashboard** button under it. The button only opens the dashboard on that
  item, with a link made for you (the same ten minutes, only for you); once the request is decided, the link says so. That message
  is not deleted, so after ten minutes open the dashboard → **Approvals** as it says. See
  [Chat with your coding agents](chat.md#3-be-told-in-the-chat-decide-in-the-dashboard).
- A lost phone: unlink from the dashboard, and secure the Telegram account itself with Telegram's two-step verification and by ending
  its other sessions. Oz Box cannot see or enforce those.

**Status:** Preview.

## 5. What is kept, and what Telegram can see

- Telegram is not private: a bot's messages are not end to end encrypted and the vendor has no data agreement with the project. **Never
  type a secret into the bot.** Nothing secret is sent to it.
- What was said is kept in a **sealed transcript** on the dashboard's server (30 days, encrypted under a key in the secret store, readable
  by an owner on the Account page, never sent anywhere). The audit chain holds an HMAC of each message, never the text. Telegram's own
  copy, which a person can delete for both sides, is not the record.
- Every act, allowed or refused, is an audit entry, by you (`person:<you>:chat:telegram`), with the update number, the rule and the
  delegation used. A message from an account that is not linked is only counted.
- The bridge stops, with an alert, when Telegram answers **409** (another program reads the bot, or a webhook is set) or when the bot's
  settings are not as above, and stays stopped across a restart until an owner confirms in **Settings → Apps**. It reads updates by
  long polling, takes `message` updates only (the one kind of button a message carries opens a web page and sends nothing back), and
  ignores a message older than five minutes.

**Status:** Preview.

## 6. Owners: Production boxes and the hub

In **Settings → Apps → Telegram** an owner marks which boxes are Production (a chat shows their state and nothing else) and which box is
the hub that runs the dashboard and the bridge. Changing it needs a passkey shown a moment ago.

## 7. What is not built yet

Starting, pausing, extending, creating and resizing a box from a chat, `/run`, the chat profile that holds a chat-started session to
always-ask on the box itself, detail levels and the stronger redaction of what an agent writes back, worker boxes, and `ozbox chat lock`
and `ozbox chat unlink` on the command line. Until they are built, an act the policy would allow but that has no executor answers with a
link to the dashboard ("this version cannot do it from a chat yet"). Your links and permissions carry over when they arrive. The design
is [ADR 0050](../adr/0050-telegram-is-a-control-surface-a-closed-table-of-acts-delegated-in-advance-by-passkey-and-never-an-approver.md).

---

## Trying it on a real phone

This is what makes the Preview mark honest, and it is run by a person, with a **test bot**, not your everyday one.

1. Make a test bot with BotFather and set group joining off and privacy mode on. Do not use a bot that your team relies on.
2. On a dashboard with a sign-in, a passkey and a **public address** (Settings → Access), save the token and switch Telegram on.
3. Open the dashboard from your phone's real browser. Check that the passkey prompt works there; if it only fails inside Telegram's
   built-in browser, open the link in your browser instead (the message says so).
4. Link your account as in section 1 from the phone's own Telegram. Check that `/link` is not answered before the window is open.
5. Delegate chat on a **test box** (not Production, not the hub) and try `/new <box> say hello`. Try `/stop`, `/budget +5`, `/approve`
   and `/box destroy <box>` and check each one is refused or sent to the dashboard. Check a request the agent files shows up on the
   Approvals page and waits for your passkey.
6. Send `/lock`, check that `/new` is refused, lift the lock from the dashboard. Send `/unlink`, check the next message is not answered.
7. Open a handoff link on iOS and on Android, including from Telegram's built-in browser, and note what works.
8. Record the date, the phone, the dashboard's address kind (tunnel or domain) and what failed, and only then move this page to Works.
