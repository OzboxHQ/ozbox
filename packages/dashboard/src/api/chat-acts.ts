// Generated from crates/ozbox-core/src/chat_policy/acts.rs (TABLE). Do not edit by hand: a Rust test compares this file
// with the table and fails when they differ. Regenerate with `OZBOX_WRITE_CHAT_ACTS=1 cargo test -p ozbox-cli the_dashboards_copy_of_the_act_table`.

export type ChatTier = 'read' | 'converse' | 'power' | 'run' | 'handoff' | 'refused';
export type ChatNeeds = 'nothing' | 'converse' | 'power' | 'run';

export interface ChatActRow {
  id: string;
  command: string;
  tier: ChatTier;
  tierNumber: number;
  needs: ChatNeeds;
  safe: boolean;
  built: boolean;
  box: boolean;
  about: string;
}

export const CHAT_ACTS: readonly ChatActRow[] = [
  { id: "status", command: "/status", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "The fleet in one message, or the session this chat follows." },
  { id: "fleet", command: "/fleet", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "Every box and its state." },
  { id: "box.list", command: "/box list", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "Every box and its state." },
  { id: "tasks", command: "/tasks", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "Your sessions." },
  { id: "log", command: "/log", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "The last lines of the session this chat follows." },
  { id: "sessions", command: "/sessions [box]", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "Coding agents running in your repos." },
  { id: "help", command: "/help", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "What this chat can do for you." },
  { id: "whoami", command: "/whoami", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "Which person, role and delegations this chat is linked to." },
  { id: "usage", command: "(a command with a missing or odd argument)", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "Says how the command is written; does nothing else." },
  { id: "link", command: "/link", tier: 'read', tierNumber: 0, needs: 'nothing', safe: false, built: true, box: false, about: "Starts linking this Telegram account, only while a person has a pairing window open in the dashboard." },
  { id: "converse", command: "(plain text)", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: true, about: "The next turn of the session this chat follows, under the chat profile." },
  { id: "new", command: "/new <box> <what to do>", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: true, about: "Starts a session on a running box." },
  { id: "session.pause", command: "/pause · /session pause", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: true, about: "Pauses the session this chat follows (not a box)." },
  { id: "session.resume", command: "/resume · /session resume", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: true, about: "Continues the session this chat follows (not a box)." },
  { id: "switch", command: "/switch <session>", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: true, about: "Follows another of your sessions." },
  { id: "detach", command: "/detach", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: false, about: "Lets go of the session this chat follows." },
  { id: "attach", command: "/attach <session>", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: true, about: "Types into a terminal session that is at or below the chat profile." },
  { id: "adopt", command: "/adopt <session>", tier: 'converse', tierNumber: 1, needs: 'converse', safe: false, built: true, box: true, about: "Puts a terminal session on the board." },
  { id: "box.resume", command: "/box resume <box>", tier: 'power', tierNumber: 2, needs: 'power', safe: false, built: false, box: true, about: "Starts a box that is paused, inside the caps." },
  { id: "box.pause", command: "/box pause <box>", tier: 'power', tierNumber: 2, needs: 'power', safe: false, built: false, box: true, about: "Pauses a box, only when it is idle." },
  { id: "box.pause.when_idle", command: "/box pause <box> when-idle", tier: 'power', tierNumber: 2, needs: 'power', safe: false, built: false, box: true, about: "Pauses a box the next time it is idle, for up to two hours." },
  { id: "box.pause.cancel", command: "/box pause <box> cancel", tier: 'power', tierNumber: 2, needs: 'power', safe: false, built: false, box: true, about: "Cancels a pause that waits for the box to be idle." },
  { id: "box.extend", command: "/box extend <box> <hours>", tier: 'power', tierNumber: 2, needs: 'power', safe: false, built: false, box: true, about: "Extends the auto-pause deadline of a chat-started box, once." },
  { id: "box.create", command: "/box create <name> <size>", tier: 'power', tierNumber: 2, needs: 'power', safe: false, built: false, box: false, about: "Creates a box inside the caps (owner decision D14)." },
  { id: "box.resize", command: "/box resize <box> <size>", tier: 'power', tierNumber: 2, needs: 'power', safe: false, built: false, box: true, about: "Resizes a box inside the caps (owner decision D14)." },
  { id: "run", command: "/run <command from the catalogue>", tier: 'run', tierNumber: 3, needs: 'run', safe: false, built: false, box: true, about: "Runs one read-only inspector from the shipped catalogue. Never a free-form command." },
  { id: "box.clone", command: "/box clone", tier: 'handoff', tierNumber: 4, needs: 'nothing', safe: false, built: true, box: false, about: "Sends you to the dashboard." },
  { id: "box.snapshot", command: "/box snapshot", tier: 'handoff', tierNumber: 4, needs: 'nothing', safe: false, built: true, box: false, about: "Sends you to the dashboard." },
  { id: "box.destroy", command: "/box destroy", tier: 'handoff', tierNumber: 4, needs: 'nothing', safe: false, built: true, box: false, about: "Sends you to the dashboard." },
  { id: "lock", command: "/lock", tier: 'read', tierNumber: 0, needs: 'nothing', safe: true, built: true, box: false, about: "Refuses every act above reading from this link until a passkey in the dashboard lifts it." },
  { id: "unlink", command: "/unlink", tier: 'read', tierNumber: 0, needs: 'nothing', safe: true, built: true, box: false, about: "Cuts this link." },
  { id: "refused.approve", command: "/approve", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "Chat never approves anything; that is a passkey in the dashboard." },
  { id: "refused.deny", command: "/deny", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "Chat never denies or cancels a request." },
  { id: "refused.stop", command: "/stop", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "A run is stopped in the dashboard. (A box is paused with /box pause; there is no stop alias.)" },
  { id: "refused.budget", command: "/budget", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "A spending limit is raised in the dashboard." },
  { id: "refused.secrets", command: "/secret", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "Secrets are never read, set, imported or exported from chat." },
  { id: "refused.governance", command: "/policy · /role · /people · /settings · /allow · /tunnel", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "Policy, roles, people, links of others, delegations, caps, the network allow-list and tunnels are the dashboard's." },
  { id: "refused.outbound", command: "/send · /push · /merge", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "Outbound messages and pushes to a protected branch are never made from chat." },
  { id: "refused.not_in_table", command: "(anything else)", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "A word that is not in this table is refused." },
  { id: "refused.rejected", command: "(a malformed command)", tier: 'refused', tierNumber: 5, needs: 'nothing', safe: false, built: true, box: false, about: "A command with a typographic dash or quote, a foreign bot's name or a control character is refused, not guessed at." },
] as const;
