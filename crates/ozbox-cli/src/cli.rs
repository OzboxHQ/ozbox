//! The command-line grammar.

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use ozbox_core::{BoxName, Size};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProviderKind {
    Fake,
    Hcloud,
    Aws,
    /// A provider plugin (`plugin = "<name>"` in the config; see `ozbox plugin`).
    Plugin,
}

#[derive(Debug, Parser)]
#[command(
    name = "ozbox",
    version,
    about = "Cloud workstations for AI coding agents: create, pause, resize, snapshot, clone and destroy boxes.",
    long_about = None
)]
pub struct Cli {
    /// Where boxes run. Default: `provider` from the config file, else `fake`.
    #[arg(long, global = true, value_enum)]
    pub provider: Option<ProviderKind>,

    /// Print the plan and stop. Nothing is changed.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Do not ask for confirmation.
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Machine-readable output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Developers only: render boxes from the `module_dir` in the config although it is not this program's own copy of the
    /// box modules. Every plan says so.
    #[arg(long, global = true)]
    pub dev_modules: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum StateCommand {
    /// Show where box state is kept, and which boxes are on this computer and which are in the bucket. Read-only.
    Status,
    /// Copy boxes' state from this computer into the bucket, verify it, and keep the local copy. Plan, then apply.
    Migrate {
        /// The box to copy.
        #[arg(value_parser = parse_name, conflicts_with = "all")]
        name: Option<BoxName>,
        /// Copy every box that has state on this computer.
        #[arg(long)]
        all: bool,
        /// When every copy has checked out, set `state_backend = "s3"` in the configuration.
        #[arg(long)]
        switch: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a box.
    Create {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// XS, S, M, L, XL, XXL, GPU-S or GPU-L (see `ozbox sizes`). Default: the box defaults in the settings file.
        #[arg(long, value_parser = parse_size)]
        size: Option<Size>,
        /// Size of the persistent /work disk in GB (default: the box defaults, else 200).
        #[arg(long)]
        disk: Option<u32>,
        #[arg(long)]
        region: Option<String>,
        /// Image to boot from.
        #[arg(long)]
        image: Option<String>,
        /// A label, `key=value`. Repeatable.
        #[arg(long = "label", value_parser = parse_label)]
        labels: Vec<(String, String)>,
        /// Tools to install after the box is up: ids and `bundle:<name>`, comma separated (see `ozbox tools list`).
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Start from a saved profile (`ozbox profile list`): its tools and box defaults. Flags win over the profile.
        #[arg(long)]
        profile: Option<String>,
        /// Use an image whose signed release was built with a different first-boot configuration than this program
        /// renders. The plan prints a warning. Without this, such an image is refused.
        #[arg(long)]
        allow_first_boot_mismatch: bool,
    },
    /// List boxes.
    List,
    /// Show one box.
    Show {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Say how to connect to a box.
    Connect {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// The web IDE (default).
        #[arg(long, group = "mode")]
        web: bool,
        #[arg(long, group = "mode")]
        desktop: bool,
        #[arg(long, group = "mode")]
        shell: bool,
        /// Print the SSH config entry (`ozbox-<name>`) that reaches the box through its tunnel.
        #[arg(long, group = "mode")]
        ssh: bool,
        /// With --ssh: add the entry to ~/.ssh/ozbox/config (the main config gets one Include line, after a backup).
        #[arg(long, requires = "ssh")]
        write: bool,
        /// With --ssh: which route when a box has more than one (aws-ssm or cloudflare).
        #[arg(long, requires = "ssh")]
        route: Option<String>,
        /// With --ssh on AWS: make the box accept your dedicated key (~/.ssh/ozbox_ed25519, created if missing) for
        /// 60 seconds. Nothing is stored on the box; the saved SSH entry does this by itself at each connection.
        #[arg(long, requires = "ssh")]
        push_key: bool,
    },
    /// Rebuild a box's OpenTofu state from its cloud resources when the state is missing (AWS). Reads the cloud, imports
    /// into the state, and finishes only if the result plans as no change (or tags only). Never changes the cloud.
    Adopt {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Where each box's OpenTofu state lives: show it, or copy it from this computer into the encrypted state bucket.
    State {
        #[command(subcommand)]
        command: StateCommand,
    },
    /// Replace a box's system disk from a newer image and keep /work, then run its self-test.
    Upgrade {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// An image id, or `latest` (the default): the newest Oz image this account can see.
        #[arg(long)]
        image: Option<String>,
        /// Use an image whose release signature could not be verified. The plan prints a warning. Without this, such an
        /// image is refused.
        #[arg(long)]
        allow_unverified_image: bool,
        /// Go ahead although the box's secrets store will not survive (its key is kept in a file on the system disk with
        /// no escrow), or ozbox could not ask the box. The plan lists what must be entered again; after the upgrade the old
        /// store is set aside (never deleted), approved by this computer's pinned key, and a new one is started. Without
        /// this, such an upgrade is refused.
        #[arg(long)]
        accept_new_secrets_store: bool,
        /// Replace the box's machine from the image it already runs, so it boots with this program's first-boot
        /// configuration (/work is kept). Without this, a box on the target image is replaced only when it says its first
        /// boot differs from this program's, or has no record of it.
        #[arg(long)]
        reprovision: bool,
        /// Use an image whose signed release was built with a different first-boot configuration than this program
        /// renders. The plan prints a warning. Without this, such an image is refused.
        #[arg(long)]
        allow_first_boot_mismatch: bool,
        /// AWS: move a box whose secrets store holds nothing from a key kept in a file to the fleet's KMS key (`secrets_key_arn`
        /// and `fleet` under [aws], from `ozbox init`), so later upgrades keep the store. Refused if the store holds anything,
        /// or the box cannot be asked; the plan says so. Nothing is lost, because the store is empty.
        #[arg(long)]
        use_fleet_key: bool,
        /// (Preview) Do not stop the box unless it was fully ready: uncommitted work snapshotted without a failure, no run that
        /// could not be stopped, and the box's agent able to do both. A program that ignores the request to end and is
        /// stopped after the wait does not count against it. A box whose agent is older is refused.
        #[arg(long)]
        strict_checkpoint: bool,
        /// On a box whose agent is older than this program, use the agent's own checkpoint instead of going on without one. It
        /// writes a visible branch wip/<box>/<time> in each repository with changes, and PUSHES it if that box has a push
        /// remote. Runs are not asked to end. Not with --strict-checkpoint.
        #[arg(long, conflicts_with = "strict_checkpoint")]
        legacy_checkpoint: bool,
    },
    /// Move an AWS box's secrets store from a key kept in a file on its system disk to the fleet's KMS key, in place, so an
    /// upgrade keeps the store. Needs secrets_key_arn and fleet under [aws]. The box's role is allowed to use the key (for the
    /// box's own secrets only), the box is marked as moving (`ozbox upgrade` refuses it meanwhile), the box re-wraps its
    /// store's keys under KMS itself, and only when it says so is the label written that later upgrades read. Nothing is
    /// re-entered. Run it again if it stops; `--cancel` takes the mark and the grant back. A box whose program is older than
    /// this feature is refused before anything changes: upgrade it first.
    AdoptFleetKey {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// Take back a move that has begun and not finished: the mark and the role's grant.
        #[arg(long)]
        cancel: bool,
    },
    /// Run one allow-listed action as root on a box: reown, reinstall-ozboxd, restart-services, collect-logs, enable-linger,
    /// ensure-supervisor, configure-box-secrets, recover-secrets or host-guard. There is no shell: the box user has no sudo, and
    /// this is the only root path, recorded on the box. recover-secrets is approved by the key this computer pinned when it
    /// made the box.
    Admin {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// The action and its arguments, after `--`, for example: ozbox admin dev -- reown --from-uid 1000
        #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
        action: Vec<String>,
    },
    /// Declare which secrets a box keeps of its own (Staging keys for its role, in Parameter Store or OpenBao): shows what
    /// will change, then writes the box's instance tags and has the box read them. The read permission itself comes from the
    /// box's module variables (box_secrets_backend, box_secrets_prefix, box_role), which stay the source of truth.
    BoxSecrets {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// aws-ssm or openbao.
        #[arg(long)]
        backend: Option<String>,
        /// The path prefix, like /ozbox/dev. The box reads <prefix>/<role> and below.
        #[arg(long)]
        path: Option<String>,
        /// The box's role, like main or worker.
        #[arg(long)]
        role: Option<String>,
        /// Remove the declaration: the box keeps no secrets of its own.
        #[arg(long, conflicts_with_all = ["backend", "path", "role"])]
        remove: bool,
        /// Hetzner (no instance tags): the OpenBao address, https://host or https://host:port. Not a secret; the token is
        /// placed separately with `ozbox admin <box> -- place-bao-token`.
        #[arg(long)]
        vault_addr: Option<String>,
        /// Hetzner: the OpenBao KV mount (default secret).
        #[arg(long)]
        mount: Option<String>,
        /// Hetzner: a fresh approval code, for a box whose dashboard has a second factor (from the dashboard, or
        /// `ozbox secrets approve --scope box-secrets --project declaration`).
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
    },
    /// The box-wide egress list: the places the whole machine may reach. Off by default. With no `--mode`, shows what the
    /// list has seen (what the box reached that was not on it). `--mode log` first, then `--mode enforce`.
    BoxEgress {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// off, log (nothing blocked; what is not listed is noted) or enforce (what is not listed is dropped).
        #[arg(long)]
        mode: Option<String>,
        /// A named set of destinations (see --list-presets). Repeat for several.
        #[arg(long = "preset")]
        presets: Vec<String>,
        /// An extra host name, reached on port 443. Repeat for several.
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// Print the presets and what each is for, then stop.
        #[arg(long)]
        list_presets: bool,
        /// Enforce without the box having run in log mode first.
        #[arg(long)]
        skip_log_first: bool,
        /// A fresh approval code, needed to turn the list off or widen it (from the dashboard, or `ozbox secrets approve
        /// --scope host-guard --project egress --env DIGEST`; the plan shows the digest). Asking for less needs none.
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
    },
    /// When a box may restart itself after patches (it never does by default). With no `--rule`, shows the rule and whether
    /// the box is in use.
    BoxPatch {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// never, or when-idle (inside a window of the day, once nothing has used the box for a while).
        #[arg(long)]
        rule: Option<String>,
        /// With when-idle: the window starts at this hour (UTC, 0 to 23).
        #[arg(long)]
        from: Option<u32>,
        /// With when-idle: the window ends at this hour (UTC).
        #[arg(long)]
        to: Option<u32>,
        /// With when-idle: minutes nothing must have used the box (default 30).
        #[arg(long)]
        idle: Option<u32>,
        /// A fresh approval code, needed for any when-idle rule (from the dashboard, or `ozbox secrets approve --scope
        /// host-guard --project patch --env DIGEST`; the plan shows the digest). `never` needs none.
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
    },
    /// The box end of a browsing session: reads its settings, then one request per line. Not for typing by hand.
    #[command(hide = true)]
    BrowserWorker,
    /// Coding agents on a box (Claude Code, Codex, Gemini CLI, OpenCode) using the Oz Box tools, browser included.
    AgentMcp {
        #[command(subcommand)]
        command: AgentMcpCommand,
    },
    /// Run on a box by its socket: start a browsing session's worker as the browser's own user. Not for typing by hand.
    #[command(hide = true)]
    BrowserLaunch,
    /// Run on a box as root, by first-boot configuration: make the browser's own user, its folders and its launcher. Not for
    /// typing by hand.
    #[command(hide = true)]
    BrowserSetup {
        #[arg(num_args = 0.., allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// On a box: run a command inside a memory cap (a production build, a test browser), so it can slow or end itself but never
    /// stall the box or kill your terminal. `ozbox capped [--max-gib N] [--soft] -- npm run build`. Never runs it uncapped.
    Capped {
        #[arg(num_args = 1.., allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Run on a box by its root helper: the box's own guards. Not for typing by hand.
    #[command(hide = true)]
    HostGuard {
        #[arg(num_args = 1.., allow_hyphen_values = true)]
        words: Vec<String>,
    },
    /// The box's web IDE (VS Code in the browser) on http://localhost, or on your own address behind your Oz Box sign-in.
    Ide {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        #[command(flatten)]
        code: CodeFlags,
    },
    /// The box's desktop with Firefox (KasmVNC) on http://localhost, or on your own address behind your Oz Box sign-in.
    Desktop {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        #[command(flatten)]
        code: CodeFlags,
    },
    /// What is running on a box that you started: tmux sessions, coding agents and listening servers. Stopping one is a
    /// change, shown first and confirmed.
    Ps {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// Stop this tmux session.
        #[arg(long, conflicts_with = "stop_pid")]
        stop_session: Option<String>,
        /// Stop this coding agent or server (a process number `ps` showed).
        #[arg(long)]
        stop_pid: Option<u32>,
    },
    /// Open a box's /work/repos in a desktop editor over SSH: vscode, cursor, antigravity, windsurf, zed or jetbrains.
    Open {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// The editor.
        #[arg(long = "in", value_parser = ["vscode", "cursor", "antigravity", "windsurf", "zed", "jetbrains"])]
        editor: String,
        /// Print the link and do not open it.
        #[arg(long)]
        print: bool,
        /// The folder on the box to open.
        #[arg(long, default_value = "/work/repos")]
        folder: String,
    },
    /// Stop a box; /work stays on its disk and you pay only for storage.
    Pause {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Start a paused box.
    Resume {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Change a box's size, grow its /work disk, or both.
    #[command(group(ArgGroup::new("what").required(true).multiple(true).args(["size", "disk"])))]
    Resize {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        #[arg(long, value_parser = parse_size)]
        size: Option<Size>,
        /// New /work disk size in GB. Disks can grow, never shrink.
        #[arg(long)]
        disk: Option<u32>,
        /// (Preview) Do not stop the box unless it was fully ready: uncommitted work snapshotted without a failure, no run that
        /// could not be stopped, and the box's agent able to do both. A program that ignores the request to end and is
        /// stopped after the wait does not count against it. A box whose agent is older is refused. Without this, a box that
        /// was not fully ready is reported and you are asked again (/work is kept either way).
        #[arg(long)]
        strict_checkpoint: bool,
        /// On a box whose agent is older than this program, use the agent's own checkpoint instead of going on without one. It
        /// writes a visible branch wip/<box>/<time> in each repository with changes, and PUSHES it if that box has a push
        /// remote. Runs are not asked to end. Not with --strict-checkpoint.
        #[arg(long, conflicts_with = "strict_checkpoint")]
        legacy_checkpoint: bool,
    },
    /// Snapshot a box's /work disk.
    Snapshot {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Create a new box from another box's latest snapshot.
    Clone {
        #[arg(value_parser = parse_name)]
        from: BoxName,
        #[arg(value_parser = parse_name)]
        to: BoxName,
    },
    /// Delete a box and its /work disk.
    Destroy {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// Do not keep a final snapshot of /work.
        #[arg(long)]
        no_final_snapshot: bool,
    },
    /// The box modules and first-boot configuration this program renders: its version, their hashes, and the folder in use.
    Infra,
    /// The size catalogue and the machine type each provider maps it to.
    Sizes,
    /// The providers and what each can do.
    Providers,
    /// Back up a box's /work: list, back up now, restore, delete, and the schedule.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Model providers (your own keys or cloud account), which model each engine uses, and what they cost.
    Models {
        #[command(subcommand)]
        command: ModelsCommand,
    },
    /// What the provider really billed, how that compares with the estimate, and what in the account nothing uses.
    Cost {
        #[command(subcommand)]
        command: CostCommand,
    },
    /// Add and remove tools on a box: editors, AI agents, languages, cloud CLIs. Plan first, then apply.
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
    /// Save a box's tools and settings as a named profile, and use it to create boxes.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Guided first-run setup: provider, sign-in check, region, state bucket, network, budget, alerts, security.
    Init {
        /// The sign-in profile of your cloud CLI (AWS: a named profile).
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        region: Option<String>,
        /// Monthly budget in US dollars (required before a box can be created on a real cloud).
        #[arg(long)]
        budget: Option<f64>,
        /// Send alerts to this address (needs --alert-from; the sending key is read from OZBOX_ALERT_EMAIL_API_KEY).
        #[arg(long, requires = "alert_from")]
        alert_email: Option<String>,
        #[arg(long, requires = "alert_email")]
        alert_from: Option<String>,
        /// Confirm that two-factor sign-in is required for the cloud account.
        #[arg(long)]
        two_factor: bool,
        /// How you will reach your boxes: session (the provider's session service, the default), headscale, tailscale or
        /// cloudflare. Asked, with each way explained, when left out on a terminal. Changeable later.
        #[arg(long)]
        access: Option<String>,
        /// A zip with the built `ozbox-issuer` program (`bootstrap` inside): setup also plans the off-box issuer for
        /// Production secrets in your account. Shown and approved like every other step; nothing is downloaded.
        #[arg(long, value_name = "ZIP", requires = "issuer_package_sha256")]
        issuer_package: Option<String>,
        /// The package's SHA-256 (64 hex characters) from the signed release's manifest or a reproducible build. Required with
        /// --issuer-package: a hash made from the file itself would prove nothing about it.
        #[arg(long, value_name = "HEX", requires = "issuer_package")]
        issuer_package_sha256: Option<String>,
    },
    /// Turn on the opt-in AWS security services: GuardDuty Runtime Monitoring, a locked bucket for Session Manager logs, and
    /// Patch Manager. What you name is the whole set: leaving one out turns it off. Plan, then apply; costs are stated.
    Harden {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        region: Option<String>,
        /// GuardDuty Runtime Monitoring (bills per vCPU of monitored machines).
        #[arg(long)]
        guardduty_runtime: bool,
        /// A bucket locked against change for --retention-days, and Session Manager logging to it.
        #[arg(long)]
        session_logs: bool,
        /// Weekly patching that installs updates and never restarts a box.
        #[arg(long)]
        patching: bool,
        /// How long a session log is locked (1 to 3650).
        #[arg(long, default_value_t = 365)]
        retention_days: u32,
        /// governance (default) or compliance. Compliance cannot be undone by anyone until the retention ends.
        #[arg(long, default_value = "governance")]
        lock_mode: String,
    },
    /// Serve the web dashboard on this computer (loopback only, behind a random access token).
    Serve {
        /// A loopback address: 127.0.0.1 (default), ::1 or localhost. Anything else is refused.
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// TCP port; 0 picks a free one.
        #[arg(long, default_value_t = 7878)]
        port: u16,
        /// For a shared machine behind a tunnel: still loopback only, but people sign in (passkey, or GitHub or
        /// Google then a second factor) instead of using the local token. Needs the settings `ozbox auth init` writes.
        #[arg(long)]
        public_behind_tunnel: bool,
        /// The sign-in settings file (default: auth.toml beside the main configuration).
        #[arg(long)]
        auth_config: Option<std::path::PathBuf>,
        /// The address people open, like https://ozbox.example.com. Turns on sign-in (the same mode as
        /// --public-behind-tunnel) and replaces the address in the sign-in settings file. Still loopback only.
        #[arg(long)]
        public_url: Option<String>,
        /// Start and keep up an outbound tunnel to --public-url, with your own account: cloudflare,
        /// tailscale-funnel, tailscale-serve, caddy or ngrok. Settings come from `ozbox tunnel setup`.
        #[arg(long)]
        tunnel: Option<String>,
        /// In sign-in mode: the loopback port that serves the web IDE and desktop on your own addresses
        /// (`ozbox ide <box> --public-url ...`). Point your tunnel's extra host names at it.
        #[arg(long, default_value_t = 7879)]
        code_port: u16,
    },
    /// Run a command with a project's workload secrets (the `.env` keys it needs) filled in, and print only what the command
    /// printed with every known secret value removed.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// The commit barrier: git hooks that stop a commit or a push that contains a key.
    Guard {
        #[command(subcommand)]
        command: GuardCommand,
    },
    /// The encrypted secret store of this machine: report on it, rotate its keys, run a program with a secret.
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },
    /// Optional, anonymous usage counts. Off until you turn it on, and sent only to an address you choose.
    Telemetry {
        #[command(subcommand)]
        command: TelemetryCommand,
    },
    /// Provider and tunnel plugins: programs that speak a small protocol, run only after you approve their exact hash.
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// A tailnet you run yourself (Headscale): reach your boxes over it instead of Session Manager or a Cloudflare tunnel.
    Mesh {
        #[command(subcommand)]
        command: MeshCommand,
    },
    /// The outbound tunnel that reaches the dashboard from outside (your own account, token and domain).
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommand,
    },
    /// Run the dashboard as a service on one of your boxes.
    Dashboard {
        #[command(subcommand)]
        command: DashboardCommand,
    },
    /// Supervised agent runs: start, list, show, logs, cancel, retry, resume.
    Run {
        #[command(subcommand)]
        command: RunCommand,
    },
    /// Tasks between two endpoints (a laptop and a box, or two boxes): typed, signed, ordered, with a state and an audit record.
    Tasks {
        #[command(subcommand)]
        command: TasksCommand,
    },
    /// Orchestrations: one agent hands features to worker boxes. Start, follow, answer, merge.
    Orch {
        #[command(subcommand)]
        command: OrchCommand,
    },
    /// Agent memory: notes in git that agents can read once you approve them.
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    /// Reviewed skills: install per fleet, box or project; usable only after you approve the exact files.
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    /// What agents ask to do, and your answer: list, approve, deny.
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// Modes, rules and time-boxed Production grants for what agents and people may do.
    Permissions {
        #[command(subcommand)]
        command: PermissionsCommand,
    },
    /// The tamper-evident audit log: list it and check that nothing was changed.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Sign-in settings for a dashboard on a shared machine.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Scheduled agent runs, in your own time zone.
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    /// Signed inbound webhooks that start agent runs.
    Trigger {
        #[command(subcommand)]
        command: TriggerCommand,
    },
}

/// What the schedule and trigger commands take from the global flags.
#[derive(Debug, Clone, Copy)]
pub struct ScheduleFlags {
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

pub type TriggerFlags = ScheduleFlags;

#[derive(Debug, clap::Args)]
pub struct ScheduleAdd {
    /// A name for the schedule.
    #[arg(long)]
    pub name: String,
    /// When, in words: "every weekday at 9am Lagos time". The cron it means and the next 5 runs are shown first.
    #[arg(long, conflicts_with_all = ["cron", "every_minutes"])]
    pub when: Option<String>,
    /// When, as five-field cron (minute hour day-of-month month day-of-week).
    #[arg(long, conflicts_with = "every_minutes")]
    pub cron: Option<String>,
    /// Every N minutes from now (a heartbeat).
    #[arg(long)]
    pub every_minutes: Option<u32>,
    /// The time zone the times are read in (default: yours from Settings).
    #[arg(long)]
    pub time_zone: Option<String>,
    #[arg(long)]
    pub owner: Option<String>,
    /// The agent or engine, like claude-code.
    #[arg(long, default_value = "claude-code")]
    pub engine: String,
    #[arg(long)]
    pub prompt: Option<String>,
    #[arg(long)]
    pub skill: Option<String>,
    /// The box to run on.
    #[arg(long = "box", conflicts_with = "profile")]
    pub box_name: Option<String>,
    /// Or: any box with this profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// The most one run may spend, in US cents.
    #[arg(long)]
    pub max_spend_cents: Option<u64>,
    /// The longest one run may take.
    #[arg(long)]
    pub max_minutes: Option<u32>,
    /// Where results go besides the history: alert, pull_request.
    #[arg(long = "results-to")]
    pub results_to: Vec<String>,
    /// How late a missed run may still be made up (default 120).
    #[arg(long)]
    pub catch_up_minutes: Option<u32>,
    /// A check-in rather than a task: off until you turn it on.
    #[arg(long)]
    pub heartbeat: bool,
    /// Create it switched off.
    #[arg(long)]
    pub disabled: bool,
}

#[derive(Debug, Subcommand)]
pub enum ScheduleCommand {
    /// Make a schedule. Prints the cron and the next 5 runs; --dry-run stops there.
    Add(Box<ScheduleAdd>),
    List,
    Show {
        id: String,
    },
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
    /// Ask the dashboard server to run it now.
    RunNow {
        id: String,
    },
    Remove {
        id: String,
    },
    /// Two computers, one set of schedules: keep them in a shared S3 object so exactly one fires and the other takes over.
    Failover {
        #[command(subcommand)]
        command: FailoverCommand,
    },
    /// Show what a sentence or cron means, with the next runs, without saving anything.
    Preview {
        /// "every weekday at 9am Lagos time"
        text: Option<String>,
        #[arg(long)]
        cron: Option<String>,
        #[arg(long)]
        time_zone: Option<String>,
        #[arg(long, default_value_t = 5)]
        count: usize,
    },
}

#[derive(Debug, clap::Args)]
pub struct TriggerAdd {
    #[arg(long)]
    pub name: String,
    /// github, generic or stripe: how the sender signs its requests.
    #[arg(long, default_value = "github")]
    pub scheme: String,
    /// What the agent should do. Write {{field.name}} to refer to a field of the event.
    #[arg(long)]
    pub template: String,
    /// The agent or engine, like claude-code.
    #[arg(long, default_value = "claude-code")]
    pub engine: String,
    #[arg(long)]
    pub skill: Option<String>,
    #[arg(long = "box", conflicts_with = "profile")]
    pub box_name: Option<String>,
    #[arg(long)]
    pub profile: Option<String>,
    #[arg(long)]
    pub max_spend_cents: Option<u64>,
    #[arg(long)]
    pub max_minutes: Option<u32>,
    #[arg(long = "results-to")]
    pub results_to: Vec<String>,
    /// GitHub only: the events to act on (push, pull_request, ...). Default: all but ping.
    #[arg(long = "event")]
    pub events: Vec<String>,
    #[arg(long)]
    pub owner: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum TriggerCommand {
    /// Make a trigger. Its secret is shown once.
    Add(Box<TriggerAdd>),
    List,
    Remove {
        id: String,
    },
    /// Recent requests and why each was accepted or refused.
    Deliveries {
        id: String,
    },
    /// Make a new secret for a trigger, shown once. The old secret keeps working for 24 hours so the sender can be
    /// updated without a gap.
    RotateSecret {
        id: String,
    },
}

/// What `ozbox ide` and `ozbox desktop` share.
#[derive(Debug, clap::Args)]
pub struct CodeFlags {
    /// Do not open the browser; print the address.
    #[arg(long)]
    pub no_open: bool,
    /// The local port (default: a free one).
    #[arg(long)]
    pub port: Option<u16>,
    /// Serve it on your own address instead of localhost, like https://ide.example.com, behind your Oz Box sign-in.
    /// Needs the dashboard in sign-in mode (`ozbox serve --public-url`) and --tunnel.
    #[arg(long)]
    pub public_url: Option<String>,
    /// The tunnel that carries that address: cloudflare or caddy (the ones that can serve more than one host name).
    #[arg(long)]
    pub tunnel: Option<String>,
    /// Stop it and remove it from the box (its password and its own address too).
    #[arg(long, conflicts_with_all = ["public_url", "tunnel"])]
    pub off: bool,
    /// Make a new password for it.
    #[arg(long)]
    pub new_password: bool,
    /// Stop serving it on its own address, keep it on the box.
    #[arg(long, conflicts_with_all = ["public_url", "tunnel", "off"])]
    pub remove_public: bool,
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Names and ages of the stored secrets. Never a value.
    Status,
    /// Move the store to a new key-encryption key: kms, tpm2 or keychain.
    RotateKek {
        #[arg(long, value_name = "KIND")]
        to: String,
    },
    /// Give every secret a new data key (the values do not change).
    RotateDataKeys,
    /// Make a new key for internal tokens; the previous one keeps working for the overlap.
    RotateHmac {
        /// How long, in hours, sessions made before keep working.
        #[arg(long, default_value_t = 24)]
        overlap_hours: u64,
    },
    /// Run the box's secrets service (as the secrets user): the box socket, and optionally the runner and admin sockets.
    Serve {
        #[arg(long)]
        box_socket: std::path::PathBuf,
        #[arg(long)]
        runner_socket: Option<std::path::PathBuf>,
        #[arg(long)]
        admin_socket: Option<std::path::PathBuf>,
        /// Where the box user (and a laptop's `ozbox secrets import --box`) hands in a project's keys and declaration.
        #[arg(long)]
        import_socket: Option<std::path::PathBuf>,
        /// The socket the `ozbox-ingress` account reaches: this service's public key and sealed requests from the owner's
        /// computer (a folder only the secrets user and that account may enter).
        #[arg(long)]
        ingress_socket: Option<std::path::PathBuf>,
        /// Run the credential broker inside this service and listen for the run side on this socket. The pins that say
        /// where each key may be sent are kept beside the store.
        #[arg(long)]
        broker_socket: Option<std::path::PathBuf>,
        /// The supervisor's own socket (a directory only its user may enter). With it, the box socket and the broker socket
        /// shrink to what the box user needs, and the supervisor alone can issue run tokens and ask for an approval.
        #[arg(long)]
        supervisor_socket: Option<std::path::PathBuf>,
        /// Where the box's own secrets are kept while the box is up: a file on tmpfs, sealed under the same key. Without
        /// it the service holds none.
        #[arg(long)]
        memory_store: Option<std::path::PathBuf>,
        /// Keep the box's audit chain here (ADR 0028): this service alone writes it, the box user can only read it. The
        /// seal key is a secret in the store, never a file.
        #[arg(long)]
        audit_dir: Option<std::path::PathBuf>,
        /// Where the second copy of every checkpoint goes (a folder only this user can open). Default: beside the store.
        #[arg(long)]
        audit_anchor_dir: Option<std::path::PathBuf>,
        /// Keep a copy of the store (and the key file, where the key is a file) here, on the persistent disk, so a system-disk
        /// replacement (`ozbox upgrade`) does not lose the box's secrets. Only the secrets user can open it.
        #[arg(long)]
        persist_dir: Option<std::path::PathBuf>,
        /// The key comes from a passphrase read from standard input (one line), never stored.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Import the keys of a `.env` file for one project and environment. Shows names and fingerprints, never values;
    /// nothing is stored without --yes. A key that looks like production is held back unless named in --allow-live.
    Import {
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        #[arg(long)]
        project: String,
        #[arg(long = "env")]
        env: String,
        /// A production-looking key to store anyway (it stays flagged, and no agent's command receives it). Repeatable.
        #[arg(long = "allow-live", value_name = "NAME")]
        allow_live: Vec<String>,
        /// Mark a value PUBLIC: a public URL or an anonymous key that a declared command may be given as plain environment
        /// (`"public": ["NAME"]` in its declaration). Your explicit word, never guessed from a value. Refused for a name that
        /// says it is secret, a production-looking value, a kind of key that is only ever secret, and a service-role key.
        /// Repeatable.
        #[arg(long = "public", value_name = "NAME")]
        public: Vec<String>,
        /// Send the keys to this box's secrets service over its SSH route instead of storing them here. The file is read on
        /// this computer; the values travel on the SSH connection only, never in a file on the box or an argument.
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: Option<BoxName>,
        /// The approval code the dashboard gave you after your passkey or authenticator code (Settings, Secrets). A box
        /// whose dashboard has a second factor refuses the keys without one.
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
    },
    /// The box end of `ozbox secrets import --box` and `ozbox env policy set --box`: reads one request line on standard
    /// input and hands it to the import socket. A person never runs it.
    #[command(hide = true)]
    Receive {
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
    /// The box's command launcher (root, started per request by its socket unit): reads one request line on standard
    /// input, starts the command as the project's runner user, answers on standard output.
    #[command(hide = true)]
    RunAs,
    /// Inside a command's sandbox unit: reads the environment as one JSON line on standard input, sets each variable
    /// directly, and starts the command after `--`. Started by the launcher through `systemd-run`; a person never runs it.
    #[command(hide = true)]
    ExecEnv {
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Inside a service's sandbox unit that receives secrets: reads each file of `$CREDENTIALS_DIRECTORY`, sets it as a variable of
    /// the same name, and starts the program after `--`. Started by the launcher through `systemd-run`; a person never runs it.
    #[command(hide = true)]
    ExecCred {
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// The program of a service's egress proxy unit: listens on a loopback port for the declared hosts and raw destinations, tells
    /// systemd it is ready, and serves until the unit is stopped. Started by the launcher through `systemd-run`; a person never
    /// runs it.
    #[command(hide = true)]
    EgressServe {
        #[arg(long)]
        port: u16,
        /// The numeric uid of the one user whose connections the proxy serves (the service's own).
        #[arg(long)]
        uid: u32,
        /// A declared host (`api.example.com`, `*.example.com`, optionally `:port`).
        #[arg(long = "rule")]
        rules: Vec<String>,
        /// A declared raw destination, `host:port:ENV:localport`.
        #[arg(long = "tcp")]
        tcp: Vec<String>,
    },
    /// Enrol, list or revoke a signing key kept on this computer, which can approve changes to a box's secrets without the
    /// dashboard (the key's private half stays in the keychain).
    ApprovalKey {
        #[command(subcommand)]
        command: ApprovalKeyCommand,
    },
    /// The sealed route to a box's secrets service: pin its key, keep a copy of its store key in this computer's keychain, or
    /// read the dashboard's first-time code. Everything a computer sends to a box's secrets service goes this way.
    Ingress {
        #[command(subcommand)]
        command: IngressCommand,
    },
    /// Ask a box for an approval code signed by this computer's key (single-use, for one scope, expires in minutes).
    Approve {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
        /// import, policy, tunnel-token, guard-override, signer-enroll, box-secrets or host-guard.
        #[arg(long)]
        scope: String,
        #[arg(long, default_value = "")]
        project: String,
        #[arg(long = "env", default_value = "")]
        env: String,
        /// Which of this computer's keys signs (default: laptop).
        #[arg(long, default_value = "laptop")]
        key: String,
        /// tunnel-token only: read the new token from standard input (one line) and bind the code to it, so it approves
        /// storing that token and no other. A box whose root helper predates this takes only a code made without it.
        #[arg(long)]
        token_stdin: bool,
    },
    /// Put one secret into the box's secrets service as root (the admin socket), reading the value from standard input.
    /// Used by the box's root helper; a person never needs it.
    Put {
        #[arg(long)]
        name: String,
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
        /// The line on standard input is the value in base64, for a value with spaces, quotes or line breaks. It is stored
        /// exactly (a tunnel token and the box's other fixed names keep the plain rule).
        #[arg(long)]
        base64: bool,
    },
    /// Ask the admin socket whether a gated change is allowed (the root helper calls this before it stores a tunnel
    /// token). The approval code is read from standard input, one line (it may be empty). Prints how it was allowed.
    #[command(hide = true)]
    Gate {
        #[arg(long)]
        scope: String,
        #[arg(long, default_value = "")]
        project: String,
        #[arg(long, default_value = "")]
        env: String,
        /// Read the approval code on the first line of standard input and the token being stored on the second, and bind
        /// the approval to that token (instead of --env): the root helper's check for a tunnel-token change.
        #[arg(long)]
        bind_token_stdin: bool,
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
    /// Give the dashboard a user of its own (ADR 0023): the box's root-owned program carries the setup script and runs it, so
    /// the first-boot configuration stays small. Run by first boot and by the root helper; `--finish` destroys the old
    /// copies after the new dashboard has been seen working, `--rollback` puts the old dashboard back.
    #[command(hide = true)]
    SupervisorSetup {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Make the ingress account (the one way this computer's `ozbox secrets ... --box` reaches the box's secrets service):
    /// as root, at first boot and when the image is built. Takes no word from the box user.
    #[command(hide = true)]
    IngressSetup {
        /// The person's SSH public key, lowercase base32 (the `ozbox-ingress` label); empty for none.
        #[arg(default_value = "")]
        key: String,
    },
    /// The box's secrets declaration and vault token where the provider has no instance tags (the root helper runs it as
    /// root: write-box-secrets, clear-box-secrets, place-bao-token).
    #[command(hide = true)]
    BoxSecretsAdmin {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Start a new, empty store on a box whose store can no longer be opened (its key file was on a system disk that was
    /// replaced, and nothing escrowed it). The old store and its copy on /work are kept aside, renamed, never opened. Run as
    /// root by the root helper (`recover-secrets`). Refused unless the secrets service itself stopped because the key is lost
    /// with no escrow, and unless the key pinned when the box was made signed a fresh challenge (`--challenge` issues one;
    /// `ozbox admin <box> -- recover-secrets` on your computer does both steps). `--console` is for root at the machine's own
    /// console, with no pinned key.
    #[command(hide = true)]
    RecoverStore {
        /// Issue a one-time challenge for the pinned key to sign.
        #[arg(long, conflicts_with_all = ["nonce", "console"])]
        challenge: bool,
        #[arg(long, requires_all = ["expires", "signature"])]
        nonce: Option<String>,
        #[arg(long)]
        expires: Option<u64>,
        #[arg(long)]
        signature: Option<String>,
        /// Root at the machine's own console (a terminal): no signature, the same state checks.
        #[arg(long, conflicts_with = "nonce")]
        console: bool,
    },
    /// Set the machine up for a project's STORED declaration, or take it back when there is none: the runner's access to the
    /// project folder (an ACL for that one user), a root-owned read-only copy of the tools and browsers it names. Run as root by
    /// the root helper (`ensure-runner`). It reads the declaration from the secrets service; nothing in a request chooses a path.
    #[command(hide = true)]
    RunnerSetup {
        project: String,
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
    /// Read this box's secrets declaration (its instance tags: backend, path, role) from the metadata service and write the
    /// loader's settings file. Run as root before the loader, and by the root helper. Reads and writes no secret.
    #[command(hide = true)]
    ConfigureBox {
        #[arg(long, default_value = "/etc/ozbox/box-secrets.env")]
        env_file: std::path::PathBuf,
    },
    /// Check that the KMS key named by OZBOX_KMS_KEY_ID can wrap and unwrap a throwaway key under this box's encryption
    /// context. Reads and writes no secret. Run as the secrets user by the move to the fleet's KMS key, before it stops anything.
    #[command(hide = true)]
    ProbeKms,
    /// Move the store from a key kept in a file to the fleet's KMS key named by this box's instance tag `ozbox-secrets-adopt`
    /// (`ozbox adopt-fleet-key` on your computer sets it). Run as root, as a unit of its own, by `configure-box`.
    #[command(hide = true)]
    AdoptKms,
    /// Print, as root, what this box's secrets store looks like (the move to the fleet's KMS key): the same lines every time, in
    /// a fixed shape. `ozbox adopt-fleet-key` reads them through the cloud's own root channel, never over the box user's SSH.
    #[command(hide = true)]
    AdoptStatus,
    /// Record, as root and under the move's lock, that the move to the fleet's KMS key is cancelled, and take a store that
    /// already moved back under its file key. The laptop takes the grant away only after this says it is done.
    #[command(hide = true)]
    AdoptCancel {
        /// Put the copy of the store made before the move back, for a store whose KMS no longer answers. Loses the secrets
        /// saved since the move. Refused while KMS still answers (the plain cancel loses nothing).
        #[arg(long)]
        from_copy: bool,
    },
    /// Take a recorded cancel away, so a move can start again (run as root before `ozbox adopt-fleet-key` sets the tag).
    #[command(hide = true)]
    AdoptArm,
    /// Pull this box's own secrets from the provider's secret store (AWS Parameter Store, or OpenBao) and hand them to the
    /// secrets service, which keeps them in memory only. Run at boot and on a timer, as the secrets user. Reads
    /// OZBOX_BOX_SECRETS_BACKEND (aws-ssm | openbao), OZBOX_BOX_SECRETS_PATH, OZBOX_BOX_ROLE and OZBOX_BOX_SECRETS_REGION.
    #[command(hide = true)]
    LoadBox {
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
    /// Remove one secret through the admin socket (the root helper's other half).
    Remove {
        #[arg(long)]
        name: String,
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
    /// Run a program with secrets in its environment, as the user that runs this command. The value goes to that
    /// program's environment only; it is not printed and not put in any argument.
    Exec {
        /// ENVNAME=secret-name, repeated.
        #[arg(long = "env", value_name = "ENVNAME=SECRET")]
        env: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// The plugins you have added, and whether each is approved.
    List,
    /// Copy a plugin folder (plugin.toml and its program) in. It is not run, and not approved.
    Add { path: std::path::PathBuf },
    /// Approve a plugin's program as it is now (shows its SHA-256 first). A changed program needs approving again.
    Approve { name: String },
    /// Take back an approval. The plugin stays added but is no longer run.
    Revoke { name: String },
    /// Delete an added plugin and its approval.
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
pub enum TelemetryCommand {
    /// Whether it is on, and where it would send.
    Status,
    /// Print the exact event that would be sent now. Sends nothing.
    Preview,
    /// Turn it on, sending to an https address you run or trust.
    On {
        #[arg(long)]
        endpoint: String,
    },
    /// Turn it off and forget what it kept.
    Off,
    /// Send today's event now (it must be on).
    Send,
}

#[derive(Debug, Subcommand)]
pub enum MeshCommand {
    /// Save where your Headscale server is and which Headscale user owns your computers and boxes.
    Setup {
        /// Your Headscale server, like https://headscale.example.com.
        #[arg(long)]
        control_url: String,
        /// The Headscale user.
        #[arg(long)]
        user: String,
        /// The SSH name of the machine that runs Headscale, when it is not this computer.
        #[arg(long)]
        admin_host: Option<String>,
        /// The account on a box you sign in as (default ozbox).
        #[arg(long)]
        ssh_user: Option<String>,
        /// Your tailnet's base domain, like tail.example.com, for names like <box>.tail.example.com.
        #[arg(long)]
        base_domain: Option<String>,
    },
    /// Let one box open connections to another on the given ports. Boxes cannot reach each other until you say so.
    Allow {
        #[arg(value_parser = parse_name)]
        from: BoxName,
        #[arg(value_parser = parse_name)]
        to: BoxName,
        #[arg(long, required = true)]
        port: Vec<u16>,
    },
    /// Remove a box-to-box rule.
    Deny {
        #[arg(value_parser = parse_name)]
        from: BoxName,
        #[arg(value_parser = parse_name)]
        to: BoxName,
    },
    /// Generate the access rules from your boxes: print them, write them to a file, or --apply them to Headscale.
    Policy {
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Send them to Headscale (needs its policy mode set to database).
        #[arg(long)]
        apply: bool,
    },
    /// Join a box to your tailnet with a one-use key made for it.
    Join {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// A public key file to add to the box user's authorized keys (usually ~/.ssh/ozbox_ed25519.pub).
        #[arg(long)]
        ssh_key: Option<std::path::PathBuf>,
        /// Join although the server's loaded policy cannot be confirmed to be the one `ozbox mesh policy` generates (a
        /// file-mode server, or rules you keep yourself). Without the deny-by-default rules, Headscale lets every node reach
        /// every other.
        #[arg(long)]
        policy_managed_elsewhere: bool,
    },
    /// Keep a one-use key you made yourself for a box in the secret store (read from standard input), or remove it.
    Key {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        #[arg(long)]
        clear: bool,
    },
    /// Which of your boxes have joined, and which are online.
    Status,
    /// Print the command that forwards a box's dashboard or IDE port to this computer over the tailnet.
    Forward {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        #[arg(long, default_value_t = 7878)]
        port: u16,
    },
    /// What to run on this computer to join your tailnet.
    Client,
    /// Forget the saved settings. Nothing changes on Headscale or on any box.
    Remove,
}

#[derive(Debug, Subcommand)]
pub enum IngressCommand {
    /// Pin (or check) the key a box's secrets service seals requests to. The first request to a box pins it by itself; use
    /// this to look at the fingerprint, or to accept a new key on purpose (--replace) after a box's store was made again.
    Pin {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
        /// Replace a different pinned key. Shows both fingerprints and asks you to type the box's name.
        #[arg(long)]
        replace: bool,
    },
    /// Keep a copy of a box's file-kept store key in this computer's keychain, so `ozbox upgrade` can put it back through
    /// the ingress route when the system disk is replaced. The key is never printed. WARNING: that copy opens every value on the
    /// box (every project key, the box's own tokens and credentials), and any program running as you on this computer can read
    /// your keychain. Once the box has a second factor the copy needs an approval from your approval key; the box records it.
    Escrow {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
    },
    /// The dashboard's first-time setup code, delivered here and never to a log the box user can read.
    SetupCode {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
    },
    /// The approval requests of a box (ADR 0041): read them and decide them from this computer, over the sealed route. This
    /// computer's key is a software key: it decides what a member may decide, never an owner-only change and never
    /// Production. Use the dashboard (your passkey) for those.
    Requests {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
        #[command(subcommand)]
        action: RequestsAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum RequestsAction {
    /// The requests waiting, and the ones decided in the last day.
    List,
    /// One request: who asked, the change in full (each field with where its words came from) and its whole digest.
    Show { id: String },
    /// Approve a request. Needs the whole digest, as `show` prints it, so what you approve is what you read.
    Approve {
        id: String,
        #[arg(long, value_name = "64 HEX DIGITS")]
        digest: String,
        /// The approval key on this computer.
        #[arg(long, default_value = "laptop")]
        key: String,
    },
    /// Deny a pending request, or revoke one that is approved and not yet used.
    Deny {
        id: String,
        #[arg(long, default_value = "laptop")]
        key: String,
    },
    /// The laptop keys enrolled on the box, and which have proved presence.
    Keys,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalKeyCommand {
    /// Make a key on this computer and enrol its public half on a box. Once the box has a second factor this needs an
    /// approval (from the dashboard, or from a key already enrolled).
    Enroll {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
        #[arg(long, default_value = "laptop")]
        key: String,
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
    },
    /// Remove a key from a box (and from this computer's keychain).
    Revoke {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
        #[arg(long, default_value = "laptop")]
        key: String,
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
    },
    /// The keys enrolled on a box (names only).
    List {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: BoxName,
    },
}

#[derive(Debug, Subcommand)]
pub enum TunnelCommand {
    /// Save which provider reaches the dashboard and at what address. A token is read from standard input.
    Setup {
        /// cloudflare, tailscale-funnel, tailscale-serve, caddy or ngrok.
        #[arg(value_name = "PROVIDER")]
        tunnel_provider: String,
        /// The exact address people open, like https://ozbox.example.com.
        #[arg(long)]
        public_url: String,
        /// Read the provider's token (Cloudflare tunnel token, ngrok auth token) from standard input, one line.
        #[arg(long)]
        token_stdin: bool,
        /// Caddy: your server's name, like vps.example.com.
        #[arg(long)]
        ssh_host: Option<String>,
        /// Caddy: the account on your server the tunnel signs in as.
        #[arg(long)]
        ssh_user: Option<String>,
        /// Caddy: your server's SSH port.
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// Caddy: the private key file made for this tunnel.
        #[arg(long)]
        ssh_key: Option<String>,
        /// Caddy: the loopback port on your server that Caddy forwards to.
        #[arg(long, default_value_t = 7878)]
        remote_port: u16,
        /// Cloudflare only: run the tunnel on this box, as the box user's own service, instead of saving it for this
        /// computer's dashboard. The token is read from standard input (--token-stdin) and kept in a private file on the box.
        #[arg(long, value_name = "BOX", value_parser = parse_name)]
        on_box: Option<BoxName>,
        /// Replace a token that is already stored. Without this a stored token is never overwritten, and with it the
        /// replacement needs a typed confirmation at a terminal (a token decides where the dashboard is reached from).
        #[arg(long)]
        replace: bool,
        /// On a box whose dashboard has a second factor: a single-use approval code for this token change, from
        /// `ozbox secrets approve --box <box> --scope tunnel-token --project <provider>` on the computer that made the box.
        /// It also counts as the confirmation `--replace` asks for. Read from `OZBOX_TUNNEL_APPROVAL` when not given here.
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
        /// Read the approval code from the line after the token on standard input (needs --token-stdin), so it is in no
        /// argument and no environment.
        #[arg(long)]
        approval_stdin: bool,
    },
    /// Show the saved tunnel, whether it is running, and whether the public address answers.
    Status {
        /// Do not ask the public address; show only what is saved and what the server reported.
        #[arg(long)]
        no_probe: bool,
    },
    /// Forget the saved tunnel and its token, or with --on-box stop the tunnel running on a box and delete its token there.
    Remove {
        #[arg(long, value_name = "BOX", value_parser = parse_name)]
        on_box: Option<BoxName>,
    },
}

#[derive(Debug, Subcommand)]
pub enum DashboardCommand {
    /// Install the dashboard as a service on a box, with its tunnel, running as a user of its own (never the box user). Shows
    /// the plan first.
    Install {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// The address people open, like https://ozbox.example.com.
        #[arg(long)]
        public_url: String,
        /// cloudflare, tailscale-funnel, tailscale-serve, caddy or ngrok.
        #[arg(long)]
        tunnel: Option<String>,
        /// Where the box downloads the `ozbox` program for Linux from (https). Leave out to use the signed release of
        /// this version: it is downloaded and checked on this computer (a private release repository works, using your
        /// own GitHub sign-in) and sent to the box, which checks its sha256 again.
        #[arg(long, requires = "binary_sha256")]
        binary_url: Option<String>,
        /// The sha256 of that file, which the box checks before running it.
        #[arg(long, requires = "binary_url")]
        binary_sha256: Option<String>,
        /// The release to take the program from when --binary-url is left out: `0.3.0`, `image-v0.3.0` or
        /// `v0.3.0`. Default: the image release the box itself is from. The box's own program is used when it is the one
        /// that release's signed manifest lists; otherwise the release's signed program is downloaded here and sent.
        #[arg(long)]
        release: Option<String>,
        /// The GitHub repository (owner/name) whose signed release is used when --binary-url is left out. The program is
        /// downloaded and checked on this computer, with your own GitHub sign-in when the repository is private, and sent
        /// to the box. Default: the project's own repository.
        #[arg(long)]
        release_repo: Option<String>,
        /// Someone allowed to sign in: `id[,label=Name][,github=login][,google=email][,access=email][,role=owner|member|viewer]`. The first person is the owner unless a role says otherwise; the rest are members. Repeat.
        #[arg(long = "person", required = true)]
        people: Vec<String>,
        /// Cloudflare Access team domain, like myteam.cloudflareaccess.com (needs --access-audience).
        #[arg(long, requires = "access_audience")]
        access_team: Option<String>,
        /// The Access application's audience tag.
        #[arg(long)]
        access_audience: Option<String>,
        /// Read the tunnel's token from standard input, one line (it never appears in a command line).
        #[arg(long)]
        token_stdin: bool,
        /// Caddy: your server's name.
        #[arg(long)]
        ssh_host: Option<String>,
        /// Caddy: the account on your server the tunnel signs in as.
        #[arg(long)]
        ssh_user: Option<String>,
        /// Caddy: your server's SSH port.
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// Caddy: the loopback port on your server that Caddy forwards to.
        #[arg(long, default_value_t = 7878)]
        remote_port: u16,
        /// On a box whose dashboard has a second factor: a single-use approval code for changing the tunnel's token, from
        /// `ozbox secrets approve --box <box> --scope tunnel-token --project <provider> --token-stdin` on this computer
        /// (the same token piped in; a box from an older image takes a code made without --token-stdin).
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
        /// Read the approval code from the line after the token on standard input (needs --token-stdin), so it is not in
        /// this computer's command line or shell history.
        #[arg(long, requires = "token_stdin")]
        approval_stdin: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Write the public address and the list of people who may sign in.
    Init {
        /// The exact address people open, like https://box.example.com (https; plain http only for localhost).
        #[arg(long)]
        origin: String,
        /// Someone allowed to sign in: `id[,label=Name][,github=login][,google=email][,access=email][,role=owner|member|viewer]`. The first person is the owner unless a role says otherwise; the rest are members. Repeat.
        #[arg(long = "person", required = true)]
        people: Vec<String>,
        /// Your own GitHub OAuth app's client ID (device flow enabled; no secret needed).
        #[arg(long)]
        github_client_id: Option<String>,
        /// Your own Google OAuth client ID (the secret is entered in the dashboard).
        #[arg(long)]
        google_client_id: Option<String>,
        /// Cloudflare Access team domain, like myteam.cloudflareaccess.com (needs --access-audience).
        #[arg(long, requires = "access_audience")]
        access_team: Option<String>,
        /// The Access application's audience tag.
        #[arg(long)]
        access_audience: Option<String>,
        /// Where to write it (default: auth.toml beside the main configuration).
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Set what a person may do (owner, member or viewer), for an operator who cannot do it from the dashboard: every
    /// owner has lost their passkey, or the settings file's role should win over one chosen there. Stop the dashboard
    /// first, then start it again: it holds the roles in memory and would write over this.
    Role {
        /// The person's id, as in the settings file.
        id: String,
        /// owner, member or viewer.
        role: String,
        /// The sign-in settings file (default: auth.toml beside the main configuration).
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PriceCommand {
    /// Set the price of a model.
    Set {
        /// The provider id from `ozbox models list`.
        #[arg(value_name = "PROVIDER")]
        provider_id: String,
        model: String,
        /// US dollars per million input tokens.
        #[arg(long)]
        input: f64,
        /// US dollars per million output tokens.
        #[arg(long)]
        output: f64,
    },
    /// Go back to the built-in estimate (or no price) for a model.
    Clear {
        #[arg(value_name = "PROVIDER")]
        provider_id: String,
        model: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ModelsCommand {
    /// The providers, whether each has a key, and the model chosen per engine.
    List,
    /// Add a provider. The key, if any, is read from standard input with --key-stdin and never shown again.
    Add {
        /// A short name: lower-case letters, digits and dashes.
        id: String,
        /// anthropic, openai, google, bedrock, azure_openai, vertex, openrouter, mistral, groq, together or openai_compatible.
        #[arg(long)]
        kind: String,
        /// A name to show (default: the id).
        #[arg(long)]
        label: Option<String>,
        /// openai_compatible only: the endpoint address, ending before /chat/completions.
        #[arg(long)]
        base_url: Option<String>,
        /// The endpoint is your own server: plain http to this computer or a private network address is allowed.
        #[arg(long)]
        local: bool,
        /// bedrock only: the AWS region of your account.
        #[arg(long)]
        region: Option<String>,
        /// azure_openai only: the name of your Azure OpenAI resource.
        #[arg(long)]
        resource: Option<String>,
        /// A local endpoint that runs on this box (Ollama or vLLM from the Tools catalog).
        #[arg(long)]
        hosted_on: Option<String>,
        /// A monthly spend cap in US dollars.
        #[arg(long)]
        cap: Option<f64>,
        /// Read the key from standard input, one line.
        #[arg(long)]
        key_stdin: bool,
    },
    /// Ask the provider which models these credentials can use (free). With --ping, send one tiny test message.
    Test {
        id: String,
        /// Send one one-word message instead (can cost a fraction of a cent; needs --yes).
        #[arg(long)]
        ping: bool,
        /// The model for --ping (default: a default model that uses this provider).
        #[arg(long)]
        model: Option<String>,
    },
    /// Remove a provider, its key and every choice that uses it.
    Remove { id: String },
    /// Your own price for one model (US dollars per million tokens). It wins over the built-in estimate.
    Price {
        #[command(subcommand)]
        command: PriceCommand,
    },
    /// Choose the model for coding, chat or review, or for an agent engine (claude-code, codex, gemini-cli, aider, opencode).
    Default {
        target: String,
        provider: Option<String>,
        model: Option<String>,
        /// An engine's fallback, as provider:model.
        #[arg(long)]
        fallback: Option<String>,
        /// Make the engine's choice for this box only.
        #[arg(long = "box")]
        on_box: Option<String>,
        /// Remove the choice.
        #[arg(long, conflicts_with_all = ["provider", "model", "fallback"])]
        clear: bool,
    },
    /// Which engine would get which provider and model, and which environment variable NAMES carry its credentials
    /// (never the values). Changes nothing.
    Resolve {
        engine: String,
        /// The box the run would be on.
        #[arg(long = "box")]
        on_box: Option<String>,
    },
    /// Record what a model call used, so Usage and spend caps can count it. Runs call this; names and counts only.
    Record {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        model: String,
        #[arg(long)]
        input_tokens: u64,
        #[arg(long)]
        output_tokens: u64,
        #[arg(long, default_value_t = 0)]
        cached_input_tokens: u64,
        #[arg(long = "box")]
        on_box: Option<String>,
        #[arg(long)]
        engine: Option<String>,
    },
    /// Tokens and estimated cost recorded by runs, by model.
    Usage {
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum CostCommand {
    /// This month's real bill for what Oz Box made, by box and service (read-only; AWS only, needs Cost Explorer access).
    Bill,
    /// Compare the estimate with the bill, day by day, and say the likely cause of each difference.
    Reconcile,
    /// Resources that look like Oz Box's but are not tagged, and disks and snapshots no box uses, with what each costs.
    /// `--delete` plans the removal of the tagged unused ones.
    Orphans {
        /// Delete these tagged, unused disks and snapshots (shows the plan, then asks you to type the words).
        #[arg(long = "delete", num_args = 1..)]
        delete: Vec<String>,
        /// The words the plan asks for, for a terminal that cannot ask.
        #[arg(long)]
        confirm: Option<String>,
        /// Look in this region too. Repeatable.
        #[arg(long = "region")]
        regions: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ToolsCommand {
    /// Every tool and whether it is installed on the box.
    List {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Show what installing or removing would do. Changes nothing.
    Plan {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// Tool ids and `bundle:<name>`.
        ids: Vec<String>,
        /// Plan the removal of these tools instead.
        #[arg(long)]
        remove: bool,
    },
    /// Install tools: shows the plan, asks, applies, and follows the job.
    Install {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        ids: Vec<String>,
        /// Install the tools chosen when the box was created.
        #[arg(long, conflicts_with = "ids")]
        pending: bool,
    },
    /// Remove tools.
    Remove {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        ids: Vec<String>,
    },
    /// Recent install and remove jobs.
    Jobs {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Tools an agent on the box has asked for.
    Requests {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Approve an agent's request; it installs the tool through the usual plan.
    Approve {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        id: String,
        /// Also approve future requests for this tool.
        #[arg(long)]
        always: bool,
    },
    /// Turn an agent's request down.
    Deny {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Save a running box's tools, size, disk and labels as a profile.
    Save {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        profile: String,
        #[arg(long)]
        description: Option<String>,
        /// Replace a profile that already has this name.
        #[arg(long)]
        overwrite: bool,
    },
    List,
    Show {
        profile: String,
    },
    Delete {
        profile: String,
    },
}

fn parse_name(s: &str) -> Result<BoxName, String> {
    BoxName::new(s).map_err(|e| e.to_string())
}

fn parse_size(s: &str) -> Result<Size, String> {
    s.parse::<Size>().map_err(|e| e.to_string())
}

fn parse_label(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(format!("expected key=value, got {s:?}")),
    }
}

/// Where a backup goes: the provider's snapshots, or a restic repository you own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackupTo {
    Snapshot,
    Restic,
    Both,
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// A box's backups: provider snapshots and repository backups, newest first.
    List {
        #[arg(value_parser = parse_name)]
        name: BoxName,
    },
    /// Back up a box now. Shows the plan, asks, applies.
    Now {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// Where to: the provider's snapshot, the restic repository, or both. Default: what Settings -> Backups turned on.
        #[arg(long, value_enum)]
        to: Option<BackupTo>,
    },
    /// Restore a backup. A provider snapshot goes to a new box (--new-box) or replaces /work (--in-place); a repository
    /// backup goes into a folder beside the box's files, over /work (--in-place), or into a new box (--to-new-box: it
    /// creates the box, restores into it and checks it, and running the same command again carries on if it stopped).
    #[command(group(ArgGroup::new("target").multiple(false).args(["new_box", "in_place"])))]
    Restore {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        /// The backup's id, as `backup list` shows it.
        id: String,
        /// Create this new box with /work restored from the backup (a provider snapshot or a repository backup).
        #[arg(long, alias = "to-new-box", value_parser = parse_name)]
        new_box: Option<BoxName>,
        /// Replace /work of this box. High risk: the box name is typed, and the current state is kept first.
        #[arg(long)]
        in_place: bool,
    },
    /// Delete one backup. It cannot be brought back.
    Delete {
        #[arg(value_parser = parse_name)]
        name: BoxName,
        id: String,
    },
    /// Show or change the backup schedule and retention (the same settings as Settings -> Backups).
    Schedule {
        /// Change one box's schedule instead of the fleet's.
        #[arg(long, value_parser = parse_name)]
        r#box: Option<BoxName>,
        /// off, daily or weekly.
        #[arg(long, value_parser = ["off", "daily", "weekly"])]
        every: Option<String>,
        /// The time on your own clock, HH:MM.
        #[arg(long)]
        at: Option<String>,
        /// The weekday for a weekly schedule: mon, tue, wed, thu, fri, sat or sun.
        #[arg(long)]
        on: Option<String>,
        #[arg(long)]
        keep_daily: Option<u32>,
        #[arg(long)]
        keep_weekly: Option<u32>,
        #[arg(long)]
        keep_monthly: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
pub enum RunCommand {
    /// Queue a run. `ozbox serve` admits it when the box has room and supervises it.
    Start {
        /// The agent engine, like claude-code.
        #[arg(long)]
        engine: String,
        /// The box it runs on.
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        box_name: BoxName,
        /// A repository under /work/repos.
        #[arg(long)]
        repo: Option<String>,
        /// The branch to work on.
        #[arg(long)]
        branch: Option<String>,
        /// A skill to run.
        #[arg(long)]
        skill: Option<String>,
        /// What to do.
        #[arg(long)]
        prompt: Option<String>,
        /// Read what to do from a file.
        #[arg(long, value_name = "FILE")]
        prompt_file: Option<std::path::PathBuf>,
        /// Pause and ask after this many active minutes.
        #[arg(long)]
        max_minutes: Option<u64>,
        /// Pause and ask after this many US dollars.
        #[arg(long)]
        max_spend: Option<f64>,
        /// Pause and ask after this many tokens.
        #[arg(long)]
        max_tokens: Option<u64>,
        /// Where the result goes besides the board: pr, alert. Comma separated.
        #[arg(long, value_delimiter = ',')]
        deliver: Vec<String>,
        /// Starting the same key again returns the first run.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// A provider and model for this run only, like `openai/gpt-4o` (a provider id from Settings -> Models).
        #[arg(long, value_name = "PROVIDER/MODEL")]
        model: Option<String>,
    },
    /// List runs, newest first.
    List {
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        box_name: Option<BoxName>,
        #[arg(long)]
        engine: Option<String>,
        /// queued, running, needs_you, review, done, failed or cancelled.
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        person: Option<String>,
        /// Only runs created since this time, like 2026-11-09T12:00:00Z.
        #[arg(long)]
        since: Option<String>,
    },
    /// Show one run.
    Show { id: String },
    /// Print a run's log.
    Logs {
        id: String,
        /// How many of the last lines.
        #[arg(long, default_value_t = 100)]
        tail: usize,
    },
    /// Stop a run. Its work is saved to a WIP branch first.
    Cancel { id: String },
    /// Start a failed or cancelled run again.
    Retry { id: String },
    /// Add budget to a run paused at a limit, and let it continue from its saved work.
    Resume {
        id: String,
        #[arg(long)]
        add_spend: Option<f64>,
        #[arg(long)]
        add_minutes: Option<u64>,
        #[arg(long)]
        add_tokens: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PermissionsCommand {
    /// The mode, the rules and the active grants.
    Show,
    /// Set the default mode: ask, plan_only, accept_edits or auto.
    Mode { mode: String },
    /// Allow actions on something tagged production for a short time. Cannot be extended; revoke it any time.
    Grant {
        /// What it covers: box, project, run or orchestration.
        #[arg(long)]
        scope: String,
        /// The name of that box, project, run or orchestration.
        #[arg(long)]
        id: String,
        /// Why (at least 8 characters). It is kept with the grant.
        #[arg(long)]
        reason: String,
        /// How long, from 1 minute to 240 (4 hours).
        #[arg(long)]
        minutes: u64,
        /// An action it covers, such as git.* (repeatable; default all).
        #[arg(long = "action")]
        actions: Vec<String>,
        /// Type the same name as --id. This is not a second factor.
        #[arg(long)]
        confirm: Option<String>,
        /// Let a run started by a schedule or trigger use it.
        #[arg(long)]
        unattended: bool,
        /// At most this many uses.
        #[arg(long)]
        uses: Option<u32>,
    },
    /// End a grant now.
    Revoke { id: String },
    /// What would the engine say about an action? Changes nothing.
    Check {
        /// An action name, like git.push or box.destroy.
        action: String,
        #[arg(long = "box")]
        r#box: Option<String>,
        /// sandbox, staging or production.
        #[arg(long)]
        env: Option<String>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        writes: Option<bool>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// The latest entries, newest first.
    List {
        #[arg(long, default_value_t = 30)]
        limit: usize,
        /// Only actions starting with this, like permission. or grant.
        #[arg(long)]
        action: Option<String>,
    },
    /// Check the whole chain: names changed, missing and out-of-order entries and a cut-off end. Exits non-zero if it fails.
    Verify,
    /// Seal the chain up to its last entry now.
    Seal,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// What is waiting for an answer.
    List {
        /// Include decided and expired requests.
        #[arg(long)]
        all: bool,
    },
    /// Let the agent do it. A request that needs a second factor needs --yes here.
    Approve { id: String },
    /// Refuse it.
    Deny { id: String },
}

#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Run `COMMAND` with `{{secret:NAME}}` references and --var names filled from the project's secrets. Only names given
    /// with --allow are delivered; a production key never is.
    Run {
        #[arg(long)]
        project: String,
        #[arg(long = "env")]
        env: String,
        /// A name this command may receive. Repeatable.
        #[arg(long, value_name = "NAME")]
        allow: Vec<String>,
        /// A name to put in the command's environment under its own name (it must also be allowed). Repeatable.
        #[arg(long = "var", value_name = "NAME")]
        vars: Vec<String>,
        /// The command the project declared (`ozbox env policy set`): what it may receive comes from that declaration, not from
        /// --allow or --var. Required on a box.
        #[arg(long, value_name = "NAME")]
        named: Option<String>,
        /// A plain value for a name the command declared in `pass` (`NAME=value`). Never a secret: the box refuses a value that
        /// looks like one or holds a stored one. Repeatable.
        #[arg(long = "pass", value_name = "NAME=VALUE")]
        pass: Vec<String>,
        /// Start the declared service `--named` names, wait for its health check, and return. It keeps running until `--stop`.
        #[arg(long, conflicts_with_all = ["stop", "status"], requires = "named")]
        start: bool,
        /// Stop the declared service.
        #[arg(long, conflicts_with_all = ["start", "status"], requires = "named")]
        stop: bool,
        /// Say whether the declared service is running and healthy, with what it printed last.
        #[arg(long, conflicts_with_all = ["start", "stop"], requires = "named")]
        status: bool,
        #[arg(last = true, required_unless_present_any = ["start", "stop", "status"])]
        command: Vec<String>,
    },
    /// Declare which secret names each named command of a project may receive, from a JSON file.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum GuardCommand {
    /// Put the hooks in every repository under a folder (default /work). Safe to run again: it keeps a repository's own
    /// hooks (they run after ours) and puts back one that was removed.
    Install {
        #[arg(long, default_value = "/work")]
        root: std::path::PathBuf,
    },
    /// Wait for an approval request to be decided (the waiting hook of ADR 0041 §6): prints where to decide it, waits in long
    /// polls, and on approval prints the request's digest. Ctrl-C stops waiting; the request stays for 30 minutes. Exits 0
    /// only when it was approved.
    Wait {
        /// The request id the blocked operation was given.
        id: String,
    },
    /// What git runs: `pre-commit`, `post-commit` or `pre-push`. A person never runs it.
    #[command(hide = true)]
    Hook {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Save a project's declaration. With --box it goes to that box's secrets service over its SSH route.
    Set {
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        #[arg(long)]
        project: String,
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        on_box: Option<BoxName>,
        /// The approval code from the dashboard (see `ozbox secrets import --approval`).
        #[arg(long, value_name = "CODE")]
        approval: Option<String>,
    },
    /// Print what to pin, to paste into a declaration. Run it on YOUR computer, against your own checkout at the commit the box
    /// has (`--commit`): a digest computed on the box only freezes what an agent may already have changed. It reads files and
    /// prints digests; it changes nothing. FILE words give `pin` entries; `--entry` follows a script and prints every file and
    /// package folder it loads (`pin` and `pin_tree`); `--tree` pins a folder; `--tool NAME=DIR` prints the digest of a tool you
    /// extracted yourself from the catalog's checked release; `--browser NAME --browser-cache DIR` prints `browser_digests` for a
    /// Playwright browser cache you downloaded yourself.
    Pin {
        #[arg(long, value_name = "DIR")]
        dir: std::path::PathBuf,
        /// A script that receives a secret: print the pins for it and everything it loads.
        #[arg(long, value_name = "FILE")]
        entry: Vec<String>,
        /// A folder under DIR (such as node_modules/some-package) to pin by the content of every file in it.
        #[arg(long, value_name = "PATH")]
        tree: Vec<String>,
        /// A catalog tool and the folder you extracted it to (`node=./node-v22-linux-x64`): print the digest of that folder.
        #[arg(long, value_name = "NAME=DIR")]
        tool: Vec<String>,
        /// A browser (chromium): print the digest of each revision in `--browser-cache`, or with `--revision` of Playwright's own
        /// Linux build, downloaded here from its CDN.
        #[arg(long, value_name = "NAME")]
        browser: Vec<String>,
        /// With `--tool NAME` (no folder): fetch the catalog's Linux release of that version for the box's architecture, check it
        /// against the catalog's checksum and print the digest the box will see. Needs `--arch` unless the box is amd64.
        #[arg(long, value_name = "VERSION")]
        release: Option<String>,
        /// With `--browser`: the Playwright revision of ONE folder, as `KIND=N` (`chromium=1169`, `chromium_headless_shell=1169`,
        /// `ffmpeg=1011`: the number in the cache folder's name), downloaded here from Playwright's CDN. Give one for each folder the
        /// browser needs; a folder left out is refused.
        #[arg(long, value_name = "KIND=N")]
        revision: Vec<String>,
        /// The box's architecture for `--release` and `--revision`: amd64 (x86_64, `linux-x64`) or arm64 (aarch64). Default amd64.
        #[arg(long, value_name = "ARCH")]
        arch: Option<String>,
        /// A Playwright browser cache folder (what `PLAYWRIGHT_BROWSERS_PATH` points at) you downloaded yourself.
        #[arg(long, value_name = "DIR")]
        browser_cache: Option<std::path::PathBuf>,
        /// The commit the box reports for the project folder (`git rev-parse HEAD` there). Your checkout must be at it, and clean.
        #[arg(long, value_name = "SHA")]
        commit: Option<String>,
        /// Compute on this box anyway. The digests then freeze what is on the box now, which an agent may have changed.
        #[arg(long)]
        on_box: bool,
        #[arg(value_name = "FILE")]
        files: Vec<String>,
    },
    /// Show the declaration stored on this machine (never a value).
    Show {
        #[arg(long)]
        project: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TasksCommand {
    /// Create this endpoint's keys and name. Run once on each side.
    Init {
        #[arg(long)]
        name: String,
    },
    /// Print this endpoint's public identity, to hand to the other side by a way you trust.
    Identity,
    /// Pin the other side's identity (shows fingerprints first). `--via` is the command that reaches its `ozbox`, for example
    /// `"ssh my-box ozbox"`; it is run as an argument list, never through a shell.
    Pin {
        /// A file from `ozbox tasks identity`, or `-` for standard input.
        file: std::path::PathBuf,
        #[arg(long)]
        via: Option<String>,
        /// Change an existing pin (a new epoch after a restore, or new keys). Compare the fingerprints first.
        #[arg(long)]
        replace: bool,
    },
    /// Start a task for a pinned peer. It is held here and delivered on the next sync.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        text: Option<String>,
        /// Read the text from standard input.
        #[arg(long)]
        stdin: bool,
        /// A note: nothing is asked, nothing is expected back.
        #[arg(long)]
        note: bool,
        /// Give up after this many minutes (default 1440).
        #[arg(long)]
        minutes: Option<u64>,
    },
    /// Ask the peer to push one commit to one branch. Acts that need an approval are refused until the passkey approval path
    /// exists, and a Production act is refused outright.
    PushRef {
        #[arg(long)]
        to: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        remote: String,
        #[arg(long = "ref")]
        r#ref: String,
        #[arg(long)]
        sha: String,
        /// The environment the push is for (for example staging). Anything not known to be non-Production counts as Production.
        #[arg(long)]
        env: String,
    },
    /// What is waiting for you: tasks you received that are not finished, and anything with news.
    Inbox {
        #[arg(long)]
        all: bool,
    },
    /// One task with its messages, or (with no id) the pinned peers and what waits to be sent.
    Status { id: Option<String> },
    /// Answer a task, and optionally move its state (only the side that received it may).
    Reply {
        id: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        stdin: bool,
        /// working, input-required, completed or failed.
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Ask for a task to stop. A cancel is a request: the other side decides.
    Cancel { id: String },
    /// Why a task is where it is, and who acts next.
    Why { id: String },
    /// Send what is waiting and take what the peer has, once.
    Sync {
        #[arg(long)]
        peer: Option<String>,
    },
    /// Keep syncing every few seconds and print what is new. It runs only while you keep it open.
    Watch {
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value_t = 5)]
        every: u64,
        #[arg(long, hide = true)]
        rounds: Option<u64>,
    },
    /// The answering side of a sync (run by the other side through its `--via` command). Not for people.
    #[command(hide = true)]
    Exchange {
        #[arg(long)]
        peer: String,
    },
    /// Record that this endpoint's store was restored from a backup. It moves to a new epoch, so nothing captured before is
    /// accepted; every peer must pin the new epoch.
    Restored,
}

#[derive(Debug, Subcommand)]
pub enum OrchCommand {
    /// List orchestrations, newest first.
    List,
    /// One orchestration: its features, claims, contracts, messages, merge queue and spend.
    Show {
        id: String,
    },
    /// Start an orchestration. Limits can only be tighter than your settings (`ozbox orch settings`).
    Start {
        /// What the whole job is.
        #[arg(long)]
        goal: String,
        /// The box that holds the main branch (the conductor works there).
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        box_name: BoxName,
        /// An ozbox.orchestration.md file: limits and house rules.
        #[arg(long, value_name = "FILE")]
        rules_file: Option<std::path::PathBuf>,
        #[arg(long)]
        max_workers: Option<u8>,
        #[arg(long)]
        max_sub_agents: Option<u8>,
        /// One spend cap for the whole orchestration, in US dollars.
        #[arg(long)]
        max_spend: Option<f64>,
        /// Also queue a conductor run on that box.
        #[arg(long)]
        conduct: bool,
        /// What to add to the conductor's instructions.
        #[arg(long)]
        prompt: Option<String>,
    },
    /// Check a rules file and show what would apply.
    Rules {
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
    },
    /// Show or change your limits for orchestrations (the most a rules file or a request may ask for).
    Settings {
        #[arg(long)]
        max_workers: Option<u8>,
        #[arg(long)]
        max_sub_agents: Option<u8>,
        #[arg(long)]
        max_spend: Option<f64>,
        /// none, conductor or person: who approves a merge.
        #[arg(long)]
        merge_approval: Option<String>,
    },
    /// Add a feature for a worker box.
    Feature {
        id: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        brief: String,
        /// The worker box.
        #[arg(long = "box", value_name = "BOX", value_parser = parse_name)]
        box_name: Option<BoxName>,
        /// Files, directories or globs the worker owns. Repeat or comma separate.
        #[arg(long, value_delimiter = ',')]
        claim: Vec<String>,
        /// Contracts to build against.
        #[arg(long, value_delimiter = ',')]
        contract: Vec<String>,
        #[arg(long)]
        engine: Option<String>,
        #[arg(long)]
        sub_agents: Option<u8>,
        #[arg(long)]
        max_spend: Option<f64>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Pause, resume or stop one feature's worker (its work is saved to its branch first).
    Worker {
        /// pause, resume or stop.
        verb: String,
        id: String,
        feature: String,
    },
    /// Pause, resume or stop a whole orchestration.
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
    Stop {
        id: String,
    },
    /// The mailbox between the conductor, the workers and you.
    Messages {
        id: String,
        #[arg(long, default_value_t = 0)]
        since: u64,
    },
    /// Answer a worker's question (the ones marked for you).
    Answer {
        id: String,
        question: u64,
        #[arg(long)]
        text: String,
    },
    /// Send a worker an instruction.
    Message {
        id: String,
        feature: String,
        #[arg(long)]
        text: String,
    },
    /// Declare or check the files a feature owns.
    Claims {
        id: String,
        feature: String,
        #[arg(long, value_delimiter = ',')]
        declare: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        check: Vec<String>,
    },
    /// Publish or read a shared contract.
    Contract {
        id: String,
        #[arg(long)]
        name: Option<String>,
        /// api, types, schema or doc.
        #[arg(long, default_value = "api")]
        kind: String,
        #[arg(long, value_name = "FILE")]
        body_file: Option<std::path::PathBuf>,
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,
    },
    /// The merge queue: put a finished feature in it, or see where it stands.
    Merge {
        id: String,
        /// The feature to queue; leave out to see the queue.
        feature: Option<String>,
    },
    /// What the orchestration has spent against its cap; add budget to continue after the cap.
    Budget {
        id: String,
        /// US dollars to add to the cap.
        #[arg(long)]
        add: Option<f64>,
    },
    /// Print the MCP settings an agent needs to reach the Oz Box tools.
    McpConfig,
}

#[derive(Debug, Subcommand)]
pub enum AgentMcpCommand {
    /// The MCP server an engine starts (stdio). Not for typing by hand: `install` puts it in the engines' settings.
    #[command(hide = true)]
    Bridge,
    /// Add the Oz Box tools to the coding agents' settings in your home folder (safe to run again; your other servers stay).
    Install {
        /// Only this engine: claude-code, codex, gemini-cli or opencode.
        #[arg(long)]
        engine: Option<String>,
    },
    /// Take the Oz Box tools out of the coding agents' settings again.
    Remove {
        #[arg(long)]
        engine: Option<String>,
    },
    /// Which engines have the Oz Box tools in their settings.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommand {
    /// List notes (add --pending for what agents proposed and nobody has reviewed).
    List {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        pending: bool,
    },
    /// Search notes by words.
    Search {
        query: String,
        #[arg(long)]
        scope: Option<String>,
    },
    /// One note in full, with who wrote and who approved it.
    Show { id: String },
    /// Add a note (approved at once). The scope is person:name, project:name or box:name.
    Add {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        body: String,
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Forget it after this many days.
        #[arg(long)]
        expires_days: Option<u64>,
    },
    /// Change a note's title, text or tags.
    Edit {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        body: Option<String>,
    },
    /// Approve an agent's proposal so agents can read it.
    Approve { id: String },
    /// Forget a note, or reject a proposal. Git history keeps it.
    Forget { id: String },
    /// Rebuild the search index from the files.
    Reindex,
}

#[derive(Debug, Subcommand)]
pub enum SkillsCommand {
    /// The catalog: what ships with Oz Box and what you added, with each skill's hash and installs.
    List,
    /// Print a skill's files as they would be approved.
    Show { name: String },
    /// Add a skill folder (it must be named for the skill and hold a SKILL.md) to your library.
    Add { dir: std::path::PathBuf },
    /// Install at fleet, box:name or project:name. Installing does not approve.
    Install {
        name: String,
        #[arg(long, default_value = "fleet")]
        scope: String,
    },
    /// Remove an install.
    Uninstall {
        name: String,
        #[arg(long, default_value = "fleet")]
        scope: String,
    },
    /// Approve the skill's current files (shown first; the hash is what you approve).
    Approve { name: String },
    /// Withdraw every approval of a skill.
    Revoke { name: String },
}

#[derive(Debug, Subcommand)]
pub enum FailoverCommand {
    /// Keep schedules and triggers in `s3://bucket/key` (conditional writes; your own AWS credentials).
    Set {
        s3: String,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Back to one computer keeping its own.
    Off,
    /// Whether it is on, and who holds the lease.
    Status,
}
