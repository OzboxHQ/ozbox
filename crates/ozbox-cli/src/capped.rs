//! `ozbox capped [--max-gib N] [--soft] -- <command>`: run a command inside a memory cap, on the box you are standing on.
//!
//! For a person in a terminal and for an agent's hooks: a production build, a test browser or a local model server is the kind
//! of job that fills a box and stalls it (ADR 0045). The command runs in its own systemd scope under the box user's manager
//! with the same numbers the daemon gives every run it starts (`ozbox_core::memory_plan`): throttled well before it is
//! killed, a share of the compressed swap, and killed on its own, never the terminal around it, if it passes its cap. It is
//! never run uncapped as a fallback: if the scope cannot be made, it says so and stops.

use ozbox_core::memory_plan::{self as plan, sizing, CAPPED_OOM_SCORE_ADJ, GIB};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opts {
    /// A cap smaller than the default, in GiB.
    pub max_gib: Option<u64>,
    /// Throttle only (`MemoryHigh`): nothing is ever killed.
    pub soft: bool,
    pub command: Vec<String>,
}

pub fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        max_gib: None,
        soft: false,
        command: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => {
                o.command = it.by_ref().cloned().collect();
            }
            "--soft" => o.soft = true,
            "--max-gib" => {
                let n: u64 = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n >= 1)
                    .ok_or("--max-gib needs a whole number of GiB, 1 or more")?;
                o.max_gib = Some(n);
            }
            _ if o.command.is_empty() && a.starts_with('-') => {
                return Err(format!(
                    "unknown option {a}; use --max-gib N, --soft, then -- and the command"
                ))
            }
            _ => {
                o.command.push(a.clone());
                o.command.extend(it.by_ref().cloned());
            }
        }
    }
    if o.command.is_empty() {
        return Err("give the command to run after --".into());
    }
    Ok(o)
}

/// The whole command line: `systemd-run` with the limits, then a wrapper that raises the command's own OOM score (it can
/// only be raised, so this never gives the command more than any other process of the box user has) and runs it.
pub fn argv(total_bytes: u64, o: &Opts) -> Result<Vec<String>, String> {
    let s = sizing(total_bytes);
    if s.run_max_bytes == 0 {
        return Err("this box's memory could not be read, so there is no cap to derive".into());
    }
    let max = o
        .max_gib
        .map_or(s.run_max_bytes, |g| (g * GIB).min(s.run_max_bytes));
    let high = plan::high_for(max);
    let mut v: Vec<String> = [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "-p",
        "MemoryAccounting=yes",
    ]
    .map(String::from)
    .to_vec();
    v.extend(["-p".into(), format!("MemoryHigh={high}")]);
    if !o.soft {
        v.extend(["-p".into(), format!("MemoryMax={max}")]);
        v.extend([
            "-p".into(),
            format!("MemorySwapMax={}", s.run_swap_max_bytes.min(max)),
        ]);
    }
    v.extend([
        "--".into(),
        "sh".into(),
        "-c".into(),
        format!(
            "{}; exec \"$@\"",
            plan::raise_score_snippet(CAPPED_OOM_SCORE_ADJ)
        ),
        "ozbox-capped".into(),
    ]);
    v.extend(o.command.iter().cloned());
    Ok(v)
}

/// Run it; the command's own exit code is this program's (a command ended by a signal: 128 plus the signal).
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = parse(args)?;
    let total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| plan::mem_total_from_meminfo(&t))
        .unwrap_or(0);
    let v = argv(total, &o)?;
    let status = std::process::Command::new(&v[0])
        .args(&v[1..])
        .status()
        .map_err(|e| format!("could not make the memory scope ({}): this needs systemd-run and the box user's own service manager (`ozbox admin <box> -- enable-linger`). The command was not run uncapped.", e.kind()))?;
    Ok(exit_code(&status))
}

/// The command's own exit code; a command ended by a signal gives 128 plus its number, as a shell reports it. An OOM kill is
/// 137, so a caller (and the proof) can tell it from the command failing by itself.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn the_command_comes_after_the_dashes_and_options_before() {
        let o = parse(&w("--max-gib 4 --soft -- npm run build")).unwrap();
        assert_eq!((o.max_gib, o.soft), (Some(4), true));
        assert_eq!(o.command, ["npm", "run", "build"]);
        // without the dashes, the first word that is not an option starts the command, flags and all
        assert_eq!(parse(&w("make -j4")).unwrap().command, ["make", "-j4"]);
        assert!(parse(&w("--max-gib 0 -- x")).is_err() && parse(&w("--max-gib")).is_err());
        assert!(parse(&w("--soft")).is_err() && parse(&w("--bogus -- x")).is_err());
    }

    #[test]
    fn a_default_cap_is_what_the_daemon_gives_every_run_and_the_command_is_never_a_shell_string() {
        let v = argv(8 * GIB, &parse(&w("-- npm run build")).unwrap()).unwrap();
        let s = sizing(8 * GIB);
        let line = v.join(" ");
        assert!(
            line.contains(&format!("MemoryMax={}", s.run_max_bytes)),
            "{line}"
        );
        assert!(
            line.contains(&format!("MemoryHigh={}", s.run_high_bytes)),
            "{line}"
        );
        assert!(
            line.contains(&format!("MemorySwapMax={}", s.run_swap_max_bytes)),
            "{line}"
        );
        assert!(v.starts_with(&["systemd-run".into(), "--user".into(), "--scope".into()]));
        // the person's words are arguments, not text for a shell to read: a `;` stays inside one word
        let tricky = argv(
            8 * GIB,
            &Opts {
                max_gib: None,
                soft: false,
                command: vec!["echo".into(), "a;b".into()],
            },
        )
        .unwrap();
        assert_eq!(&tricky[tricky.len() - 2..], ["echo", "a;b"]);
        assert!(line.contains("echo 300 >/proc/self/oom_score_adj"));
    }

    #[test]
    fn soft_throttles_and_never_kills_and_a_smaller_cap_is_honoured_never_a_larger_one() {
        let soft = argv(8 * GIB, &parse(&w("--soft -- x")).unwrap())
            .unwrap()
            .join(" ");
        assert!(
            soft.contains("MemoryHigh=")
                && !soft.contains("MemoryMax")
                && !soft.contains("MemorySwapMax")
        );
        let small = argv(8 * GIB, &parse(&w("--max-gib 2 -- x")).unwrap())
            .unwrap()
            .join(" ");
        assert!(small.contains(&format!("MemoryMax={}", 2 * GIB)), "{small}");
        let big = argv(8 * GIB, &parse(&w("--max-gib 64 -- x")).unwrap())
            .unwrap()
            .join(" ");
        assert!(
            big.contains(&format!("MemoryMax={}", sizing(8 * GIB).run_max_bytes)),
            "never above the box's own cap"
        );
        assert!(
            argv(0, &parse(&w("-- x")).unwrap()).is_err(),
            "unknown RAM is a refusal, not an uncapped run"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_command_ended_by_a_signal_is_128_plus_the_signal_never_1() {
        use std::os::unix::process::ExitStatusExt;
        // 9 is the OOM killer's: 137, what a shell says
        assert_eq!(exit_code(&std::process::ExitStatus::from_raw(9)), 137);
        assert_eq!(exit_code(&std::process::ExitStatus::from_raw(15)), 143);
        // a normal exit keeps its own code (the raw wait status holds it in the high byte)
        assert_eq!(exit_code(&std::process::ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(&std::process::ExitStatus::from_raw(0)), 0);
    }
}
