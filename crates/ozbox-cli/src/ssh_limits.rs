//! How long ozbox waits for an SSH connection to come up.
//!
//! A box on AWS is reached through Session Manager (`ProxyCommand` runs `aws ssm start-session`, then EC2 Instance Connect
//! pushes a key), and that handshake takes several seconds on its own: more than the ten seconds that were enough for a
//! plain TCP connect. The default is 30 seconds; `OZBOX_SSH_CONNECT_TIMEOUT` (seconds) or `[ssh] connect_timeout_secs` in the
//! config changes it, within 5 to 300.

use std::time::Duration;

pub const DEFAULT_SECS: u64 = 30;
const MIN_SECS: u64 = 5;
const MAX_SECS: u64 = 300;

/// The connect timeout for a value that may be absent or nonsense (then the default). Pure.
pub fn parse(v: Option<&str>) -> Duration {
    let secs = v
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map_or(DEFAULT_SECS, |n| n.clamp(MIN_SECS, MAX_SECS));
    Duration::from_secs(secs)
}

pub fn connect_timeout() -> Duration {
    parse(std::env::var("OZBOX_SSH_CONNECT_TIMEOUT").ok().as_deref())
}

/// `-o ConnectTimeout=<seconds>`, as one argument.
pub fn option() -> String {
    format!("ConnectTimeout={}", connect_timeout().as_secs())
}

/// How long to wait for a forward to bind: the connect timeout, and a little for the forward itself.
pub fn forward_wait() -> Duration {
    connect_timeout() + Duration::from_secs(15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_fits_an_ssm_handshake_and_a_setting_is_kept_within_bounds() {
        assert_eq!(parse(None), Duration::from_secs(30));
        assert!(
            parse(None) > Duration::from_secs(10),
            "the old limit was too short for SSM"
        );
        assert_eq!(parse(Some("45")), Duration::from_secs(45));
        assert_eq!(parse(Some(" 60 ")), Duration::from_secs(60));
        assert_eq!(parse(Some("1")), Duration::from_secs(5));
        assert_eq!(parse(Some("100000")), Duration::from_secs(300));
        assert_eq!(parse(Some("soon")), Duration::from_secs(30));
        assert_eq!(parse(Some("")), Duration::from_secs(30));
    }
}
