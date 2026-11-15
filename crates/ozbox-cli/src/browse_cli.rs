//! The box end of a browsing session (ADR 0037). The worker (`ozbox browser-worker`) is what a browsing session runs as on the
//! box: it reads its settings as the first line on standard input, then answers one line per request (ADR 0037).

use std::io::BufRead;

use ozbox_browser::protocol::Start;

use crate::run::CliError;

/// The box end of a browsing session. A person never runs it: the browser tools start it as a run with its input kept open.
pub fn run_worker() -> Result<(), CliError> {
    let stdin = std::io::stdin();
    let mut first = String::new();
    stdin
        .lock()
        .read_line(&mut first)
        .map_err(|e| CliError::Msg(e.to_string()))?;
    let start: Start = serde_json::from_str(first.trim()).map_err(|e| {
        CliError::Msg(format!(
            "the browser worker was not given its settings: {e}"
        ))
    })?;
    let mut out = std::io::stdout().lock();
    ozbox_browser::worker::run(start, std::io::BufReader::new(std::io::stdin()), &mut out)
        .map_err(CliError::Msg)
}
