//! For a plugin written in Rust: answer the host.
//!
//! The host starts the program, sends `initialize`, then one or more requests, one JSON-RPC 2.0 message per line on
//! standard input, and reads one answer per line from standard output. Standard input closing is the end.
//!
//! ```no_run
//! use ozbox_plugin::{sdk, Failure};
//! fn main() {
//!     sdk::serve(|method, _params| match method {
//!         "describe" => Ok(serde_json::json!({"program": "mytunnel", "public": false})),
//!         _ => Err(Failure::new("unsupported", "not implemented")),
//!     });
//! }
//! ```

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::protocol::{Failure, Request, Response, API_VERSION, MAX_MESSAGE};

/// Serve requests from standard input until it closes, then exit.
pub fn serve<F>(handler: F) -> !
where
    F: FnMut(&str, Value) -> Result<Value, Failure>,
{
    let code = serve_io(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        handler,
    );
    std::process::exit(code)
}

/// [`serve`] over any reader and writer, so a test needs no process. `0` when the input ended normally, `2` when a line
/// was too long or not a request.
pub fn serve_io<F>(input: &mut dyn BufRead, out: &mut dyn Write, mut handler: F) -> i32
where
    F: FnMut(&str, Value) -> Result<Value, Failure>,
{
    let mut line = String::new();
    loop {
        line.clear();
        match input.read_line(&mut line) {
            Ok(0) => return 0,
            Ok(n) if n <= MAX_MESSAGE => {}
            _ => return 2,
        }
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Request>(&line) else {
            return 2;
        };
        let resp = if req.jsonrpc != "2.0" {
            Response::failure(
                req.id,
                Failure::new("bad_request", "this is a JSON-RPC 2.0 protocol"),
            )
        } else if req.method == "initialize" {
            let host = req.params["api_version"].as_u64().unwrap_or(0);
            if host == u64::from(API_VERSION) {
                Response::success(req.id, json!({ "api_version": API_VERSION }))
            } else {
                Response::failure(
                    req.id,
                    Failure::new(
                        "bad_request",
                        format!(
                            "this plugin speaks protocol {API_VERSION}, the host asked for {host}"
                        ),
                    ),
                )
            }
        } else {
            match handler(&req.method, req.params) {
                Ok(v) => Response::success(req.id, v),
                Err(f) => Response::failure(req.id, f),
            }
        };
        if writeln!(out, "{}", resp.to_line()).is_err() || out.flush().is_err() {
            return 2;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn call(input: &str) -> (i32, Vec<Response>) {
        let mut out = Vec::new();
        let code = serve_io(&mut input.as_bytes(), &mut out, |m, p| match m {
            "echo" => Ok(p),
            _ => Err(Failure::new("unsupported", "no")),
        });
        let text = String::from_utf8(out).unwrap();
        (code, text.lines().filter_map(Response::from_line).collect())
    }

    #[test]
    fn a_session_is_initialize_then_requests_one_answer_per_line() {
        let (c, r) = call(concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"api_version":1}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"echo","params":{"a":1}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#,
            "\n",
        ));
        assert_eq!(c, 0);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].outcome.as_ref().unwrap()["api_version"], 1);
        assert_eq!(r[1].outcome.as_ref().unwrap()["a"], 1);
        assert_eq!(r[2].outcome.as_ref().unwrap_err().code, "unsupported");
        assert_eq!(r[2].id, 3);
    }

    #[test]
    fn another_protocol_version_or_something_that_is_not_a_request_is_refused() {
        let (_, r) =
            call(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"api_version":2}}"#);
        assert!(r[0].outcome.is_err());
        let (_, r) = call(r#"{"jsonrpc":"1.0","id":1,"method":"echo"}"#);
        assert!(r[0].outcome.is_err());
        assert_eq!(call("not json\n").0, 2);
        assert_eq!(call("").0, 0);
    }

    #[test]
    fn unknown_fields_are_ignored_and_failures_carry_the_word_and_a_standard_number() {
        let (_, r) = call(r#"{"jsonrpc":"2.0","id":4,"method":"nope","future":true}"#);
        assert_eq!(r[0].outcome.as_ref().unwrap_err().code, "unsupported");
        let line = Response::failure(5, Failure::new("not_found", "x")).to_line();
        assert!(
            line.contains("-32001") && line.contains("\"kind\":\"not_found\""),
            "{line}"
        );
    }
}
