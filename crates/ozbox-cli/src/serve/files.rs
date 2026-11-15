//! The file browser's path through `ozbox serve`: the browser asks this server, this server asks the box's daemon over
//! the agent, and bytes are streamed in both directions (never held in memory) on their own threads, so a transfer
//! cannot stall the rest of the dashboard.
//!
//! Two kinds of URL reach here: `/v1/boxes/<box>/files/<op>` (the daemon's file API, behind the bearer token) and
//! `/dl/<box>/<link>` (an expiring download link, which is its own credential: it is what a browser can follow with
//! nothing but a URL). The daemon decides what any request may touch; this layer only forwards, limits and records.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use ozbox_core::BoxRecord;
use ozboxd::files::FilesService;

use super::agent::{BoxAgent, FileBody, FileInput, FileReply};
use super::{unix_ms, ActivityEntry, App, Req, Resp, MAX_BODY};

/// At most this many transfers at once through one server.
pub const MAX_TRANSFERS: usize = 6;

pub struct Proxy {
    transfers: Arc<AtomicUsize>,
    tx: Sender<ActivityEntry>,
    rx: Receiver<ActivityEntry>,
}

impl Default for Proxy {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self {
            transfers: Arc::new(AtomicUsize::new(0)),
            tx,
            rx,
        }
    }
}

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct FileJob {
    agent: Arc<dyn BoxAgent>,
    rec: BoxRecord,
    pub method: String,
    /// The daemon's path, `/v1/files/...`.
    pub path: String,
    query: BTreeMap<String, String>,
    action: Option<String>,
    /// Who asked, shown in Activity: a transfer outlives the request that started it.
    actor: String,
    tx: Sender<ActivityEntry>,
    /// The server's agent is the demo's: what it answers is made up (G7 X3). A page says so.
    simulated: bool,
    _slot: Slot,
}

fn is_op(seg: &str) -> bool {
    !seg.is_empty()
        && seg.len() <= 24
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `/v1/boxes/<box>/files/<op...>` or `/dl/<box>/<link>`: the box and the daemon path it maps to.
fn parse(req: &Req) -> Option<(String, String, BTreeMap<String, String>, bool)> {
    let segs: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
    match segs.as_slice() {
        ["v1", "boxes", name, "files", rest @ ..]
            if !rest.is_empty() && rest.len() <= 3 && rest.iter().all(|s| is_op(s)) =>
        {
            let q: BTreeMap<String, String> = super::parse_query(&req.query).into_iter().collect();
            Some((
                name.to_string(),
                format!("/v1/files/{}", rest.join("/")),
                q,
                false,
            ))
        }
        ["dl", name, link]
            if link.len() <= 120 && link.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.') =>
        {
            let q = BTreeMap::from([("token".to_string(), link.to_string())]);
            Some((name.to_string(), "/v1/files/download".into(), q, true))
        }
        _ => None,
    }
}

pub fn is_files_path(path: &str) -> bool {
    (path.starts_with("/v1/boxes/") && path.contains("/files/")) || path.starts_with("/dl/")
}

impl App {
    /// Check the request and bind it to a box. The caller then runs the job on its own thread.
    pub(super) fn prepare_files(&self, req: &Req) -> Result<FileJob, Resp> {
        let dl = req.path.starts_with("/dl/");
        if let Some(r) = self.guard(req, !dl) {
            return Err(r);
        }
        let (name, path, query, is_dl) =
            parse(req).ok_or_else(|| Resp::error(404, "not_found", "no such endpoint"))?;
        if !matches!(req.method.as_str(), "GET" | "PUT" | "POST" | "DELETE")
            || (is_dl && req.method != "GET")
        {
            return Err(Resp::error(405, "method_not_allowed", "method not allowed"));
        }
        let rec = self.running_box(&name)?;
        if self.files.transfers.fetch_add(1, Ordering::SeqCst) >= MAX_TRANSFERS {
            self.files.transfers.fetch_sub(1, Ordering::SeqCst);
            return Err(Resp::error(
                429,
                "too_many_transfers",
                "too many file transfers are running; try again in a moment",
            ));
        }
        let slot = Slot(Arc::clone(&self.files.transfers));
        let op = path.trim_start_matches("/v1/files/").to_string();
        let mutating = (req.method != "GET" && op != "trash/restore-preview") || is_dl;
        // The box's own audit holds paths; this server's activity list holds only what was done and how it went.
        let action =
            mutating.then(|| format!("files {}", if is_dl { "download" } else { op.as_str() }));
        Ok(FileJob {
            agent: Arc::clone(&self.agent),
            rec,
            method: req.method.clone(),
            path,
            query,
            action,
            actor: self.actor_of(req).shown(),
            tx: self.files.tx.clone(),
            simulated: self.simulated_metrics,
            _slot: slot,
        })
    }

    /// Fold in what finished transfers reported.
    pub(super) fn drain_file_activity(&mut self) {
        while let Ok(e) = self.files.rx.try_recv() {
            if self.activity.len() >= super::MAX_ACTIVITY {
                self.activity.pop_front();
            }
            self.activity.push_back(e);
        }
    }

    /// The same job, answered in memory: for requests that arrive through [`App::handle`] (tests and small replies).
    pub(super) fn files_inline(&self, req: &Req) -> Resp {
        let job = match self.prepare_files(req) {
            Ok(j) => j,
            Err(r) => return r,
        };
        let mut body = req.body.as_slice();
        let input = if FilesService::wants_stream_body(&job.method, &job.path) {
            let len = body.len() as u64;
            FileInput::Stream {
                reader: &mut body,
                len,
            }
        } else if body.is_empty() {
            FileInput::None
        } else {
            FileInput::Bytes(body)
        };
        match job.call(input) {
            Ok(reply) => reply_to_resp(reply),
            Err(r) => r,
        }
    }
}

fn reply_to_resp(reply: FileReply) -> Resp {
    let json = reply
        .header("content-type")
        .is_some_and(|t| t.starts_with("application/json"));
    let body = match reply.body {
        FileBody::Bytes(b) => b,
        FileBody::Stream { reader, len } => {
            let mut v = Vec::new();
            let _ = reader
                .take(len.min(MAX_BODY as u64 * 64))
                .read_to_end(&mut v);
            v
        }
    };
    Resp {
        status: reply.status,
        content_type: if json {
            "application/json"
        } else {
            "application/octet-stream"
        },
        body,
        no_store: true,
        stream: false,
    }
}

impl FileJob {
    pub fn call(&self, input: FileInput<'_>) -> Result<FileReply, Resp> {
        let out = self
            .agent
            .files(&self.rec, &self.method, &self.path, &self.query, input);
        let status = out.as_ref().map(|r| r.status).unwrap_or(502);
        if let Some(a) = &self.action {
            let _ = self.tx.send(ActivityEntry {
                ts_ms: unix_ms(),
                actor: self.actor.clone(),
                action: a.clone(),
                box_name: self.rec.spec.name.to_string(),
                risk: None,
                outcome: if status < 300 {
                    "ok".into()
                } else {
                    format!("not done ({status})")
                },
            });
        }
        out.map(|r| with_source(r, self.simulated))
            .map_err(|e| App::agent_error(&e))
    }
}

/// A JSON object answer carries where it came from, `live` or `simulated`, so the file browser never shows a demo folder as
/// a box's disk (G7 X3). Anything that is not a small JSON object (a download, a stream, an error) is passed through.
fn with_source(mut reply: FileReply, simulated: bool) -> FileReply {
    const LIMIT: usize = 4 * 1024 * 1024;
    // The file service's JSON answers carry no content type of their own; a download names its type.
    let json = reply
        .header("content-type")
        .map(|t| t.starts_with("application/json"))
        .unwrap_or(true);
    if !json || reply.status >= 300 {
        return reply;
    }
    if let FileBody::Bytes(b) = &reply.body {
        if b.len() <= LIMIT {
            if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(b) {
                if let Some(o) = v.as_object_mut() {
                    o.insert(
                        "source".into(),
                        serde_json::json!(if simulated { "simulated" } else { "live" }),
                    );
                    if let Ok(bytes) = serde_json::to_vec(&v) {
                        reply.body = FileBody::Bytes(bytes);
                    }
                }
            }
        }
    }
    reply
}

/// Run a job against a live `tiny_http` request: stream the body in, stream the answer out.
pub fn run(job: FileJob, mut request: tiny_http::Request) {
    use std::io::Read;
    let head_only = request.method().as_str() == "HEAD";
    let outcome = if FilesService::wants_stream_body(&job.method, &job.path) {
        match request.body_length() {
            Some(len) => {
                let len = len as u64;
                job.call(FileInput::Stream {
                    reader: request.as_reader(),
                    len,
                })
            }
            None => Err(Resp::error(
                411,
                "length_required",
                "an upload needs a Content-Length",
            )),
        }
    } else {
        let mut body = Vec::new();
        let _ = request
            .as_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut body);
        if body.len() > MAX_BODY {
            Err(Resp::error(413, "too_large", "request body too large"))
        } else if body.is_empty() {
            job.call(FileInput::None)
        } else {
            job.call(FileInput::Bytes(&body))
        }
    };
    let reply = match outcome {
        Ok(r) => r,
        Err(r) => FileReply {
            status: r.status,
            headers: vec![("Content-Type".into(), r.content_type.into())],
            body: FileBody::Bytes(r.body),
        },
    };
    respond(request, reply, head_only);
}

fn header_map(headers: &[(String, String)]) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect()
}

fn decorate<R: Read>(
    mut r: tiny_http::Response<R>,
    h: &HashMap<String, String>,
) -> tiny_http::Response<R> {
    let mut add = |k: &str, v: &str| {
        if let Ok(hd) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            r.add_header(hd);
        }
    };
    let inline = h
        .get("content-disposition")
        .is_some_and(|d| d.starts_with("inline"));
    let json = h
        .get("content-type")
        .is_some_and(|t| t.starts_with("application/json"));
    for k in [
        "content-type",
        "content-disposition",
        "x-ozbox-size",
        "x-ozbox-skipped",
    ] {
        if let Some(v) = h.get(k) {
            add(k, v);
        }
    }
    add("X-Content-Type-Options", "nosniff");
    add("Referrer-Policy", "no-referrer");
    add("Cross-Origin-Resource-Policy", "same-origin");
    add("Cache-Control", "no-store");
    if inline {
        // An image or PDF shown in this dashboard's own preview frame, and nowhere else.
        add("X-Frame-Options", "SAMEORIGIN");
        add("Content-Security-Policy", "frame-ancestors 'self'");
    } else if json {
        add("X-Frame-Options", "DENY");
        add(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        );
    } else {
        add("X-Frame-Options", "DENY");
        add(
            "Content-Security-Policy",
            "default-src 'none'; sandbox; frame-ancestors 'none'",
        );
    }
    r
}

fn respond(request: tiny_http::Request, reply: FileReply, head_only: bool) {
    let h = header_map(&reply.headers);
    let status = tiny_http::StatusCode(reply.status);
    match reply.body {
        FileBody::Bytes(b) => {
            let b = if head_only { Vec::new() } else { b };
            let _ = request.respond(decorate(
                tiny_http::Response::from_data(b).with_status_code(status),
                &h,
            ));
        }
        FileBody::Stream { reader, len } => {
            let reader: Box<dyn Read + Send> = if head_only {
                Box::new(std::io::empty())
            } else {
                reader
            };
            let size = if head_only { 0 } else { len as usize };
            let resp = tiny_http::Response::new(status, Vec::new(), reader, Some(size), None);
            let _ = request.respond(decorate(resp, &h));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text(r: &FileReply) -> serde_json::Value {
        match &r.body {
            FileBody::Bytes(b) => serde_json::from_slice(b).unwrap(),
            FileBody::Stream { .. } => panic!("a stream"),
        }
    }

    #[test]
    fn a_json_answer_says_where_it_came_from() {
        let demo = with_source(FileReply::json(200, &json!({ "roots": [] })), true);
        assert_eq!(text(&demo)["source"], "simulated");
        assert_eq!(text(&demo)["roots"], json!([]));
        let real = with_source(FileReply::json(200, &json!({ "entries": [1] })), false);
        assert_eq!(text(&real)["source"], "live");
        assert_eq!(text(&real)["entries"], json!([1]));
    }

    #[test]
    fn an_error_a_list_and_a_download_are_passed_through_untouched() {
        let err = with_source(FileReply::error(403, "secret_blocked", "no"), true);
        assert!(text(&err).get("source").is_none());
        // a JSON array is not an object: nothing to add to
        let arr = with_source(FileReply::json(200, &json!([1, 2])), true);
        assert_eq!(text(&arr), json!([1, 2]));
        // a download names its type and is never rewritten
        let dl = FileReply {
            status: 200,
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            body: FileBody::Bytes(b"{\"a\":1}".to_vec()),
        };
        let out = with_source(dl, true);
        assert_eq!(text(&out), json!({ "a": 1 }));
    }
}
