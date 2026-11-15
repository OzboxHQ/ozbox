//! Expiring download links and bundles. A link names files by registry id; the files are resolved and checked again at
//! download time, so a link never outlives a rule (a file that became a secret name is refused).

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::json;

use super::jail::{self, blocked, Op, Refusal, STATE_DIR};
use super::tokens::{random_hex, TokenRec};
use super::zipw::ZipWriter;
use super::{json_body, lock, AuditEvent, Body, Fail, FilesService, Input, Reply, R};

#[derive(Deserialize)]
struct CreateBody {
    paths: Vec<String>,
    ttl_s: Option<u64>,
    inline: Option<bool>,
}

/// Deletes the bundle file once it has been streamed (or abandoned).
struct TempReader {
    file: std::fs::File,
    path: PathBuf,
}

impl Read for TempReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Drop for TempReader {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn disposition(name: &str, inline: bool) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && !matches!(c, '"' | '\\' | '/' | ';') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut enc = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            enc.push(b as char);
        } else {
            enc.push_str(&format!("%{b:02X}"));
        }
    }
    format!(
        "{}; filename=\"{ascii}\"; filename*=UTF-8''{enc}",
        if inline { "inline" } else { "attachment" }
    )
}

struct Item {
    real: PathBuf,
    /// Name inside a bundle.
    name: String,
    dir: bool,
    size: u64,
}

impl FilesService {
    /// Walk the chosen paths into bundle items. Secret files inside a chosen folder are skipped (and counted); a secret
    /// file chosen by name is refused. Links are never followed.
    fn bundle_items(&self, paths: &[String]) -> R<(Vec<Item>, u64, u64)> {
        let (mut items, mut total, mut skipped) = (Vec::new(), 0u64, 0u64);
        for p in paths {
            let r = self.jail.resolve(p, Op::Read, true)?;
            let top = r
                .rel
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "files".into());
            let mut stack = vec![(r.real.clone(), r.rel.clone(), top)];
            while let Some((real, rel, name)) = stack.pop() {
                let md = std::fs::symlink_metadata(&real)?;
                if md.file_type().is_symlink() {
                    skipped += 1;
                    continue;
                }
                if md.is_dir() {
                    items.push(Item {
                        real: real.clone(),
                        name: name.clone(),
                        dir: true,
                        size: 0,
                    });
                    for e in std::fs::read_dir(&real)?.flatten() {
                        let n = e.file_name().to_string_lossy().into_owned();
                        let child_rel = rel.join(&n);
                        if n == STATE_DIR || blocked(&child_rel, Op::Read).is_some() {
                            skipped += 1;
                            continue;
                        }
                        stack.push((e.path(), child_rel, format!("{name}/{n}")));
                    }
                } else if md.is_file() {
                    total += md.len();
                    items.push(Item {
                        real,
                        name,
                        dir: false,
                        size: md.len(),
                    });
                } else {
                    skipped += 1;
                }
                if total > self.cfg.max_zip || items.len() > self.cfg.max_zip_files {
                    return Err(Fail::new(
                        413,
                        "too_large",
                        "That selection is too large to bundle.",
                    )
                    .with(json!({ "max": self.cfg.max_zip })));
                }
            }
        }
        Ok((items, total, skipped))
    }

    pub(super) fn token_create(&self, input: &Input<'_>) -> R<Reply> {
        let b: CreateBody = json_body(input)?;
        if b.paths.is_empty() || b.paths.len() > 500 {
            return Err(Fail::new(
                400,
                "bad_request",
                "Choose between 1 and 500 items.",
            ));
        }
        let ttl = b.ttl_s.unwrap_or(15 * 60);
        let inline = b.inline.unwrap_or(false);
        // Resolve now so a bad or secret path is refused when the link is made, not when it is used.
        let mut single_file = None;
        let mut label = String::new();
        for (i, p) in b.paths.iter().enumerate() {
            let r = self.jail.resolve(p, Op::Read, true).inspect_err(|_| {
                self.audit(
                    "token_create",
                    Some(p.chars().take(200).collect()),
                    None,
                    None,
                    "refused",
                );
            })?;
            let md = std::fs::metadata(&r.real)?;
            if i == 0 {
                label = r
                    .rel
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if md.is_file() && b.paths.len() == 1 {
                    single_file = Some(label.clone());
                }
            }
        }
        let kind = if single_file.is_some() { "file" } else { "zip" };
        if kind == "zip" {
            let (_, total, _) = self.bundle_items(&b.paths)?;
            if b.paths.len() > 1 {
                label = format!("{label} +{}", b.paths.len() - 1);
            }
            let _ = total;
        }
        if inline {
            let ok = single_file
                .as_deref()
                .is_some_and(|n| jail::inline_safe(jail::mime_for(n)));
            if !ok {
                return Err(Fail::new(
                    422,
                    "not_inline",
                    "Only images and PDFs can be shown in the browser.",
                ));
            }
        }
        let (rec, token) = lock(&self.tokens)
            .create(
                self.clock.now_ms(),
                ttl,
                kind,
                b.paths.clone(),
                inline,
                label,
            )
            .map_err(|why| match why {
                "ttl" => Fail::new(
                    400,
                    "bad_ttl",
                    "A link lasts between 10 seconds and 24 hours.",
                ),
                _ => Fail::new(
                    429,
                    "too_many_tokens",
                    "Too many active links. Revoke one first.",
                ),
            })?;
        self.audit_full(AuditEvent {
            ts_ms: self.clock.now_ms(),
            action: "token_create".into(),
            path: None,
            to: None,
            size: None,
            count: Some(b.paths.len() as u64),
            token: Some(rec.id.clone()),
            outcome: "ok".into(),
        });
        Ok(Reply::json(
            201,
            &json!({ "id": rec.id, "token": token, "expires_ms": rec.expires_ms, "kind": rec.kind,
                                      "label": rec.label, "inline": rec.inline }),
        ))
    }

    pub(super) fn tokens_list(&self) -> R<Reply> {
        let list: Vec<TokenRec> = lock(&self.tokens).list(self.clock.now_ms());
        // Paths stay out of the list: a label and an id are enough to recognise and revoke a link.
        let out: Vec<_> = list
            .iter()
            .map(|t| json!({ "id": t.id, "label": t.label, "kind": t.kind, "inline": t.inline,
                             "created_ms": t.created_ms, "expires_ms": t.expires_ms, "count": t.paths.len() }))
            .collect();
        Ok(Reply::json(200, &json!({ "tokens": out })))
    }

    pub(super) fn token_revoke(&self, id: &str) -> R<Reply> {
        if !lock(&self.tokens).revoke(id) {
            return Err(Refusal::NotFound.into());
        }
        self.audit_full(AuditEvent {
            ts_ms: self.clock.now_ms(),
            action: "token_revoke".into(),
            path: None,
            to: None,
            size: None,
            count: None,
            token: Some(id.chars().take(24).collect()),
            outcome: "ok".into(),
        });
        Ok(Reply::json(200, &json!({ "revoked": id })))
    }

    pub(super) fn download(&self, q: &std::collections::BTreeMap<String, String>) -> R<Reply> {
        let token = Self::path_arg(q, "token")?;
        // One answer for every kind of bad token: expired, revoked, forged and unknown look the same.
        let gone = || Fail::new(404, "link_invalid", "This link has expired or was revoked.");
        let rec = lock(&self.tokens)
            .verify(&token, self.clock.now_ms())
            .ok_or_else(gone)?;
        let mut ev = AuditEvent {
            ts_ms: self.clock.now_ms(),
            action: "download".into(),
            path: None,
            to: None,
            size: None,
            count: None,
            token: Some(rec.id.clone()),
            outcome: "ok".into(),
        };
        let res = if rec.kind == "file" {
            self.download_file(&rec, &mut ev)
        } else {
            self.download_zip(&rec, &mut ev)
        };
        if let Err(f) = &res {
            ev.outcome = format!("refused:{}", f.code);
        }
        self.audit_full(ev);
        res
    }

    fn download_file(&self, rec: &TokenRec, ev: &mut AuditEvent) -> R<Reply> {
        let path = rec.paths.first().ok_or(Refusal::NotFound)?;
        let (r, f, md) = self.open_regular(path, Op::Read)?;
        ev.path = Some(self.jail.audit_name(&r));
        ev.size = Some(md.len());
        let name = r
            .rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mime = jail::mime_for(&name);
        let inline = rec.inline && jail::inline_safe(mime);
        Ok(Reply {
            status: 200,
            headers: vec![
                (
                    "Content-Type".into(),
                    if inline {
                        mime
                    } else {
                        "application/octet-stream"
                    }
                    .into(),
                ),
                ("Content-Disposition".into(), disposition(&name, inline)),
                ("X-Content-Type-Options".into(), "nosniff".into()),
            ],
            body: Body::Stream {
                reader: Box::new(f),
                len: md.len(),
            },
        })
    }

    fn download_zip(&self, rec: &TokenRec, ev: &mut AuditEvent) -> R<Reply> {
        let (items, total, skipped) = self.bundle_items(&rec.paths)?;
        ev.count = Some(items.iter().filter(|i| !i.dir).count() as u64);
        ev.size = Some(total);
        let tmp_dir = self.jail.root_canon(0).join(STATE_DIR).join("tmp");
        std::fs::create_dir_all(&tmp_dir)?;
        let path = tmp_dir.join(format!("bundle-{}.zip", random_hex(6)));
        let build = || -> std::io::Result<()> {
            let out = std::io::BufWriter::new(std::fs::File::create(&path)?);
            let mut z = ZipWriter::new(out, self.clock.now_ms() / 1000);
            for it in &items {
                if it.dir {
                    z.add_dir(&it.name)?;
                } else {
                    let mut f = std::fs::File::open(&it.real)?;
                    z.add_file(&it.name, &mut f, it.size.max(1) + 1024 * 1024)?;
                }
            }
            z.finish()?;
            Ok(())
        };
        if let Err(e) = build() {
            let _ = std::fs::remove_file(&path);
            return Err(e.into());
        }
        let file = std::fs::File::open(&path)?;
        let len = file.metadata()?.len();
        let reader = TempReader { file, path };
        let name = format!("{}.zip", rec.label.split(" +").next().unwrap_or("files"));
        Ok(Reply {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "application/zip".into()),
                ("Content-Disposition".into(), disposition(&name, false)),
                ("X-Content-Type-Options".into(), "nosniff".into()),
                ("X-Ozbox-Skipped".into(), skipped.to_string()),
            ],
            body: Body::Stream {
                reader: Box::new(reader),
                len,
            },
        })
    }

    /// Remove bundle files a crash left behind.
    pub fn clean_tmp(&self) {
        let dir: &Path = &self.jail.root_canon(0).join(STATE_DIR).join("tmp");
        let _ = std::fs::remove_dir_all(dir);
    }
}
