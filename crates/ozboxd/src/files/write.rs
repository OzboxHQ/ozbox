//! The changes: save a text file, upload, make a folder, rename or move, delete to the trash, restore, empty the trash.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use super::jail::{self, blocked, valid_name, Op, Refusal, Resolved, STATE_DIR};
use super::tokens::random_hex;
use super::{
    json_body, lock, mtime_ms, sha256_hex, Fail, FilesService, Input, Reply, MAX_WRITE, R,
};
use crate::timeutil::day_stamp;

const DAY_MS: u64 = 86_400_000;

fn temp_name(prefix: &str) -> String {
    format!(".ozbox-{prefix}-{}.part", random_hex(6))
}

/// Removes its file unless told to keep it, so a failed or abandoned transfer leaves nothing behind.
struct TempFile {
    path: PathBuf,
    keep: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn create_new(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o644);
    }
    o.open(path)
}

#[derive(Deserialize)]
struct MkdirBody {
    path: String,
}

#[derive(Deserialize)]
struct RenameBody {
    from: String,
    to: String,
}

#[derive(Deserialize)]
struct DeleteBody {
    paths: Vec<String>,
}

#[derive(Deserialize)]
struct RestoreBody {
    id: String,
    to: Option<String>,
}

#[derive(Deserialize, Default)]
struct EmptyBody {
    ids: Option<Vec<String>>,
}

#[derive(serde::Serialize, Deserialize)]
struct TrashMeta {
    original: String,
    name: String,
    kind: String,
    size: u64,
    deleted_ms: u64,
}

impl FilesService {
    fn refused(&self, action: &str, path: &str, f: &Fail) {
        // The path is what the caller typed, trimmed to something loggable; a refusal is evidence, not a secret.
        let shown: String = path.chars().filter(|c| !c.is_control()).take(200).collect();
        self.audit(
            action,
            Some(shown),
            None,
            None,
            &format!("refused:{}", f.code),
        );
    }

    pub(super) fn write_text(&self, q: &BTreeMap<String, String>, input: Input<'_>) -> R<Reply> {
        let path = Self::path_arg(q, "path")?;
        let res = self.write_text_inner(q, &path, input);
        if let Err(f) = &res {
            self.refused("write", &path, f);
        }
        res
    }

    fn write_text_inner(
        &self,
        q: &BTreeMap<String, String>,
        path: &str,
        input: Input<'_>,
    ) -> R<Reply> {
        let Input::Stream { reader, len } = input else {
            return Err(Fail::new(400, "bad_request", "A body is required."));
        };
        if len > MAX_WRITE {
            return Err(Fail::new(
                413,
                "too_large",
                "Only files up to 1 MiB can be edited here.",
            ));
        }
        let if_match = q
            .get("if_match")
            .ok_or_else(|| {
                Fail::new(
                    400,
                    "if_match_required",
                    "if_match is required: the hash you opened, or `none` for a new file.",
                )
            })?
            .clone();
        let r = self.jail.resolve(path, Op::Write, true)?;
        let mut body = Vec::new();
        reader.take(len).read_to_end(&mut body)?;
        if body.len() as u64 != len {
            return Err(Fail::new(400, "incomplete", "The upload ended early."));
        }
        if body.contains(&0) || std::str::from_utf8(&body).is_err() {
            return Err(Fail::new(422, "not_text", "Only text can be saved here."));
        }
        let name = r
            .rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !valid_name(&name) {
            return Err(Refusal::BadPath.into());
        }
        let _one = lock(&self.change_lock);
        let existing = std::fs::symlink_metadata(&r.real).ok();
        match (&existing, if_match.as_str()) {
            (None, "none") => {}
            (None, _) => {
                return Err(Fail::new(
                    409,
                    "stale",
                    "The file is gone; it was removed after you opened it.",
                ))
            }
            (Some(_), "none") => {
                return Err(Fail::new(
                    409,
                    "exists",
                    "A file with that name already exists.",
                ))
            }
            (Some(md), want) => {
                if !md.is_file() {
                    return Err(Refusal::NotRegular.into());
                }
                if md.len() > MAX_WRITE {
                    return Err(Fail::new(
                        422,
                        "too_large",
                        "Only files up to 1 MiB can be edited here.",
                    ));
                }
                let current = std::fs::read(&r.real)?;
                if !jail::looks_like_text(&current) {
                    return Err(Fail::new(
                        422,
                        "not_text",
                        "Only text files can be edited here.",
                    ));
                }
                let hash = sha256_hex(&current);
                if hash != want {
                    return Err(
                        Fail::new(409, "stale", "The file changed after you opened it.")
                            .with(json!({ "current_hash": hash })),
                    );
                }
            }
        }
        let dir = r.real.parent().ok_or(Refusal::BadPath)?;
        let tmp_path = dir.join(temp_name("write"));
        let mut tmp = TempFile {
            path: tmp_path.clone(),
            keep: false,
        };
        {
            let mut f = create_new(&tmp_path)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        if let Some(md) = &existing {
            let _ = std::fs::set_permissions(&tmp_path, md.permissions());
        }
        std::fs::rename(&tmp_path, &r.real)?;
        tmp.keep = true;
        let md = std::fs::metadata(&r.real)?;
        self.audit(
            "write",
            Some(self.jail.audit_name(&r)),
            None,
            Some(len),
            "ok",
        );
        Ok(Reply::json(
            200,
            &json!({ "path": r.shown.display().to_string(), "size": len, "hash": sha256_hex(&body), "modified_ms": mtime_ms(&md) }),
        ))
    }

    pub(super) fn upload(&self, q: &BTreeMap<String, String>, input: Input<'_>) -> R<Reply> {
        let dir_arg = Self::path_arg(q, "path")?;
        let name = Self::path_arg(q, "name")?;
        let res = self.upload_inner(q, &dir_arg, &name, input);
        if let Err(f) = &res {
            self.refused(
                "upload",
                &format!("{}/{}", dir_arg.trim_end_matches('/'), name),
                f,
            );
        }
        res
    }

    fn upload_inner(
        &self,
        q: &BTreeMap<String, String>,
        dir_arg: &str,
        name: &str,
        input: Input<'_>,
    ) -> R<Reply> {
        let Input::Stream { reader, len } = input else {
            return Err(Fail::new(
                411,
                "length_required",
                "An upload needs a Content-Length.",
            ));
        };
        if !valid_name(name) {
            return Err(Fail::new(400, "bad_name", "That is not a valid file name."));
        }
        if len > self.cfg.max_upload {
            return Err(Fail::new(
                413,
                "too_large",
                "That file is larger than this box accepts.",
            )
            .with(json!({ "max": self.cfg.max_upload })));
        }
        let dir = self.jail.resolve(dir_arg, Op::Write, true)?;
        if !std::fs::metadata(&dir.real)?.is_dir() {
            return Err(Fail::new(422, "not_a_directory", "That is not a folder."));
        }
        let target = self.jail.resolve(
            &format!(
                "{}/{}",
                dir.shown.display().to_string().trim_end_matches('/'),
                name
            ),
            Op::Write,
            false,
        )?;
        let overwrite = matches!(q.get("overwrite").map(String::as_str), Some("1" | "true"));
        if !overwrite && std::fs::symlink_metadata(&target.real).is_ok() {
            return Err(Fail::new(
                409,
                "exists",
                "A file with that name already exists.",
            ));
        }
        let tmp_path = dir.real.join(temp_name("upload"));
        let tmp = TempFile {
            path: tmp_path.clone(),
            keep: false,
        };
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        {
            let mut f = create_new(&tmp_path)?;
            let mut left = len;
            let mut buf = vec![0u8; 64 * 1024];
            while left > 0 {
                let want = buf.len().min(usize::try_from(left).unwrap_or(buf.len()));
                let n = reader.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(Fail::new(400, "incomplete", "The upload ended early."));
                }
                ctx.update(&buf[..n]);
                f.write_all(&buf[..n])?;
                left -= n as u64;
            }
            f.sync_all()?;
        }
        let _one = lock(&self.change_lock);
        if !overwrite && std::fs::symlink_metadata(&target.real).is_ok() {
            return Err(Fail::new(
                409,
                "exists",
                "A file with that name already exists.",
            ));
        }
        if let Ok(md) = std::fs::symlink_metadata(&target.real) {
            if !md.is_file() {
                return Err(Fail::new(
                    409,
                    "exists",
                    "A folder with that name already exists.",
                ));
            }
        }
        std::fs::rename(&tmp_path, &target.real)?;
        let mut tmp = tmp;
        tmp.keep = true;
        self.audit(
            "upload",
            Some(self.jail.audit_name(&target)),
            None,
            Some(len),
            "ok",
        );
        Ok(Reply::json(
            201,
            &json!({ "path": target.shown.display().to_string(), "size": len,
                     "hash": super::tokens::hex(ctx.finish().as_ref()) }),
        ))
    }

    pub(super) fn mkdir(&self, input: &Input<'_>) -> R<Reply> {
        let b: MkdirBody = json_body(input)?;
        let res = (|| {
            let r = self.jail.resolve(&b.path, Op::Write, false)?;
            let name = r
                .rel
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !valid_name(&name) {
                return Err(Fail::new(
                    400,
                    "bad_name",
                    "That is not a valid folder name.",
                ));
            }
            let _one = lock(&self.change_lock);
            std::fs::create_dir(&r.real)?;
            self.audit("mkdir", Some(self.jail.audit_name(&r)), None, None, "ok");
            Ok(Reply::json(
                201,
                &json!({ "path": r.shown.display().to_string() }),
            ))
        })();
        if let Err(f) = &res {
            self.refused("mkdir", &b.path, f);
        }
        res
    }

    fn is_root(&self, r: &Resolved) -> bool {
        r.rel.as_os_str().is_empty()
    }

    pub(super) fn rename(&self, input: &Input<'_>) -> R<Reply> {
        let b: RenameBody = json_body(input)?;
        let res = (|| {
            let from = self.jail.resolve(&b.from, Op::Write, false)?;
            let to = self.jail.resolve(&b.to, Op::Write, false)?;
            // The source's own name must not be a secret either (moving `.env` to `notes.txt` would unhide it).
            if let Some(r) = blocked(&from.rel, Op::Read) {
                return Err(r.into());
            }
            if self.is_root(&from) || self.is_root(&to) {
                return Err(Fail::new(
                    400,
                    "bad_path",
                    "A shared folder itself cannot be moved.",
                ));
            }
            let name = to
                .rel
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !valid_name(&name) {
                return Err(Fail::new(400, "bad_name", "That is not a valid name."));
            }
            if to.root != from.root {
                return Err(Fail::new(
                    422,
                    "cross_device",
                    "That cannot be moved between these disks.",
                ));
            }
            if to.real.starts_with(&from.real) {
                return Err(Fail::new(
                    400,
                    "into_itself",
                    "A folder cannot be moved into itself.",
                ));
            }
            let _one = lock(&self.change_lock);
            std::fs::symlink_metadata(&from.real)?;
            if std::fs::symlink_metadata(&to.real).is_ok() {
                return Err(Fail::new(
                    409,
                    "exists",
                    "Something with that name already exists there.",
                ));
            }
            if !to.real.parent().is_some_and(Path::is_dir) {
                return Err(Fail::new(
                    404,
                    "not_found",
                    "The destination folder does not exist.",
                ));
            }
            std::fs::rename(&from.real, &to.real)?;
            self.audit(
                "rename",
                Some(self.jail.audit_name(&from)),
                Some(self.jail.audit_name(&to)),
                None,
                "ok",
            );
            Ok(Reply::json(
                200,
                &json!({ "path": to.shown.display().to_string() }),
            ))
        })();
        if let Err(f) = &res {
            self.refused("rename", &b.from, f);
        }
        res
    }

    // ---- trash -----------------------------------------------------------------------------------------------

    fn trash_dir(&self, root: usize) -> PathBuf {
        self.jail.root_canon(root).join(STATE_DIR).join("trash")
    }

    fn tree_size(path: &Path) -> u64 {
        let mut total = 0u64;
        let mut stack = vec![path.to_path_buf()];
        let mut seen = 0;
        while let Some(p) = stack.pop() {
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if md.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&p) {
                    for e in rd.flatten() {
                        seen += 1;
                        if seen > 20_000 {
                            return total;
                        }
                        stack.push(e.path());
                    }
                }
            } else {
                total += md.len();
            }
        }
        total
    }

    pub(super) fn delete(&self, input: &Input<'_>) -> R<Reply> {
        let b: DeleteBody = json_body(input)?;
        if b.paths.is_empty() || b.paths.len() > 500 {
            return Err(Fail::new(
                400,
                "bad_request",
                "Choose between 1 and 500 items.",
            ));
        }
        let _one = lock(&self.change_lock);
        self.sweep_trash();
        let now = self.clock.now_ms();
        let (mut done, mut failed) = (Vec::new(), Vec::new());
        for p in &b.paths {
            let res: R<Value> = (|| {
                let r = self.jail.resolve(p, Op::Remove, false)?;
                if self.is_root(&r) {
                    return Err(Fail::new(
                        400,
                        "bad_path",
                        "A shared folder itself cannot be deleted.",
                    ));
                }
                let md = std::fs::symlink_metadata(&r.real)?;
                let id = random_hex(6);
                let day_dir = self.trash_dir(r.root).join(day_stamp(now)).join(&id);
                std::fs::create_dir_all(&day_dir)?;
                let name = r
                    .rel
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let size = if md.is_dir() {
                    Self::tree_size(&r.real)
                } else {
                    md.len()
                };
                std::fs::rename(&r.real, day_dir.join("item")).inspect_err(|_| {
                    let _ = std::fs::remove_dir(&day_dir);
                })?;
                let meta = TrashMeta {
                    original: r.shown.display().to_string(),
                    name,
                    kind: if md.is_dir() { "dir" } else { "file" }.into(),
                    size,
                    deleted_ms: now,
                };
                std::fs::write(
                    day_dir.join("meta.json"),
                    serde_json::to_vec(&meta).unwrap_or_default(),
                )?;
                self.audit(
                    "delete",
                    Some(self.jail.audit_name(&r)),
                    None,
                    Some(size),
                    "ok",
                );
                Ok(json!({ "id": id, "original": meta.original }))
            })();
            match res {
                Ok(v) => done.push(v),
                Err(f) => {
                    self.refused("delete", p, &f);
                    failed.push(json!({ "path": p, "code": f.code, "message": f.message }));
                }
            }
        }
        if done.is_empty() {
            // Nothing moved: say why in the usual shape, and keep the per-item detail.
            let first = failed.first();
            let code = first
                .and_then(|f| f["code"].as_str())
                .unwrap_or("io")
                .to_string();
            let message = first
                .and_then(|f| f["message"].as_str())
                .unwrap_or("")
                .to_string();
            return Err(
                Fail::new(422, &code, &message).with(json!({ "deleted": done, "failed": failed }))
            );
        }
        Ok(Reply::json(
            200,
            &json!({ "deleted": done, "failed": failed, "retention_days": self.cfg.trash_days }),
        ))
    }

    /// Every trashed item across the roots: `(root, date dir, id dir, meta)`.
    fn trash_items(&self) -> Vec<(usize, PathBuf, TrashMeta)> {
        let mut out = Vec::new();
        for root in 0..self.jail.roots().len() {
            let Ok(days) = std::fs::read_dir(self.trash_dir(root)) else {
                continue;
            };
            for day in days.flatten() {
                let Ok(ids) = std::fs::read_dir(day.path()) else {
                    continue;
                };
                for id in ids.flatten() {
                    let dir = id.path();
                    let meta = std::fs::read(dir.join("meta.json"))
                        .ok()
                        .and_then(|b| serde_json::from_slice::<TrashMeta>(&b).ok());
                    if let Some(m) = meta {
                        out.push((root, dir, m));
                    }
                }
            }
        }
        out
    }

    fn sweep_trash(&self) {
        let now = self.clock.now_ms();
        let keep_ms = self.cfg.trash_days * DAY_MS;
        for (_, dir, m) in self.trash_items() {
            if now.saturating_sub(m.deleted_ms) > keep_ms {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
        for root in 0..self.jail.roots().len() {
            if let Ok(days) = std::fs::read_dir(self.trash_dir(root)) {
                for d in days.flatten() {
                    let _ = std::fs::remove_dir(d.path()); // only succeeds when empty
                }
            }
        }
    }

    pub(super) fn trash_list(&self) -> R<Reply> {
        let _one = lock(&self.change_lock);
        self.sweep_trash();
        let keep_ms = self.cfg.trash_days * DAY_MS;
        let mut items: Vec<Value> = self
            .trash_items()
            .into_iter()
            .map(|(_, dir, m)| {
                let id = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                json!({ "id": id, "original": m.original, "name": m.name, "kind": m.kind, "size": m.size,
                        "deleted_ms": m.deleted_ms, "expires_ms": m.deleted_ms + keep_ms })
            })
            .collect();
        items.sort_by_key(|v| std::cmp::Reverse(v["deleted_ms"].as_u64().unwrap_or(0)));
        Ok(Reply::json(
            200,
            &json!({ "items": items, "retention_days": self.cfg.trash_days }),
        ))
    }

    fn find_trash(&self, id: &str) -> R<(usize, PathBuf, TrashMeta)> {
        if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Refusal::NotFound.into());
        }
        self.trash_items()
            .into_iter()
            .find(|(_, d, _)| d.file_name().is_some_and(|n| n == id))
            .ok_or_else(|| Refusal::NotFound.into())
    }

    pub(super) fn trash_restore(&self, input: &Input<'_>) -> R<Reply> {
        let b: RestoreBody = json_body(input)?;
        let _one = lock(&self.change_lock);
        let (root, dir, meta) = self.find_trash(&b.id)?;
        let dest_arg = b.to.clone().unwrap_or_else(|| meta.original.clone());
        let res = (|| {
            let to = self.jail.resolve(&dest_arg, Op::Write, false)?;
            if to.root != root {
                return Err(Fail::new(
                    422,
                    "cross_device",
                    "That cannot be restored to another disk.",
                ));
            }
            if std::fs::symlink_metadata(&to.real).is_ok() {
                return Err(
                    Fail::new(409, "exists", "Something with that name is already there.")
                        .with(json!({ "original": meta.original })),
                );
            }
            let parent = to.real.parent().ok_or(Refusal::BadPath)?;
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(dir.join("item"), &to.real)?;
            let _ = std::fs::remove_dir_all(&dir);
            self.audit(
                "restore",
                Some(self.jail.audit_name(&to)),
                None,
                Some(meta.size),
                "ok",
            );
            Ok(Reply::json(
                200,
                &json!({ "path": to.shown.display().to_string() }),
            ))
        })();
        if let Err(f) = &res {
            self.refused("restore", &dest_arg, f);
        }
        res
    }

    pub(super) fn trash_empty(&self, input: &Input<'_>) -> R<Reply> {
        let b: EmptyBody = match input {
            Input::Bytes(x) if !x.is_empty() => json_body(input)?,
            _ => EmptyBody::default(),
        };
        let _one = lock(&self.change_lock);
        let mut removed = 0u64;
        for (_, dir, _) in self.trash_items() {
            let id = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if b.ids.as_ref().is_some_and(|ids| !ids.contains(&id)) {
                continue;
            }
            if std::fs::remove_dir_all(&dir).is_ok() {
                removed += 1;
            }
        }
        self.sweep_trash();
        let mut ev = super::AuditEvent {
            ts_ms: self.clock.now_ms(),
            action: "trash_empty".into(),
            path: None,
            to: None,
            size: None,
            count: Some(removed),
            token: None,
            outcome: "ok".into(),
        };
        ev.count = Some(removed);
        self.audit_full(ev);
        Ok(Reply::json(200, &json!({ "removed": removed })))
    }
}
