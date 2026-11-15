use super::*;
use crate::timeutil::FakeClock;

struct Fx {
    _d: tempfile::TempDir,
    root: PathBuf,
    clock: Arc<FakeClock>,
    svc: FilesService,
}

const T0: u64 = 1_800_000_000_000;

fn fx() -> Fx {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("work");
    std::fs::create_dir_all(root.join("exchange")).unwrap();
    std::fs::write(root.join("exchange/hello.txt"), "hello\nworld\n").unwrap();
    std::fs::write(root.join("notes.md"), "# notes\n").unwrap();
    std::fs::write(root.join(".env"), "SECRET=1").unwrap();
    let clock = Arc::new(FakeClock::new(T0));
    let mut cfg = FilesConfig::new(vec![root.clone()]);
    cfg.max_upload = 1024;
    cfg.max_zip = 4096;
    let svc = FilesService::new(cfg, clock.clone()).unwrap();
    Fx {
        _d: d,
        root,
        clock,
        svc,
    }
}

fn q(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

impl Fx {
    fn p(&self, rel: &str) -> String {
        format!("{}/{rel}", self.root.display())
    }
    fn get(&self, path: &str, pairs: &[(&str, &str)]) -> Reply {
        self.svc
            .call("GET", &format!("/v1/files/{path}"), &q(pairs), Input::None)
    }
    fn post(&self, path: &str, body: Value) -> Reply {
        let b = serde_json::to_vec(&body).unwrap();
        self.svc.call(
            "POST",
            &format!("/v1/files/{path}"),
            &q(&[]),
            Input::Bytes(&b),
        )
    }
    fn put(&self, path: &str, pairs: &[(&str, &str)], data: &[u8]) -> Reply {
        let mut r = data;
        self.svc.call(
            "PUT",
            &format!("/v1/files/{path}"),
            &q(pairs),
            Input::Stream {
                reader: &mut r,
                len: data.len() as u64,
            },
        )
    }
    fn json(r: &Reply) -> Value {
        serde_json::from_slice(r.bytes().unwrap()).unwrap()
    }
    fn names(&self, dir: &str, extra: &[(&str, &str)]) -> Vec<String> {
        let mut a = vec![("path", dir)];
        a.extend_from_slice(extra);
        let v = Fx::json(&self.get("list", &a));
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_string())
            .collect()
    }
    fn body(r: Reply) -> Vec<u8> {
        match r.body {
            Body::Bytes(b) => b,
            Body::Stream { mut reader, .. } => {
                let mut v = Vec::new();
                reader.read_to_end(&mut v).unwrap();
                v
            }
        }
    }
    fn token(&self, paths: &[String], ttl: u64, inline: bool) -> String {
        let r = self.post(
            "tokens",
            json!({ "paths": paths, "ttl_s": ttl, "inline": inline }),
        );
        assert_eq!(r.status, 201, "{:?}", Fx::json(&r));
        Fx::json(&r)["token"].as_str().unwrap().to_string()
    }
}

fn code(r: &Reply) -> String {
    Fx::json(r)["code"].as_str().unwrap_or("").to_string()
}

#[test]
fn listing_sorts_pages_and_hides_dotfiles_until_asked() {
    let f = fx();
    std::fs::write(f.root.join("exchange/b.txt"), "bb").unwrap();
    std::fs::write(f.root.join("exchange/.hidden"), "h").unwrap();
    std::fs::create_dir(f.root.join("exchange/zdir")).unwrap();
    let d = f.p("exchange");
    // Folders first, then by name; dotfiles hidden.
    assert_eq!(f.names(&d, &[]), ["zdir", "b.txt", "hello.txt"]);
    assert_eq!(
        f.names(&d, &[("hidden", "1")]),
        ["zdir", ".hidden", "b.txt", "hello.txt"]
    );
    assert_eq!(
        f.names(&d, &[("sort", "size"), ("order", "desc")]),
        ["zdir", "hello.txt", "b.txt"]
    );
    let page = Fx::json(&f.get("list", &[("path", &d), ("limit", "1"), ("offset", "1")]));
    assert_eq!(page["total"], 3);
    assert_eq!(page["entries"].as_array().unwrap().len(), 1);
    assert_eq!(page["entries"][0]["name"], "b.txt");
    assert_eq!(
        f.get("list", &[("path", &f.p("exchange/hello.txt"))])
            .status,
        422
    );
    assert_eq!(f.get("list", &[("path", "/etc")]).status, 403);
}

#[test]
fn the_state_folder_is_invisible_and_secret_files_are_greyed_not_hidden() {
    let f = fx();
    std::fs::write(f.root.join("server.pem"), "x").unwrap();
    std::fs::write(f.root.join(".env.example"), "KEY=").unwrap();
    let v = Fx::json(&f.get("list", &[("path", &f.p("")), ("hidden", "1")]));
    let names: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(!names.contains(&".ozbox"), "{names:?}");
    let by = |n: &str| {
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == n)
            .cloned()
            .unwrap()
    };
    assert_eq!(by(".env")["blocked"], "secret_blocked");
    assert_eq!(by("server.pem")["blocked"], "secret_blocked");
    assert!(by(".env.example").get("blocked").is_none());
    assert!(by("notes.md").get("blocked").is_none());
    assert_eq!(f.get("list", &[("path", &f.p(".ozbox"))]).status, 403);
}

#[test]
fn every_way_to_read_a_secret_is_refused_with_a_pointer_to_secrets_import() {
    let f = fx();
    let env = f.p(".env");
    for r in [
        f.get("preview", &[("path", &env)]),
        f.get("read", &[("path", &env)]),
        f.get("stat", &[("path", &env)]),
        f.put(
            "upload",
            &[("path", &f.p("")), ("name", ".env.local")],
            b"A=1",
        ),
        f.put("write", &[("path", &env), ("if_match", "none")], b"A=1"),
        f.post("tokens", json!({ "paths": [env.clone()] })),
        f.post("rename", json!({ "from": env, "to": f.p("plain.txt") })),
    ] {
        assert_eq!(r.status, 403);
        assert_eq!(code(&r), "secret_blocked");
        assert!(Fx::json(&r)["message"]
            .as_str()
            .unwrap()
            .contains("ozbox secrets import"));
    }
    assert!(f.root.join(".env").exists());
    assert!(!f.root.join(".env.local").exists());
    // Deleting a leftover secret is allowed; it goes to the trash like anything else.
    assert_eq!(
        f.post("delete", json!({ "paths": [f.p(".env")] })).status,
        200
    );
}

#[cfg(unix)]
#[test]
fn symlinks_never_let_a_request_leave_the_root() {
    use std::os::unix::fs::symlink;
    let f = fx();
    let outside = f.root.parent().unwrap().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("passwd"), "root:x").unwrap();
    symlink(&outside, f.root.join("out")).unwrap();
    symlink(outside.join("passwd"), f.root.join("p")).unwrap();
    for (route, pairs) in [
        ("list", vec![("path", f.p("out"))]),
        ("preview", vec![("path", f.p("p"))]),
        ("read", vec![("path", f.p("out/passwd"))]),
    ] {
        let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = f.get(route, &pairs);
        assert_eq!(code(&r), "symlink_escape", "{route}");
    }
    let r = f.put("upload", &[("path", &f.p("out")), ("name", "x.txt")], b"x");
    assert_eq!(code(&r), "symlink_escape");
    assert!(!outside.join("x.txt").exists());
    assert_eq!(
        code(&f.post("mkdir", json!({ "path": f.p("out/new") }))),
        "symlink_escape"
    );
    assert_eq!(
        code(&f.post(
            "rename",
            json!({ "from": f.p("notes.md"), "to": f.p("out/n.md") })
        )),
        "symlink_escape"
    );
    // The listing shows the link greyed, and a token for it is refused.
    let v = Fx::json(&f.get("list", &[("path", &f.p(""))]));
    let out = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "out")
        .unwrap();
    assert_eq!(out["blocked"], "symlink_escape");
    assert_eq!(f.post("tokens", json!({ "paths": [f.p("p")] })).status, 403);
    // Deleting the link itself is fine, and leaves its target alone.
    assert_eq!(
        f.post("delete", json!({ "paths": [f.p("out")] })).status,
        200
    );
    assert!(outside.join("passwd").exists());
}

#[test]
fn paths_with_dotdot_or_outside_the_root_are_refused() {
    let f = fx();
    for bad in [
        format!("{}/../outside", f.root.display()),
        f.p("exchange/../notes.md"),
        "/etc/passwd".into(),
        "notes.md".into(),
        "/work\0".into(),
    ] {
        let r = f.get("preview", &[("path", &bad)]);
        assert!(matches!(r.status, 400 | 403), "{bad:?} -> {}", r.status);
    }
    assert_eq!(
        f.post("delete", json!({ "paths": [f.p("")] })).status,
        422,
        "the root cannot be deleted"
    );
    assert_eq!(
        f.post("rename", json!({ "from": f.p(""), "to": f.p("x") }))
            .status,
        400
    );
}

#[test]
fn preview_detects_text_images_pdf_and_binary() {
    let f = fx();
    std::fs::write(f.root.join("pic.png"), b"\x89PNG....").unwrap();
    std::fs::write(f.root.join("doc.pdf"), b"%PDF-1.4 xx").unwrap();
    std::fs::write(f.root.join("blob.bin"), [0u8, 1, 2, 3]).unwrap();
    std::fs::write(f.root.join("icon.svg"), "<svg onload=alert(1)/>").unwrap();
    let kind = |n: &str| {
        Fx::json(&f.get("preview", &[("path", &f.p(n))]))["kind"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(kind("notes.md"), "text");
    assert_eq!(kind("pic.png"), "image");
    assert_eq!(kind("doc.pdf"), "pdf");
    assert_eq!(kind("blob.bin"), "binary");
    assert_eq!(
        kind("icon.svg"),
        "text",
        "svg is shown as text, never as an image that could run"
    );
    let v = Fx::json(&f.get("preview", &[("path", &f.p("exchange/hello.txt"))]));
    assert_eq!(v["text"], "hello\nworld\n");
    assert_eq!(v["editable"], true);
    assert_eq!(v["hash"], sha256_hex(b"hello\nworld\n"));
    assert_eq!(f.get("preview", &[("path", &f.p("exchange"))]).status, 422);
    // A text file over the edit limit previews (cut) but is not editable and has no hash.
    std::fs::write(
        f.root.join("big.txt"),
        vec![b'a'; (MAX_WRITE + 10) as usize],
    )
    .unwrap();
    let v = Fx::json(&f.get("preview", &[("path", &f.p("big.txt"))]));
    assert_eq!(
        (
            v["editable"].clone(),
            v["truncated"].clone(),
            v["hash"].clone()
        ),
        (json!(false), json!(true), Value::Null)
    );
    assert_eq!(v["text"].as_str().unwrap().len(), PREVIEW_TEXT_MAX);
}

#[test]
fn read_serves_ranges_and_caps_them() {
    let f = fx();
    let r = f.get(
        "read",
        &[
            ("path", &f.p("exchange/hello.txt")),
            ("offset", "6"),
            ("length", "5"),
        ],
    );
    assert_eq!(r.header("x-ozbox-size"), Some("12"));
    assert_eq!(Fx::body(r), b"world");
    assert_eq!(
        f.get(
            "read",
            &[("path", &f.p("exchange/hello.txt")), ("offset", "99")]
        )
        .status,
        416
    );
    assert_eq!(f.get("read", &[("path", &f.p("exchange"))]).status, 422);
}

#[test]
fn a_save_needs_the_hash_you_opened_and_a_stale_one_is_refused() {
    let f = fx();
    let path = f.p("exchange/hello.txt");
    let h0 = sha256_hex(b"hello\nworld\n");
    // no if_match at all
    assert_eq!(
        code(&f.put("write", &[("path", &path)], b"x")),
        "if_match_required"
    );
    // a wrong hash: 409 and the file is untouched; the response carries the current hash for a reload
    let r = f.put("write", &[("path", &path), ("if_match", "deadbeef")], b"x");
    assert_eq!((r.status, code(&r)), (409, "stale".into()));
    assert_eq!(Fx::json(&r)["current_hash"], h0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello\nworld\n");
    // the right hash saves, atomically, and returns the new hash
    let r = f.put(
        "write",
        &[("path", &path), ("if_match", &h0)],
        b"hello\nthere\n",
    );
    assert_eq!(r.status, 200);
    assert_eq!(Fx::json(&r)["hash"], sha256_hex(b"hello\nthere\n"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello\nthere\n");
    // the old hash is now stale
    assert_eq!(
        f.put("write", &[("path", &path), ("if_match", &h0)], b"y")
            .status,
        409
    );
    // nothing is left beside it
    assert!(!f
        .names(&f.p("exchange"), &[("hidden", "1")])
        .iter()
        .any(|n| n.contains(".part")));
    // new files use `none`, and `none` never overwrites
    let new = f.p("exchange/new.txt");
    assert_eq!(
        f.put("write", &[("path", &new), ("if_match", "none")], b"n")
            .status,
        200
    );
    assert_eq!(
        f.put("write", &[("path", &new), ("if_match", "none")], b"n")
            .status,
        409
    );
    // binary content and oversize bodies are refused
    assert_eq!(
        code(&f.put(
            "write",
            &[("path", &new), ("if_match", &sha256_hex(b"n"))],
            &[0, 1]
        )),
        "not_text"
    );
    let big = vec![b'a'; (MAX_WRITE + 1) as usize];
    assert_eq!(
        f.put("write", &[("path", &new), ("if_match", "x")], &big)
            .status,
        413
    );
    // a binary existing file cannot be edited even with its true hash
    std::fs::write(f.root.join("b.bin"), [0u8, 1]).unwrap();
    assert_eq!(
        f.put(
            "write",
            &[("path", &f.p("b.bin")), ("if_match", &sha256_hex(&[0, 1]))],
            b"t"
        )
        .status,
        422
    );
    // writing into .git internals is refused
    std::fs::create_dir_all(f.root.join("repo/.git")).unwrap();
    assert_eq!(
        code(&f.put(
            "write",
            &[("path", &f.p("repo/.git/HEAD")), ("if_match", "none")],
            b"x"
        )),
        "git_internal"
    );
}

#[test]
fn uploads_stream_to_a_temp_file_and_land_atomically() {
    let f = fx();
    let dir = f.p("exchange");
    let r = f.put(
        "upload",
        &[("path", &dir), ("name", "data.bin")],
        &[7u8; 700],
    );
    assert_eq!(r.status, 201);
    let v = Fx::json(&r);
    assert_eq!(v["size"], 700);
    assert_eq!(v["hash"], sha256_hex(&[7u8; 700]));
    assert_eq!(
        std::fs::read(f.root.join("exchange/data.bin"))
            .unwrap()
            .len(),
        700
    );
    // exists -> 409 unless overwrite
    assert_eq!(
        code(&f.put("upload", &[("path", &dir), ("name", "data.bin")], b"z")),
        "exists"
    );
    assert_eq!(
        f.put(
            "upload",
            &[("path", &dir), ("name", "data.bin"), ("overwrite", "1")],
            b"z"
        )
        .status,
        201
    );
    assert_eq!(
        std::fs::read(f.root.join("exchange/data.bin")).unwrap(),
        b"z"
    );
    // cap: refused before reading
    let mut never = std::io::empty();
    let r = f.svc.call(
        "PUT",
        "/v1/files/upload",
        &q(&[("path", &dir), ("name", "big")]),
        Input::Stream {
            reader: &mut never,
            len: 5000,
        },
    );
    assert_eq!((r.status, code(&r)), (413, "too_large".into()));
    // a short body leaves no partial file
    let mut short: &[u8] = b"abc";
    let r = f.svc.call(
        "PUT",
        "/v1/files/upload",
        &q(&[("path", &dir), ("name", "cut.txt")]),
        Input::Stream {
            reader: &mut short,
            len: 10,
        },
    );
    assert_eq!(code(&r), "incomplete");
    assert!(!f.root.join("exchange/cut.txt").exists());
    assert!(!f
        .names(&dir, &[("hidden", "1")])
        .iter()
        .any(|n| n.ends_with(".part")));
    // names are validated
    for bad in ["../x", "a/b", "", ".."] {
        assert_eq!(
            code(&f.put("upload", &[("path", &dir), ("name", bad)], b"x")),
            "bad_name",
            "{bad:?}"
        );
    }
    // not a folder / missing
    assert_eq!(
        f.put("upload", &[("path", &f.p("notes.md")), ("name", "x")], b"x")
            .status,
        422
    );
    assert_eq!(
        f.put("upload", &[("path", &f.p("nope")), ("name", "x")], b"x")
            .status,
        404
    );
    // a request without a length is refused
    let r = f.svc.call(
        "PUT",
        "/v1/files/upload",
        &q(&[("path", &dir), ("name", "n")]),
        Input::Bytes(b"x"),
    );
    assert_eq!(r.status, 411);
}

#[test]
fn mkdir_and_rename_stay_inside_and_never_clobber() {
    let f = fx();
    assert_eq!(
        f.post("mkdir", json!({ "path": f.p("exchange/sub") }))
            .status,
        201
    );
    assert_eq!(
        f.post("mkdir", json!({ "path": f.p("exchange/sub") }))
            .status,
        409
    );
    assert_eq!(
        f.post("mkdir", json!({ "path": f.p("missing/sub") }))
            .status,
        404
    );
    assert_eq!(
        code(&f.post("mkdir", json!({ "path": f.p("exchange/.ozbox") }))),
        "internal"
    );
    // move a file into the folder, then refuse to clobber
    assert_eq!(
        f.post(
            "rename",
            json!({ "from": f.p("notes.md"), "to": f.p("exchange/sub/notes.md") })
        )
        .status,
        200
    );
    assert!(f.root.join("exchange/sub/notes.md").exists());
    std::fs::write(f.root.join("notes.md"), "again").unwrap();
    assert_eq!(
        f.post(
            "rename",
            json!({ "from": f.p("notes.md"), "to": f.p("exchange/sub/notes.md") })
        )
        .status,
        409
    );
    // a folder cannot go into itself; a bad new name is refused
    assert_eq!(
        code(&f.post(
            "rename",
            json!({ "from": f.p("exchange"), "to": f.p("exchange/sub/exchange") })
        )),
        "into_itself"
    );
    assert_eq!(
        code(&f.post(
            "rename",
            json!({ "from": f.p("notes.md"), "to": f.p("a\u{1}b") })
        )),
        "bad_name"
    );
    assert_eq!(
        f.post("rename", json!({ "from": f.p("ghost"), "to": f.p("x") }))
            .status,
        404
    );
    // the state folder can be neither source nor target
    assert_eq!(
        code(&f.post(
            "rename",
            json!({ "from": f.p("notes.md"), "to": f.p(".ozbox/notes.md") })
        )),
        "internal"
    );
}

#[test]
fn delete_moves_to_a_dated_trash_and_restore_puts_it_back() {
    let f = fx();
    let before = std::fs::read(f.root.join("exchange/hello.txt")).unwrap();
    let none = f.post("delete", json!({ "paths": [f.p("nothing")] }));
    assert_eq!((none.status, code(&none)), (422, "not_found".into()));
    let r = f.post(
        "delete",
        json!({ "paths": [f.p("exchange/hello.txt"), f.p("nothing")] }),
    );
    let v = Fx::json(&r);
    assert_eq!(r.status, 200);
    assert_eq!(v["deleted"].as_array().unwrap().len(), 1);
    assert_eq!(v["failed"].as_array().unwrap().len(), 1);
    assert_eq!(v["retention_days"], 30);
    assert!(!f.root.join("exchange/hello.txt").exists());
    // the layout is /work/.ozbox/trash/<date>/<id>/item
    let day = f
        .root
        .join(".ozbox/trash")
        .join(crate::timeutil::day_stamp(T0));
    assert!(day.is_dir());
    let id = v["deleted"][0]["id"].as_str().unwrap().to_string();
    assert!(day.join(&id).join("item").is_file());
    let list = Fx::json(&f.get("trash", &[]));
    assert_eq!(list["items"][0]["original"], f.p("exchange/hello.txt"));
    assert_eq!(list["items"][0]["expires_ms"], T0 + 30 * 86_400_000);
    // restore; a second restore of the same id is gone
    assert_eq!(f.post("trash/restore", json!({ "id": id })).status, 200);
    assert_eq!(
        std::fs::read(f.root.join("exchange/hello.txt")).unwrap(),
        before
    );
    assert_eq!(f.post("trash/restore", json!({ "id": id })).status, 404);
    assert!(Fx::json(&f.get("trash", &[]))["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        f.post("trash/restore", json!({ "id": "../../etc" })).status,
        404
    );
}

#[test]
fn restore_never_overwrites_and_can_go_to_another_name() {
    let f = fx();
    let v = Fx::json(&f.post("delete", json!({ "paths": [f.p("exchange")] })));
    let id = v["deleted"][0]["id"].as_str().unwrap().to_string();
    std::fs::create_dir(f.root.join("exchange")).unwrap();
    let r = f.post("trash/restore", json!({ "id": id }));
    assert_eq!((r.status, code(&r)), (409, "exists".into()));
    assert_eq!(
        f.post(
            "trash/restore",
            json!({ "id": id, "to": f.p("exchange-restored") })
        )
        .status,
        200
    );
    assert!(f.root.join("exchange-restored/hello.txt").exists());
}

#[test]
fn the_trash_empties_by_hand_and_after_thirty_days() {
    let f = fx();
    let a = Fx::json(&f.post("delete", json!({ "paths": [f.p("notes.md")] })))["deleted"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    f.clock.advance(29 * 86_400_000);
    assert_eq!(
        Fx::json(&f.get("trash", &[]))["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.post("delete", json!({ "paths": [f.p("exchange/hello.txt")] }));
    f.clock.advance(2 * 86_400_000); // the first is now 31 days old
    let items = Fx::json(&f.get("trash", &[]));
    assert_eq!(
        items["items"].as_array().unwrap().len(),
        1,
        "the old one is gone: {items}"
    );
    assert_ne!(items["items"][0]["id"], a);
    assert_eq!(Fx::json(&f.post("trash/empty", json!({})))["removed"], 1);
    assert!(Fx::json(&f.get("trash", &[]))["items"]
        .as_array()
        .unwrap()
        .is_empty());
    // emptying by id leaves the others
    let ids: Vec<String> = ["notes.md", "exchange/hello.txt"]
        .iter()
        .map(|n| {
            std::fs::write(f.root.join(n), "x").unwrap();
            Fx::json(&f.post("delete", json!({ "paths": [f.p(n)] })))["deleted"][0]["id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    f.post("trash/empty", json!({ "ids": [ids[0]] }));
    assert_eq!(
        Fx::json(&f.get("trash", &[]))["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn search_finds_names_and_content_within_limits() {
    let f = fx();
    std::fs::create_dir_all(f.root.join("node_modules/x")).unwrap();
    std::fs::write(f.root.join("node_modules/x/hello.js"), "hello").unwrap();
    std::fs::write(f.root.join(".env.local"), "hello=secret").unwrap();
    let find = |pairs: &[(&str, &str)]| {
        let mut a = vec![("path", f.root.to_str().unwrap().to_string())];
        a.extend(pairs.iter().map(|(k, v)| (*k, v.to_string())));
        let a: Vec<(&str, &str)> = a.iter().map(|(k, v)| (*k, v.as_str())).collect();
        Fx::json(&f.get("search", &a))
    };
    let v = find(&[("q", "hello")]);
    let paths: Vec<&str> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths.len(), 1, "{paths:?}");
    assert!(paths[0].ends_with("exchange/hello.txt"));
    assert_eq!(
        find(&[("q", "*.md")])["results"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        find(&[("q", "n?tes.*")])["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // content: finds the line, never looks in a secret file or in node_modules
    let v = find(&[("q", "WORLD"), ("content", "1")]);
    assert_eq!(v["results"][0]["line"], 2);
    assert_eq!(v["results"][0]["snippet"], "world");
    assert!(find(&[("q", "secret"), ("content", "1")])["results"]
        .as_array()
        .unwrap()
        .is_empty());
    // limits
    for i in 0..5 {
        std::fs::write(f.root.join(format!("many{i}.txt")), "m").unwrap();
    }
    let v = find(&[("q", "many"), ("limit", "2")]);
    assert_eq!(
        (
            v["results"].as_array().unwrap().len(),
            v["truncated"].clone()
        ),
        (2, json!(true))
    );
    assert_eq!(
        f.get("search", &[("path", &f.p("")), ("q", "")]).status,
        400
    );
}

#[cfg(unix)]
#[test]
fn search_does_not_follow_links_out() {
    use std::os::unix::fs::symlink;
    let f = fx();
    let outside = f.root.parent().unwrap().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("needle.txt"), "needle").unwrap();
    symlink(&outside, f.root.join("link")).unwrap();
    let v = Fx::json(&f.get("search", &[("path", &f.p("")), ("q", "needle")]));
    assert!(v["results"].as_array().unwrap().is_empty());
}

#[test]
fn a_download_link_serves_one_file_until_it_expires() {
    let f = fx();
    let tok = f.token(&[f.p("exchange/hello.txt")], 60, false);
    let r = f.get("download", &[("token", &tok)]);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert!(r
        .header("content-disposition")
        .unwrap()
        .starts_with("attachment; filename=\"hello.txt\""));
    assert_eq!(Fx::body(r), b"hello\nworld\n");
    // the link is not a secret-keeper: it dies on schedule
    f.clock.advance(61_000);
    let r = f.get("download", &[("token", &tok)]);
    assert_eq!((r.status, code(&r)), (404, "link_invalid".into()));
}

#[test]
fn a_revoked_forged_or_unknown_link_gets_the_same_answer() {
    let f = fx();
    let tok = f.token(&[f.p("notes.md")], 600, false);
    let id = tok.split('.').next().unwrap().to_string();
    let list = Fx::json(&f.get("tokens", &[]));
    assert_eq!(list["tokens"][0]["id"], id);
    assert!(list["tokens"][0].get("paths").is_none());
    assert_eq!(
        f.svc
            .call(
                "DELETE",
                &format!("/v1/files/tokens/{id}"),
                &q(&[]),
                Input::None
            )
            .status,
        200
    );
    assert_eq!(
        f.svc
            .call(
                "DELETE",
                &format!("/v1/files/tokens/{id}"),
                &q(&[]),
                Input::None
            )
            .status,
        404
    );
    for t in [
        tok.clone(),
        format!("{id}.9999999999.00"),
        "garbage".into(),
        String::new(),
    ] {
        let r = f.get("download", &[("token", &t)]);
        assert_eq!((r.status, code(&r)), (404, "link_invalid".into()), "{t}");
    }
    assert_eq!(
        f.post(
            "tokens",
            json!({ "paths": [f.p("notes.md")], "ttl_s": 86_401 })
        )
        .status,
        400
    );
    assert_eq!(
        f.post("tokens", json!({ "paths": [f.p("notes.md")], "ttl_s": 5 }))
            .status,
        400
    );
    assert_eq!(
        f.post(
            "tokens",
            json!({ "paths": [f.p("notes.md")], "ttl_s": 86_400 })
        )
        .status,
        201
    );
}

#[test]
fn a_link_is_rechecked_at_download_time() {
    let f = fx();
    let tok = f.token(&[f.p("exchange/hello.txt")], 600, false);
    // the file is replaced by a link out of the root after the link was made
    #[cfg(unix)]
    {
        std::fs::remove_file(f.root.join("exchange/hello.txt")).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", f.root.join("exchange/hello.txt")).unwrap();
        assert_eq!(
            code(&f.get("download", &[("token", &tok)])),
            "symlink_escape"
        );
    }
    let _ = tok;
}

#[test]
fn inline_links_are_for_images_and_pdfs_only() {
    let f = fx();
    std::fs::write(f.root.join("pic.png"), b"\x89PNG").unwrap();
    std::fs::write(f.root.join("x.html"), "<script>alert(1)</script>").unwrap();
    let tok = f.token(&[f.p("pic.png")], 60, true);
    let r = f.get("download", &[("token", &tok)]);
    assert_eq!(r.header("content-type"), Some("image/png"));
    assert!(r
        .header("content-disposition")
        .unwrap()
        .starts_with("inline"));
    assert_eq!(
        code(&f.post(
            "tokens",
            json!({ "paths": [f.p("x.html")], "inline": true })
        )),
        "not_inline"
    );
    // a plain link for html downloads as an opaque attachment, never rendered
    let tok = f.token(&[f.p("x.html")], 60, false);
    let r = f.get("download", &[("token", &tok)]);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
}

#[test]
fn a_bundle_zips_a_selection_skipping_secrets_and_respects_the_cap() {
    let f = fx();
    std::fs::write(f.root.join("exchange/.env"), "S=1").unwrap();
    std::fs::write(f.root.join("exchange/key.pem"), "K").unwrap();
    let tok = f.token(&[f.p("exchange"), f.p("notes.md")], 60, false);
    let r = f.get("download", &[("token", &tok)]);
    assert_eq!(r.header("content-type"), Some("application/zip"));
    assert_eq!(r.header("x-ozbox-skipped"), Some("2"));
    let zip = Fx::body(r);
    let text = String::from_utf8_lossy(&zip);
    assert!(text.contains("exchange/hello.txt") && text.contains("notes.md"));
    assert!(!text.contains("SECRET") && !text.contains(".env") && !text.contains("key.pem"));
    // the temp bundle is cleaned up once streamed
    let tmp = f.root.join(".ozbox/tmp");
    assert!(std::fs::read_dir(tmp)
        .map(|mut d| d.next().is_none())
        .unwrap_or(true));
    // over the cap is refused when the link is made
    std::fs::write(f.root.join("big.dat"), vec![0u8; 5000]).unwrap();
    let r = f.post(
        "tokens",
        json!({ "paths": [f.p("big.dat"), f.p("notes.md")] }),
    );
    assert_eq!((r.status, code(&r)), (413, "too_large".into()));
    // a secret chosen by name is refused outright
    assert_eq!(
        f.post("tokens", json!({ "paths": [f.p(".env"), f.p("notes.md")] }))
            .status,
        403
    );
}

#[test]
fn audit_records_changes_and_downloads_without_contents() {
    let f = fx();
    f.put(
        "upload",
        &[("path", &f.p("exchange")), ("name", "report.txt")],
        b"TOP-SECRET-CONTENT",
    );
    let h = sha256_hex(b"hello\nworld\n");
    f.put(
        "write",
        &[("path", &f.p("exchange/hello.txt")), ("if_match", &h)],
        b"EDITED-CONTENT",
    );
    f.post("mkdir", json!({ "path": f.p("d") }));
    f.post("rename", json!({ "from": f.p("d"), "to": f.p("e") }));
    f.post("delete", json!({ "paths": [f.p("e")] }));
    let tok = f.token(&[f.p("exchange/report.txt")], 60, false);
    Fx::body(f.get("download", &[("token", &tok)]));
    f.get("preview", &[("path", &f.p(".env"))]);
    f.put(
        "upload",
        &[("path", &f.p("exchange")), ("name", ".env")],
        b"S=1",
    );
    let ev = f.svc.audit_events();
    let actions: Vec<&str> = ev.iter().map(|e| e.action.as_str()).collect();
    for a in [
        "upload",
        "write",
        "mkdir",
        "rename",
        "delete",
        "token_create",
        "download",
    ] {
        assert!(actions.contains(&a), "{a} in {actions:?}");
    }
    let dl = ev.iter().find(|e| e.action == "download").unwrap();
    assert_eq!(dl.path.as_deref(), Some("work:exchange/report.txt"));
    assert_eq!(dl.size, Some(18));
    assert!(ev
        .iter()
        .any(|e| e.action == "upload" && e.outcome == "refused:secret_blocked"));
    let log = std::fs::read_to_string(f.root.join(".ozbox/files/audit.jsonl")).unwrap();
    assert!(!log.contains("TOP-SECRET") && !log.contains("EDITED-CONTENT") && !log.contains("S=1"));
    // and it is readable through the API
    assert!(
        Fx::json(&f.get("audit", &[("limit", "3")]))["events"]
            .as_array()
            .unwrap()
            .len()
            <= 3
    );
}

#[test]
fn unknown_routes_and_methods_are_clean_errors() {
    let f = fx();
    assert_eq!(f.get("nope", &[]).status, 404);
    assert_eq!(
        f.svc
            .call("DELETE", "/v1/files/list", &q(&[]), Input::None)
            .status,
        405
    );
    assert_eq!(
        f.svc
            .call("GET", "/v1/files/upload", &q(&[]), Input::None)
            .status,
        405
    );
    assert_eq!(code(&f.get("list", &[])), "bad_request");
    assert!(FilesService::wants_stream_body("PUT", "/v1/files/upload"));
    assert!(!FilesService::wants_stream_body("POST", "/v1/files/mkdir"));
    let r = f.get("roots", &[]);
    assert_eq!(Fx::json(&r)["limits"]["trash_days"], 30);
}

#[test]
fn glob_matching() {
    assert!(glob("*.md", "notes.md") && glob("n?tes*", "notes.md") && glob("*", ""));
    assert!(!glob("*.md", "notes.mdx") && !glob("a?c", "ac"));
}
