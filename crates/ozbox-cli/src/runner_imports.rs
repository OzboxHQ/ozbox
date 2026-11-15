//! What a script that receives a secret loads, found by reading it (a STATIC check), so a pin can cover all of it.
//!
//! A pin on `mint.mjs` covers that file's bytes and nothing it imports: a sibling or a package an agent can rewrite would run
//! with the secret. So for a secret-receiving command whose entry is a script (`.js .mjs .cjs .ts .mts .cts`), the launcher
//! reads the entry (the VERIFIED bytes) and follows what it loads:
//! - a relative import must name its extension (a bare `./x` lets `./x.js`, `./x/index.js` and `./x` compete, and the agent
//!   can add the one that wins) and the file must be pinned, or lie inside a pinned folder; every such file is READ in turn,
//!   whatever folder holds it (only a package under `node_modules/` is trusted as pinned bytes and not read: G5 seventh round, NV6-H1);
//! - a package import (`@scope/name`, `name/sub`) must be a pinned tree at `node_modules/<name>`, and that package's own
//!   `dependencies`, non-optional `peerDependencies` and `optionalDependencies` that are installed must be pinned trees too
//!   (nested copies inside a tree are covered by the tree);
//! - a Node built-in (`node:fs`, `path`, ...) loads nothing of the project and is allowed;
//! - anything else is REFUSED: a computed `import(x)` / `require(x)`, `require` used as anything but a direct call (an alias,
//!   `require.main`, `require.resolve`), `createRequire`, `getBuiltinModule`, `module.require`, `module.constructor`,
//!   `process.mainModule`, `process.execve`, `eval(`, `new Function(`, `process.dlopen`/`binding`, an absolute path, a URL, a `#`
//!   subpath import, a `.node` file, the modules `child_process`, `worker_threads`, `cluster`, `vm`, `module` and `inspector`,
//!   and a folder named `node_modules` between an importing file and the project folder (it would shadow the pinned package).
//!
//! **What this is not.** It is a reader, not a JavaScript engine. It does not see a call to `eval` or `Function` that is not
//! written the plain way (`(0, eval)(...)`, `globalThis.eval(...)`, `Function(...)` without `new`), computed member access
//! (`process['binding']`), a dynamic `import(variable)` that it can only refuse when the argument is not a plain string, what
//! a native add-on does, or package code (a pinned package is trusted as the bytes the owner approved, and is not read). The
//! owner approves the pinned file; this refuses the honest mistake (an unpinned sibling, an unpinned package, a sibling that
//! loads from a writable folder) and the loaders it can recognise.

use std::collections::{BTreeMap, BTreeSet};

/// Extensions of a script the launcher analyses and a relative import may name.
pub const SCRIPT_EXT: [&str; 6] = [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"];

/// Node's own modules (no project code). `node:`-prefixed names are always allowed.
const BUILTINS: &[&str] = &[
    "assert",
    "assert/strict",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "readline/promises",
    "repl",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// Node modules that start other code, which the pin does not follow.
/// (`module` also hides `register` and `_load`, and `inspector` lets a local client run code in the process.)
const SPAWNERS: &[&str] = &[
    "child_process",
    "worker_threads",
    "cluster",
    "vm",
    "module",
    "inspector",
];

/// How an import was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    /// `./x.mjs`, `../lib/y.js`: relative to the importing file.
    Relative(String),
    /// A package, by its name (`@scope/pkg` or `pkg`).
    Package(String),
    Builtin,
}

pub fn is_script(path: &str) -> bool {
    SCRIPT_EXT.iter().any(|e| path.ends_with(e))
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str { value: String, plain: bool },
    Punct(char),
}

fn regex_may_start(prev: Option<&Tok>) -> bool {
    match prev {
        None => true,
        Some(Tok::Punct(c)) => !matches!(c, ')' | ']' | '}'),
        Some(Tok::Ident(w)) => matches!(
            w.as_str(),
            "return"
                | "typeof"
                | "case"
                | "in"
                | "of"
                | "delete"
                | "void"
                | "throw"
                | "new"
                | "else"
                | "do"
                | "instanceof"
        ),
        Some(Tok::Str { .. }) => false,
    }
}

/// Split source into identifiers, strings and punctuation, leaving out comments and the insides of regular expressions and
/// template text (a template with a `${` is not a plain string).
fn tokens(src: &str) -> Vec<Tok> {
    let b: Vec<char> = src.chars().collect();
    let mut out: Vec<Tok> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && b.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '#' && i == 0 && b.get(1) == Some(&'!') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '\'' || c == '"' || c == '`' {
            let q = c;
            let mut s = String::new();
            let mut plain = true;
            i += 1;
            while i < b.len() && b[i] != q {
                if b[i] == '\\' {
                    plain = false;
                    i += 1;
                } else if q == '`' && b[i] == '$' && b.get(i + 1) == Some(&'{') {
                    plain = false;
                }
                if i < b.len() {
                    s.push(b[i]);
                }
                i += 1;
            }
            i += 1;
            out.push(Tok::Str { value: s, plain });
        } else if c == '/' && regex_may_start(out.last()) {
            i += 1;
            let mut in_class = false;
            while i < b.len() && b[i] != '\n' {
                match b[i] {
                    '\\' => i += 1,
                    '[' => in_class = true,
                    ']' => in_class = false,
                    '/' if !in_class => break,
                    _ => {}
                }
                i += 1;
            }
            i += 1;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Tok::Punct('~')); // a regular expression is a value
        } else if c.is_alphanumeric() || c == '_' || c == '$' {
            let mut s = String::new();
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_' || b[i] == '$') {
                s.push(b[i]);
                i += 1;
            }
            out.push(Tok::Ident(s));
        } else {
            out.push(Tok::Punct(c));
            i += 1;
        }
    }
    out
}

/// Classify one specifier, or say why it is refused.
pub fn classify(spec: &str) -> Result<Import, String> {
    if spec.is_empty() || spec.len() > 300 || spec.contains('\0') || spec.contains('\\') {
        return Err(format!("the import {spec:?} is not a plain specifier"));
    }
    // G5 sixth round, NV5-L3: a script that receives a secret may not start another program or thread of code: what it starts takes
    // paths the pin does not read (`spawn('python3', ['sign.py'])`, `new Worker('./lib/w.js')`), and another program has its own lookup.
    let bare = spec.strip_prefix("node:").unwrap_or(spec);
    if SPAWNERS.contains(&bare) {
        return Err(format!(
            "the import {spec} can start another program or script, and what it starts is not covered by the pin: a script that receives a secret may not use it"
        ));
    }
    if let Some(b) = spec.strip_prefix("node:") {
        return if b.is_empty() {
            Err("an empty node: import".into())
        } else {
            Ok(Import::Builtin)
        };
    }
    if spec.starts_with("./") || spec.starts_with("../") {
        if spec.ends_with(".node") {
            return Err(format!(
                "{spec} is a native add-on: it cannot be checked or pinned as a script"
            ));
        }
        if !SCRIPT_EXT
            .iter()
            .chain([".json"].iter())
            .any(|e| spec.ends_with(e))
        {
            return Err(format!(
                "the import {spec} must name its file extension (.js, .mjs, .cjs, .ts, .json): without one, another file can take its place"
            ));
        }
        return Ok(Import::Relative(spec.to_string()));
    }
    if spec.starts_with('/')
        || spec.contains("://")
        || spec.starts_with("data:")
        || spec.starts_with("file:")
    {
        return Err(format!("the import {spec} is an absolute path or a URL: a pinned script imports project files by relative path"));
    }
    if spec.starts_with('#') {
        return Err(format!("the import {spec} is a package subpath import, resolved through an unpinned package.json"));
    }
    if BUILTINS.contains(&spec) {
        return Ok(Import::Builtin);
    }
    // a package: `name`, `name/sub`, `@scope/name`, `@scope/name/sub`
    let mut parts = spec.split('/');
    let first = parts.next().unwrap_or("");
    let name = if first.starts_with('@') {
        match parts.next() {
            Some(second) if !second.is_empty() => format!("{first}/{second}"),
            _ => return Err(format!("the import {spec} is not a package name")),
        }
    } else {
        first.to_string()
    };
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'/' | b'~'))
        || name.starts_with('.')
        || name.contains("..")
    {
        return Err(format!("the import {spec} is not a package name"));
    }
    Ok(Import::Package(name))
}

/// Every import a script makes. `Err` names what cannot be followed (a computed loader, `eval`...).
pub fn imports(src: &str) -> Result<Vec<Import>, String> {
    let t = tokens(src);
    let mut out = Vec::new();
    let id = |i: usize, w: &str| matches!(t.get(i), Some(Tok::Ident(x)) if x == w);
    let punct = |i: usize, c: char| matches!(t.get(i), Some(Tok::Punct(x)) if *x == c);
    let mut push = |s: &Tok| -> Result<(), String> {
        match s {
            Tok::Str { value, plain: true } => {
                out.push(classify(value)?);
                Ok(())
            }
            _ => Err("a script loads a module by a computed name (import(x), require(x)): that cannot be checked, and is refused".into()),
        }
    };
    for i in 0..t.len() {
        let Tok::Ident(w) = &t[i] else { continue };
        let after_dot = i > 0 && matches!(&t[i - 1], Tok::Punct('.'));
        match w.as_str() {
            "createRequire" => return Err("createRequire loads modules by a name that cannot be checked".into()),
            "getBuiltinModule" => return Err("getBuiltinModule loads a Node module by a name that cannot be checked".into()),
            // G5 eighth round, NV7-L2: rare words that reach a loader or run code, refused anywhere (destructuring, `process?.`, an alias)
            "mainModule" | "execve" | "dlopen" => return Err(format!("{w} loads or runs code that cannot be checked")),
            // `module` is allowed only as `module.exports`: `module.paths`, `module.require`, `const m = module`... reach the loader
            "module" if !after_dot && !(punct(i + 1, '.') && id(i + 2, "exports")) => {
                return Err("module is used other than as module.exports: module.paths, module.require and an alias reach the loader, and cannot be checked".into())
            }
            "constructor" if after_dot && i >= 2 && matches!(&t[i - 2], Tok::Ident(x) if x == "module" || x == "constructor") => {
                return Err("a .constructor chain reaches Function or the module loader, and cannot be checked".into())
            }
            "main" if after_dot && i >= 2 && id(i - 2, "require") => {
                return Err("require.main loads modules by a name that cannot be checked".into())
            }
            "eval" if punct(i + 1, '(') && !after_dot => return Err("eval( runs text that cannot be checked".into()),
            "Function" if punct(i + 1, '(') && i > 0 && id(i - 1, "new") => {
                return Err("new Function( runs text that cannot be checked".into())
            }
            "binding" if after_dot && ((i >= 2 && id(i - 2, "process")) || (i >= 3 && punct(i - 2, '?') && id(i - 3, "process"))) => {
                return Err("process.dlopen / process.binding load native code".into())
            }
            "require" if after_dot && i >= 2 && id(i - 2, "module") => {
                return Err("module.require loads modules by a name that cannot be checked".into())
            }
            "require" if punct(i + 1, '.') && id(i + 2, "resolve") => {
                return Err("require.resolve is refused: it asks the unpinned file system where a module is".into())
            }
            // an aliased `require` (`const r = require`, `f(require)`, `typeof require`) hides every load behind it from this reader
            "require" if !after_dot && !punct(i + 1, '(') => {
                return Err("require is used as a value, not called directly as require('...'): a load through an alias cannot be checked".into())
            }
            "require" | "import" if punct(i + 1, '(') && !after_dot => match (t.get(i + 2), t.get(i + 3)) {
                (Some(s @ Tok::Str { .. }), Some(Tok::Punct(')' | ','))) => push(s)?,
                _ => push(&Tok::Punct('x'))?,
            },
            "import" if !after_dot && !punct(i + 1, '.') => {
                // `import "x"` or `import a, {b} from "x"`
                if let Some(s @ Tok::Str { .. }) = t.get(i + 1) {
                    push(s)?;
                    continue;
                }
                let mut j = i + 1;
                while j < t.len() && j < i + 2000 {
                    if id(j, "from") {
                        if let Some(s @ Tok::Str { .. }) = t.get(j + 1) {
                            push(s)?;
                        }
                        break;
                    }
                    if punct(j, ';') {
                        break;
                    }
                    j += 1;
                }
            }
            "export" if !after_dot && (punct(i + 1, '*') || punct(i + 1, '{')) => {
                let mut j = i + 1;
                while j < t.len() && j < i + 2000 {
                    if id(j, "from") {
                        if let Some(s @ Tok::Str { .. }) = t.get(j + 1) {
                            push(s)?;
                        }
                        break;
                    }
                    if punct(j, ';') {
                        break;
                    }
                    j += 1;
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Lexically join `base` (the importing file's folder, relative to the project) and a relative specifier; `None` if it climbs out
/// of the project.
pub fn join_rel(base_dir: &str, spec: &str) -> Option<String> {
    let mut parts: Vec<&str> = base_dir.split('/').filter(|p| !p.is_empty()).collect();
    for seg in spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

fn parent_of(rel: &str) -> &str {
    rel.rsplit_once('/').map_or("", |(d, _)| d)
}

/// What a script's loading reaches.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Closure {
    /// Project files, relative to the project folder (the entry included).
    pub files: BTreeSet<String>,
    /// Package folders that must be pinned as trees (`node_modules/<name>`).
    pub trees: BTreeSet<String>,
}

/// What a closure needs from the folder: the bytes of a script, a package's `package.json`, and whether a path is a folder.
pub trait Source {
    /// The bytes of a project file that is going to be loaded, or why it cannot be (not pinned, missing).
    fn file(&mut self, rel: &str) -> Result<Vec<u8>, String>;
    /// The `package.json` of `node_modules/<name>`, if that package is there.
    fn package_json(&mut self, name: &str) -> Result<Option<Vec<u8>>, String>;
    /// Whether `rel` (a folder under the project) exists. Used to see a `node_modules` that would shadow a pinned package.
    fn dir_exists(&mut self, rel: &str) -> bool;
    /// Whether `rel` lies inside a package under `node_modules/` that is pinned (a file there is covered by its pin and is not read).
    /// A pinned project folder is NOT covered: its files are read, so what they load is followed.
    fn covered(&mut self, rel: &str) -> bool;
}

fn pkg_deps(json: &[u8]) -> (Vec<String>, Vec<String>) {
    // (required, optional-and-installed)
    let v: serde_json::Value = serde_json::from_slice(json).unwrap_or(serde_json::Value::Null);
    let keys = |k: &str| -> Vec<String> {
        v[k].as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    };
    let mut req = keys("dependencies");
    let optional_meta: BTreeMap<String, bool> = v["peerDependenciesMeta"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, m)| (k.clone(), m["optional"] == true))
                .collect()
        })
        .unwrap_or_default();
    for p in keys("peerDependencies") {
        if !optional_meta.get(&p).copied().unwrap_or(false) {
            req.push(p);
        }
    }
    (req, keys("optionalDependencies"))
}

/// Follow `entry` and everything it loads. Does not consult pins itself: a file the source cannot give is the caller's refusal.
pub fn closure(entry: &str, src: &mut dyn Source) -> Result<Closure, String> {
    let mut c = Closure::default();
    let mut queue = vec![entry.to_string()];
    let mut packages: Vec<String> = Vec::new();
    while let Some(f) = queue.pop() {
        if !c.files.insert(f.clone()) {
            continue;
        }
        // every file the script loads is asked for, a .json one too: it loads no code, but a config an agent can edit decides where
        // a key is sent
        let bytes = src.file(&f)?;
        if !is_script(&f) {
            continue;
        }
        let text = String::from_utf8(bytes).map_err(|_| format!("{f} is not text"))?;
        for imp in imports(&text).map_err(|e| format!("{f}: {e}"))? {
            match imp {
                Import::Builtin => {}
                Import::Relative(spec) => {
                    let to = join_rel(parent_of(&f), &spec)
                        .ok_or_else(|| format!("{f}: {spec} leaves the project folder"))?;
                    if src.covered(&to) {
                        continue;
                    }
                    queue.push(to);
                }
                Import::Package(name) => {
                    // a folder named node_modules between the importing file and the project folder would win over the pinned package
                    let mut d = parent_of(&f).to_string();
                    while !d.is_empty() {
                        if src.dir_exists(&format!("{d}/node_modules")) {
                            return Err(format!("{f} imports {name}, but {d}/node_modules would shadow the pinned package"));
                        }
                        d = parent_of(&d).to_string();
                    }
                    packages.push(name);
                }
            }
        }
        while let Some(name) = packages.pop() {
            let tree = format!("node_modules/{name}");
            if !c.trees.insert(tree) {
                continue;
            }
            match src.package_json(&name)? {
                None => {
                    return Err(format!(
                        "the package {name} is not installed under node_modules"
                    ))
                }
                Some(j) => {
                    let (req, opt) = pkg_deps(&j);
                    for d in req {
                        // nested inside this package's own folder: the tree covers it
                        if !src.dir_exists(&format!("node_modules/{name}/node_modules/{d}")) {
                            packages.push(d);
                        }
                    }
                    for d in opt {
                        if src.package_json(&d)?.is_some()
                            && !src.dir_exists(&format!("node_modules/{name}/node_modules/{d}"))
                        {
                            packages.push(d);
                        }
                    }
                }
            }
        }
    }
    Ok(c)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn imp(src: &str) -> Vec<Import> {
        imports(src).unwrap()
    }

    #[test]
    fn it_finds_what_a_real_minter_loads_and_ignores_what_only_looks_like_a_load() {
        // the shape of a real project's session minter: a sibling, a package, a built-in, in several spellings
        let src = r#"#!/usr/bin/env node
            // import evil from './nope.mjs'
            /* require('./nope2.js') */
            import { createClient } from '@supabase/supabase-js'
            import fs, { readFileSync } from "node:fs";
            import { retry } from './mint-retry.mjs'
            import path from 'path'
            export * from './more.js'
            const msg = "import x from './in-a-string.js'"
            const re = /import\s+'nope'/
            const lib = require('./legacy.cjs')
            const x = await import('lodash/fp')
            console.log(1 / 2 / 3, `plain ${msg}`)
        "#;
        let got = imp(src);
        for want in [
            Import::Package("@supabase/supabase-js".into()),
            Import::Builtin,
            Import::Relative("./mint-retry.mjs".into()),
            Import::Relative("./more.js".into()),
            Import::Relative("./legacy.cjs".into()),
            Import::Package("lodash".into()),
        ] {
            assert!(got.contains(&want), "{want:?} in {got:?}");
        }
        assert_eq!(got.len(), 7, "{got:?}");
        for never in ["nope", "in-a-string"] {
            assert!(!format!("{got:?}").contains(never), "{never}");
        }
    }

    #[test]
    fn what_cannot_be_followed_is_refused_and_says_so() {
        for (bad, why) in [
            ("const m = await import(name)", "computed"),
            ("require(`./x/${a}.js`)", "computed"),
            ("const r = require(a + '.js')", "computed"),
            ("const r = createRequire(import.meta.url)", "createRequire"),
            (
                "import { createRequire } from 'node:module'",
                "not covered by the pin",
            ),
            ("eval('1')", "eval"),
            ("new Function('return 1')", "Function"),
            ("module.require('x')", "module.require"),
            ("require.resolve('x')", "require.resolve"),
            ("process.dlopen(m, 'x.node')", "dlopen"),
            ("import x from './nodots'", "extension"),
            ("import x from './addon.node'", "native"),
            ("import x from '/etc/x.js'", "absolute"),
            ("import x from 'https://x.example/a.js'", "URL"),
            ("import x from '#internal'", "subpath"),
        ] {
            let e = imports(bad).unwrap_err();
            assert!(e.to_lowercase().contains(&why.to_lowercase()), "{bad}: {e}");
        }
        // NV5-L3: modules that start other code are refused, with or without the node: prefix
        for m in [
            "child_process",
            "node:child_process",
            "worker_threads",
            "node:worker_threads",
            "cluster",
            "vm",
            "node:vm",
        ] {
            let e = imports(&format!("import x from '{m}'")).unwrap_err();
            assert!(e.contains("not covered by the pin"), "{m}: {e}");
            assert!(
                imports(&format!("const x = require('{m}')")).is_err(),
                "{m}"
            );
        }
        // NV6-L1: the shapes that reach a loader without naming it
        for bad in [
            "process.getBuiltinModule('child_process')",
            "const g = process.getBuiltinModule; g('fs')",
            "const r = require; r('child_process')",
            "f(require)",
            "typeof require",
            "require.main.require('./out/x.js')",
            "if (require.main === module) {}",
            "module.constructor._load('x')",
            "process.mainModule.require('x')",
            "process.execve('/bin/sh', [], {})",
            "process.binding('fs')",
            "process?.binding('fs')",
            "const { mainModule } = process",
            "const { execve } = process",
            "const { dlopen } = process",
            "process?.mainModule",
            "module.paths.unshift('/x')",
            "const m = module; m.require('x')",
            "(() => {}).constructor.constructor('return 1')()",
            "p.createRequire(import.meta.url)",
            "import { register } from 'node:module'",
            "import mod from 'module'",
            "import i from 'node:inspector'",
            "const i = require('inspector')",
        ] {
            assert!(imports(bad).is_err(), "{bad}");
        }
        // a direct, plain require call is still fine
        assert!(imports("const fs = require('node:fs'); const x = require('./a.cjs')").is_ok());
        // things that look dangerous but are not loaders
        assert!(imports(
            "x.eval(1); const y = obj.require; function evaluate(){}; class Function2 {}"
        )
        .is_ok());
        assert!(imports("module.exports = { a: 1 }; x.module; const y = a.module").is_ok());
        assert!(imports("import.meta.url; const { dirname } = import.meta").is_ok());
    }

    struct Fs {
        files: BTreeMap<String, String>,
        pkgs: BTreeMap<String, String>,
        dirs: BTreeSet<String>,
    }
    impl Source for Fs {
        fn file(&mut self, rel: &str) -> Result<Vec<u8>, String> {
            self.files
                .get(rel)
                .map(|s| s.clone().into_bytes())
                .ok_or_else(|| format!("{rel} is not there"))
        }
        fn package_json(&mut self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.pkgs.get(name).map(|s| s.clone().into_bytes()))
        }
        fn dir_exists(&mut self, rel: &str) -> bool {
            self.dirs.contains(rel)
        }
        fn covered(&mut self, rel: &str) -> bool {
            rel.starts_with("node_modules/")
        }
    }

    fn fs() -> Fs {
        Fs {
            files: BTreeMap::from([
                (
                    "tests/mint.mjs".to_string(),
                    "import {c} from '@supabase/supabase-js'; import {r} from './retry.mjs'; import fs from 'node:fs'".to_string(),
                ),
                ("tests/retry.mjs".to_string(), "import './cfg.json'; export const r = 1".to_string()),
                ("tests/cfg.json".to_string(), "{}".to_string()),
            ]),
            pkgs: BTreeMap::from([
                (
                    "@supabase/supabase-js".to_string(),
                    r#"{"dependencies":{"@supabase/auth-js":"1","tslib":"2"},"optionalDependencies":{"fsevents":"1"}}"#.to_string(),
                ),
                ("@supabase/auth-js".to_string(), r#"{"dependencies":{"tslib":"2"}}"#.to_string()),
                ("tslib".to_string(), "{}".to_string()),
            ]),
            dirs: BTreeSet::new(),
        }
    }

    #[test]
    fn the_closure_is_the_entry_its_relative_files_and_every_package_it_needs() {
        let c = closure("tests/mint.mjs", &mut fs()).unwrap();
        assert_eq!(
            c.files.iter().map(String::as_str).collect::<Vec<_>>(),
            ["tests/cfg.json", "tests/mint.mjs", "tests/retry.mjs"]
        );
        assert_eq!(
            c.trees.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                "node_modules/@supabase/auth-js",
                "node_modules/@supabase/supabase-js",
                "node_modules/tslib"
            ]
        );
        // an optional dependency that is installed is part of it; one that is not installed is not
        let mut f = fs();
        f.pkgs.insert("fsevents".into(), "{}".into());
        assert!(closure("tests/mint.mjs", &mut f)
            .unwrap()
            .trees
            .contains("node_modules/fsevents"));
    }

    #[test]
    fn a_missing_package_a_shadowing_node_modules_and_an_unreadable_file_refuse() {
        let mut f = fs();
        f.pkgs.remove("tslib");
        assert!(closure("tests/mint.mjs", &mut f)
            .unwrap_err()
            .contains("tslib is not installed"));
        let mut f = fs();
        f.dirs.insert("tests/node_modules".into());
        assert!(closure("tests/mint.mjs", &mut f)
            .unwrap_err()
            .contains("shadow"));
        let mut f = fs();
        f.files.remove("tests/retry.mjs");
        assert!(closure("tests/mint.mjs", &mut f)
            .unwrap_err()
            .contains("retry.mjs"));
        // a relative import that climbs out of the project
        let mut f = fs();
        f.files
            .insert("tests/mint.mjs".into(), "import '../../x.mjs'".into());
        assert!(closure("tests/mint.mjs", &mut f)
            .unwrap_err()
            .contains("leaves the project"));
        // a package that nests its own copy of a dependency needs no second pin for it
        let mut f = fs();
        f.dirs
            .insert("node_modules/@supabase/supabase-js/node_modules/@supabase/auth-js".into());
        let c = closure("tests/mint.mjs", &mut f).unwrap();
        assert!(
            !c.trees.contains("node_modules/@supabase/auth-js"),
            "the nested copy is inside supabase-js's own tree: {c:?}"
        );
    }
}
