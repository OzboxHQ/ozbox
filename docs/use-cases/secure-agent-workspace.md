# A secure workspace for AI agents

Give an agent a real machine to work on without giving it your keys, your Production, or an unlimited bill. An agent
works on a box in your own cloud account, as an ordinary user with no `sudo`, behind a permission engine that decides
every action it takes, with every decision written to a log that shows if it was edited. When the job is over, the box is
paused or deleted.

See [how to read the status](README.md#how-to-read-the-status). The box itself (create, clone, pause, destroy) is proven on
a real cloud box. The agent-side controls below (the permission engine, the tool host, the audit log, the secret runner,
memory and skills, spend caps, orchestration) are built and covered by the test suite, and a run on a real box goes through
the box daemon ([ADR 0019](../adr/0019-agent-runs-on-real-boxes.md)); they have not been exercised end to end on a real
cloud box with a real agent yet, so those examples are **Preview** at most.

**What this is, and is not.** An Oz Box is a whole virtual machine in your cloud account, with a persistent disk. It is a
good place for an agent that works for minutes or hours, builds things, runs a browser and a test suite, and should still
be there tomorrow. It is not a per-request sandbox for running thousands of untrusted snippets a minute; the last section
says when to use one of those instead.

**Where the walls are, in one picture:**

```
 you ──(plan, then apply)──▶ ozbox / dashboard (on your computer; your keys stay here or in the box's encrypted store)
                                   │
        agent (box user, no sudo) ─┼─▶ tool host ──▶ permission engine ──▶ allow · ask you · refuse ──▶ audit log
                                   │
                                   ├─▶ model provider, only through a broker that adds the key (the agent holds a per-run token)
                                   └─▶ secrets: only through a runner user, only the names a project declared
 the box: your account, no inbound port, no sudo, /work on its own disk
```

---

## 1. A disposable copy for an agent you do not fully trust

**You want:** a third-party agent, a new tool, or an experiment, run on a copy of your project that you can throw away.

```
ozbox snapshot main
ozbox clone main scratch-1          # a new box from main's latest snapshot
# ... let the agent work on scratch-1 ...
ozbox destroy scratch-1             # shows the plan and asks you to type the name
```

`main` is never touched. If you would rather the agent never sees what is on `main`, start from nothing instead:
`ozbox create scratch-1 --profile web-dev`, which has your tools and none of your files.

**Underneath:** the clone gets its own disk made from the snapshot, in your account, with no inbound port. `destroy`
deletes the machine and its `/work` and, unless you pass `--no-final-snapshot`, keeps one last snapshot.
**Limits:** a clone is a copy of everything on `main`'s `/work`, so it holds whatever was in your repositories. Keep keys out
of `/work` (the next examples show where they go). The encrypted secret store is sealed to its own box and name, so a copy of
it does not open elsewhere ([ADR 0018](../adr/0018-secrets-are-encrypted-and-out-of-the-agents-reach.md)). Clone is not
supported on Hetzner Cloud, which cannot make a volume from a snapshot; use `create --profile` there.
**Status:** Works (AWS: snapshot, clone and destroy ran end to end on a real box). Hetzner: Preview, without clone.

## 2. An agent with no keys in reach

**You want:** an agent that can build and test your project and talk to its model, but cannot read a single key.

1. Add your model provider once. The key is read from standard input and never shown again:
   ```
   ozbox models add work --kind anthropic --key-stdin
   ```
2. Import the project's **non-production** `.env` keys into the box's encrypted store. Run it first without `--yes` to see
   the names and fingerprints (never values); add `--yes` to store them. If the box's dashboard has a second factor, the
   import asks for its own approval (see **Approving an import** below): nothing to copy. The file is read the way a `.env` file is normally read (like python-dotenv and Docker Compose): quotes around a value are removed, `export` is accepted, a trailing ` # comment` is ignored, and a quoted value may run over several lines (a PEM key, a JSON document). **Any value can be stored: spaces, quotes, backslashes, JSON, several lines, non-English text.** `ozbox env run` hands the program exactly what the file said. A value the plain format cannot hold is stored encoded (the preview marks it `stored encoded`); a value that is plain stays as it was, so nothing already stored changes. Only a blank value, one with a NUL byte, one over 96 KB, or a quote that is never closed is skipped, and listed with the reason by name only; a name that is not a valid variable name is shown as `line N`. Every key is checked before any is stored, so a skipped key never leaves the others half imported; if the disk itself refuses part-way, run the import again (the same names are simply written again). A box made from an older image cannot take encoded values: the import says which keys need `ozbox upgrade` first. A `--dry-run` shows the preview and sends or stores nothing, even with `--yes`.
   ```
   ozbox secrets import .env.staging --project shop --env staging --box main
   ```
   **What the result tells you.** Every entry of the file ends in exactly one place, and the last line adds them up, for example
   `73 entries: 72 stored, 1 duplicate (line 40 kept, line 12 ignored)`: *stored* (or *ready to store* in a preview), *held back*
   (production-looking and not allowed), *skipped* (with the reason beside the name: a blank value, a name that is not a variable
   name and why, a line that is not `NAME=value`, a value the store cannot hold), *duplicate* (a name that appears again: the
   **last** line is kept, as a shell and Docker Compose do, and the lines ignored are named) and *unchanged* (already stored with
   the same value, flag and mark; reported for an import to this computer's store, not for `--box`, which does not say). `--json`
   carries the same account in `summary`, `duplicates` and `rejected_lines`, and an `outcome` on every key. Values are never
   printed; a line that is not a valid name is shown only as its line number.

   **A production file.** In an environment named `production` every key is production-looking, and none is stored unless you
   allow it. Name keys one at a time with `--allow-live NAME` (repeatable), or allow every production-looking key in the file
   with `--allow-live-all` (the two cannot be used together). Either way the keys are listed first, a person at a terminal
   types the project's name to confirm, and a script is refused with the exact command to run yourself. The keys stay flagged and
   no agent's command is ever given them.

   **Approving an import (Preview).** On a box whose dashboard has a second factor, `ozbox secrets import --box ... --yes`
   does not need a code. It files an approval request on the box for exactly these keys (names and salted digests, never the
   values), prints `Waiting for approval in your dashboard: ...`, and waits:
   1. Open **Approvals** in the box's dashboard (a push or chat message says a request is waiting, if you set one up; a chat
      app never approves). The card lists the project, the environment and every key name.
   2. Tap **Approve with passkey**, or, if your account has no passkey, **Use an authenticator code** and type the six digits.
      An authenticator code may approve any request, Production included (owner, 2026-11-17), but a passkey is offered first
      and an account with a passkey must use it. A code is weaker: it is not tied to the request the way a passkey is, so
      type it only into your own dashboard's address.
   3. The waiting command goes on by itself and stores exactly what was approved. A key changed after the approval is refused.

   For a **non-Production** environment (`dev`, `development`, `staging`, `test` or `e2e`) the command also asks
   `Approve it now? [y/N]` when this computer holds an approval key: answer `y` and the key approves it here instead. A
   **Production** import (any other environment, or a key whose name says production) is approved **only on the dashboard**,
   with your passkey or authenticator code: the command does not offer this computer's key, and the box refuses that key if
   it is tried anyway. The same holds for a declaration whose commands take secrets from a Production environment.
   An import into `staging` whose key names say production or live, or whose values are live-mode keys (`sk_live_…`) or production
   addresses, is a Production import too. This computer's key also never approves a declaration or the box's own settings (its
   first-time dashboard code, its store key's escrow, its tunnel token, who may approve): use a laptop key that needs a touch,
   root on the box, or the dashboard where it offers the change.
   `--wait MINUTES` (1 to 30, default 30) limits the wait. Ctrl-C or running out of time stores nothing and changes nothing;
   the request expires by itself, and running the command again files a new one.

   **The fallback: an approval code.** `--approval CODE` still works: ask the dashboard for a code (**Settings**, **Secrets**,
   after your passkey or authenticator) and pass it. A code made with this computer's own key (`ozbox secrets approve`) never
   approves Production: the box refuses to make one, and refuses one at import, and says where to approve instead. A box from
   before approval requests answers the import with that same sentence; `ozbox upgrade` it to get the flow above.
   **The other approved changes work the same way (Preview).** With no `--approval`, `ozbox env policy set FILE --project
   <p> --box <name>` (a declaration), `ozbox dashboard install <name> --token-stdin` (a new tunnel token for the box's
   dashboard) and `ozbox box-secrets <name>` on Hetzner (the box's own secrets declaration) each file a request for exactly
   that change, say `Waiting for approval in your dashboard: ...`, and go on once you approve it there. These are approved
   **only on the dashboard** (passkey or authenticator code); this computer's key is never offered for them. The box binds
   each request to what it approves: the declaration's own text and its project, the token's digest (never the token), the declaration's
   vault address. `env policy set` takes `--wait MINUTES`; the other two wait up to 30 minutes. A guard override filed on the
   box already waits for the dashboard ([ADR 0041](../adr/0041-one-approval-model-a-request-the-box-files-a-person-decides-and-the-box-hands-on.md)).
   **Not yet:** the dashboard does not take a `.env` file itself (importing from the browser is planned); `ozbox tunnel setup`
   run on the box itself, removing a tunnel token, placing a vault token and a host guard change still use a code.
   These keys go to the box through its **ingress account**, not the box user's: the first request pins the box's key on your
   computer (and prints its fingerprint), and every request after it is sealed to that key, so a process on the way sees only
   ciphertext. A box made before this was added is refused with a sentence that says what to do (`ozbox upgrade <box>` gives it the account, on AWS and on Hetzner; if its store's key is in a file the one-time cost is a new secrets store); the old route is not used
   instead ([ADR 0029](../adr/0029-production-secrets-have-no-standing-access.md), Amendment 9).
3. **Enrol a second factor first** (a passkey in the dashboard, or make the box with `ozbox create` from a computer with a keychain).
   Before one exists the box cannot tell you from an agent, so it refuses any declaration that gives a command a secret, and
   hands none out: an agent could otherwise declare a command of its own before you do and receive the keys you imported. A
   declaration with no secrets (a plain build or test command) is accepted without one. Then declare what each named command may receive, from a small JSON file, then run it by name (on the box; an agent reaches it
   through the tool host's staging read, example 7):
   ```
   ozbox env policy set shop-policy.json --project shop --box main
   ozbox env run --project shop --env staging --named test -- npm test
   ```

The agent never holds a provider key. It is given a **per-run token** that works for one run, one provider and the spend
that run may still use, and a **credential broker** adds the real key to each request
([ADR 0017](../adr/0017-credential-broker-per-run-tokens.md)). The project's keys reach only the command that the
declaration names, as a separate system user (one per command that receives a secret) that the agent cannot read the memory of, and what the
command prints comes back with every known secret value removed.

**Underneath:** secrets are sealed with AES-256-GCM, each under its own data key, wrapped by a key held outside the disk
(your cloud's key service for a fleet, the keychain on a laptop). They belong to a separate system user, and the box user
reaches them only through sockets that cannot read a value back. A secret in a command-line argument is refused.
**Limits:** model providers that use your cloud account instead of a key (Bedrock, Azure OpenAI, Vertex AI) are not
brokered yet, so a run that needs one waits with that reason. A laptop has no second operating-system user, so the
separation there is weaker than on a box.
**Status:** Preview.

## 3. A network that only reaches what you declared

**You want:** a poisoned test, or a prompt-injected agent running your tests, to be unable to send your data anywhere.

Put the hosts a project's commands may reach in its declaration:

```
{
  "dir": "/work/projects/shop",
  "writable": [".next", ".auth", "test-results"],
  "tools": [{"name": "node", "sha256": "<tool digest>"}],
  "browsers": ["chromium"],
  "browser_digests": {"chromium-1169": "<digest>", "chromium_headless_shell-1169": "<digest>", "ffmpeg-1011": "<digest>"},
  "commands": {
    "e2e-mint": {
      "allow": ["SERVICE_ROLE_KEY", "PUBLIC_API_URL"],
      "env": [{"name": "SERVICE_ROLE_KEY", "as": "E2E_SERVICE_ROLE_KEY"}, "PUBLIC_API_URL"],
      "argv": ["node", "tests/helpers/mint-storage-state.mjs"],
      "envs": ["staging"],
      "pin": [
        {"file": "tests/helpers/mint-storage-state.mjs", "sha256": "<digest>"},
        {"file": "tests/helpers/mint-retry.mjs", "sha256": "<digest>"}
      ],
      "pin_tree": [
        {"path": "node_modules/@vendor/client", "sha256": "<digest>"},
        {"path": "node_modules/@vendor/auth", "sha256": "<digest>"}
      ],
      "vars": {"E2E_USER_EMAIL": "e2e-staff@example.com"}
    },
    "app-build": {
      "allow": [], "argv": ["npm", "run", "build"],
      "vars": {"NEXT_PUBLIC_APP_URL": "http://localhost:3100"}
    },
    "app-start": {
      "allow": [], "service": true, "port": 3100, "health": "/",
      "argv": ["npm", "run", "start"],
      "vars": {"PORT": "3100", "NEXT_PUBLIC_APP_URL": "http://localhost:3100"}
    },
    "e2e-run": {
      "allow": [], "browser": true, "argv": ["npx", "playwright", "test"],
      "vars": {"E2E_SESSION_FILE": ".auth/staff.json", "E2E_ALLOW_WRITES": "1"},
      "pass": ["E2E_SPEC"]
    }
  }
}
```

Get the digests **on your own computer**, from your own checkout at the commit the box has (`git rev-parse HEAD` in the project
folder there), paste them in, and save the declaration. They are part of what your approval covers. A digest taken on the box only
freezes what is there now, which an agent that has been working there may already have changed, so `pin` refuses to run on a box
unless you add `--on-box`, and off the box it needs `--commit` and a clean checkout at that commit. `--entry` follows the script and
prints every file and package folder it loads, so you do not have to find them. A tool is digested by fetching the catalog's Linux release of the version
you name for the box's architecture (`--release`, `--arch amd64` or `arm64`, amd64 by default), checking the download against the
catalog's checksum, and extracting it the way the box does; a folder you extracted yourself works too (`--tool node=DIR`). A browser
is digested from Playwright's own Linux build, downloaded here from its CDN (`--revision KIND=N`, the number in the cache folder's name,
once for each folder the browser needs: `chromium=1169 --revision chromium_headless_shell=1169 --revision ffmpeg=1011`; one left out is
refused, and so is a declaration with no digest for a folder its browser needs), or from a cache you downloaded yourself. The CDN
address must be https, and a redirect to http is refused. Playwright publishes no checksum, so
the command prints the download's hash for you to compare with a second download; what the digest then proves is that it is of what
Playwright's server sent over HTTPS, and on a box where it does not match, the browser is simply not copied. A browser cache
downloaded on a Mac holds Mac builds and never matches a Linux box.

```
ozbox env policy pin --dir ~/shop --commit <the box's commit> --entry tests/helpers/mint-storage-state.mjs
ozbox env policy pin --dir ~/shop --commit <the box's commit> --tool node --release 22.20.0 --arch amd64
ozbox env policy pin --dir ~/shop --tool node=./node-v22-linux-x64
ozbox env policy pin --dir ~/shop --browser chromium --revision chromium=1169 --revision chromium_headless_shell=1169 --revision ffmpeg=1011 --arch amd64
ozbox env policy pin --dir ~/shop --commit <the box's commit> --browser chromium --browser-cache ./ms-playwright
ozbox env policy set shop-tests.json --project shop --box main
ozbox env run --project shop --env staging --named e2e-mint -- node tests/helpers/mint-storage-state.mjs
ozbox env run --project shop --env staging --named app-build -- npm run build
ozbox env run --project shop --env staging --named app-start --start
ozbox env run --project shop --env staging --named e2e-run --pass E2E_SPEC=tests/login.spec.ts -- npx playwright test
ozbox env run --project shop --env staging --named app-start --stop
```

What each part does:

- **`vars` and `pass`** are plain settings, never secrets. A name that decides how a program starts or where it looks for code
  (`PATH`, `NODE_OPTIONS`, `LD_PRELOAD`, a proxy) is refused, and a value that looks like a key, or holds one of the project's stored
  secrets, is refused. A secret still goes through `allow` and `env`, and nothing here widens it.
- **`as`** renames a received secret, so the stored name (`SERVICE_ROLE_KEY`) stays the one you imported and the command sees the
  name it expects.
- **`pin` and `pin_tree`** make the key reach only what you approved. The first time a command runs, the box reads each file and
  folder once, checks its SHA-256 against the digest you computed, and keeps a read-only, root-owned copy named by that digest. The
  command runs that copy. A file that differs from your digest stops the run and says which (a link on the way counts too); five
  of these in a minute pause the project for five minutes.
- **How big a declaration may be.** A declaration is kept as a record, not as a secret, so a real application's (one service, a
  folder pin for each package its build traced, a few file pins and a tool, about 7 KB) saves as it is. The limit is 256 KB of the
  compact JSON; over it, `env policy set` says the size and the limit and sends nothing. Each part also has a count: 64 commands per
  declaration, 16 pinned files and 64 pinned folders per command, 32 plain variables per command (`vars`, `pass` and `public`
  together), 16 tools, 3 browsers, and a plain variable's value of at most 512 characters. Everything the box would refuse is
  checked on your computer first, so a declaration it would refuse never uses up your approval code.
- **A command that receives a secret runs in a private view of `/work`.** Inside the command's own mount namespace `/work` is an
  empty, read-only tmpfs, and only what you approved is put back in it, at its own path: the pinned files and folders (root-owned
  copies) and your `writable` folders. So the command sees **no folder above the project and no other project**: a `package.json`
  or `node_modules` an agent wrote next to or above the project (Node looks there after the project folder, for a package's own
  name and for an optional package such as `ws`'s `bufferutil`), an `.npmrc` or a hook file is absent, and an import of it fails.
  Every folder on the way to the project is a root-owned folder of that tmpfs, and the command never opens the live path, so a
  folder on it cannot be swapped for a link while the command starts. After the first run the box does not read the live folder
  at all for such a command, and the command's user is granted nothing on it (it only ever sees the copies, plus its writable
  folders). Your project's own `package.json` and any on the way down to the script are pinned with it, so the file that scopes the
  script is the one you approved. A writable folder that is missing or is a link when the command starts stops the run, naming the
  folder: create it first. A writable folder may not be the project folder itself, hold a `node_modules` (or a Python `site-packages`,
  `dist-packages` or `__pycache__`), overlap a pinned folder, or sit on or inside the folder of a pinned file that is below the project folder (a file pinned at the project's top does not make every top-level folder off limits, because Node never looks for an imported package in the script's own folder): such a folder is bound from the
  live project, so code an agent wrote in it would be found before the pinned copy. The declaration is refused when it is written and
  the command again when it starts. The command takes exactly its declared words: no `--import`, `-r`, `--env-file` or `-e` that you did
  not approve. It must pin at least one file, and its program must be `node`: only Node scripts can be pinned today. A command that receives a secret with any other program (`python3`, `sh`, a path to `node`) is refused when the declaration is written and again when it starts, because the box models Node's lookup of the code a script imports and no other program's (Python puts the script's own folder on its lookup path, so a writable folder next to a pinned module would be imported in its place). `npm run` is refused for the same reason: a package script is not covered by a pin. To use another language, mint the secret in a Node script. The words must be exactly `node FILE`, where FILE is a pinned script ending in `.js`, `.mjs`, `.cjs`, `.ts`, `.mts` or `.cts`, and no option may come before it (`node tests/mint`, `-e`, `-p`, `--import` and `--require` are refused, since each loads code the pin does not follow); words after the script are the script's own. A script that receives a secret may not import `child_process`, `worker_threads`, `cluster`, `vm`, `module` or `inspector`, and may not use `getBuiltinModule`, `createRequire`, `require.main`, `mainModule`, `execve`, `dlopen` (anywhere, so destructuring and `process?.` are refused too), `process.binding`, `.constructor.constructor`, `module` as anything but `module.exports` (so `module.paths` and `const m = module` are refused), or `require` as anything but a direct `require('...')` call. A file in a pinned project folder may not be, or sit behind, a link. A helper that loads modules through `createRequire` cannot be part of a secret command: use plain `import`. Every project file the script reaches is read and followed, including those in a pinned project folder (a file there may not import a writable folder); only a package pinned under `node_modules` is trusted as the bytes you approved and is not read. This is a check of the imports the box can read, not a sandbox: it covers what the script loads, and a program the script starts is outside the pin, which is why those modules are refused. It does not see an indirect `eval` or `Function`, computed member access such as `process['binding']` or `Reflect.get(process, 'binding')`, or a native add-on. A computed `import(x)` or `require(x)` is refused, not unseen.
- **The box also reads the script** (the approved bytes) and **refuses to start it** unless every file it imports and every package
  it needs is pinned. That refusal is real, but it is a **static reading, not an engine**: a computed `import(x)`,
  `createRequire`, `eval`, an extensionless import, an absolute path or a `#` import is refused rather than guessed, and what a
  reading cannot see (a package that loads another by a name built at run time) is stopped by the private view, which contains
  only what you pinned. Its tools must be pinned by digest, it cannot drive a browser, none of its words may name code in a writable
  folder, and it names the `envs` it may draw from (the caller chooses the environment on every run). Under pnpm,
  `node_modules/<name>` is a link into `.pnpm`, which a pin refuses: pin an npm install. Anything the command reads from a
  writable folder (a config, a cached URL) is the agent's input, so do not make a secret's destination depend on it.
- **What the caller may choose is narrow.** A value passed with `--pass` to such a command is letters, digits and `_ - , =` only,
  never a host name, address or URL; the project's egress must name exact hosts (no `*.`), so no value of the caller's can aim a key
  at a host the caller controls. List your own production identifiers in `production_ids` (a database project reference, a host): a stored
  value or passed value that contains one, or whose JWT payload does, is refused. A value stored as production anywhere on the box
  is production under every name, and a file whose name says production is not imported under another environment.
- **It runs as a user of its own** (named from the full 128-bit hash of project and command; an existing user that setup did not
  make for exactly that command is refused, and any change to the declaration (a pin, the words, the names it may take, its environments, its egress) stops the run units and every process of its runner users first, repeating until none is left, so a process that forks cannot keep the old approval). A server, a
  browser or any other command runs as a different user, so none of them can read the key from `/proc/<pid>/environ`. (Marking the process non-dumpable is done while it holds the key, but the kernel resets that when
  the command starts, so the separate user is what protects it; on a box with systemd 257 or later each unit also cannot see
  another's processes.) Swap is off and core dumps are off for every runner.
- **A `service`** runs as a unit of its own on this machine's loopback, until `--stop` (or 4 hours). `--start` waits
  for its health check; `--status` says whether it answers. Another command in the project reaches it at `127.0.0.1:3100`.
  The box's loopback is shared, so treat it as a development server. A service with no secret runs as the project's runner.
- **A service can receive a secret** (`allow` and `env`, like a command). It is held to every rule a secret command is held to: a
  pinned `node FILE`, an `envs` list the caller must pick from, exact egress hosts, no browser, no `--pass`. Starting one applies those
  rules before any secret is looked up. It runs as the user of its own that a secret command gets, in the same private view of the
  project. The secret reaches it as a **systemd credential**, never as an environment line of the unit, an argument or a unit property,
  so `systemctl show` holds a path and not the value: the program reads `$CREDENTIALS_DIRECTORY/NAME`. A program that expects an
  environment variable adds `"credential_env": true`, and the box starts it through a small step (`ozbox secrets exec-cred`) that sets
  each credential as a variable of the same name; the value is then in the program's own environment, which only its own user can read.
  For the moment systemd takes to load it, the value is a file in a root-only folder under `/run/ozbox-cred`, deleted as soon as the
  unit has started (and after a failed start and a `--stop`). `/run` is memory and memory can be swapped, so a box without encrypted swap
  is outside what that claims. **What this does not do:** the box user can reach a service's port, so the agent can make the server
  use its key; a service that holds a key reaches only the hosts the project declares (`egress`), through a proxy
  that is its own unit and lives exactly as long as the service, and only that service's user may connect to it (a kernel rule on the
  user, and the proxy checks the same for itself); with nothing declared, or no secret, it reaches this machine's loopback and nothing
  else (a program must honour `HTTPS_PROXY`). A project that declares `tcp` destinations cannot start a service that holds a key yet: a
  raw tunnel is held back until the box has proven its ports cannot be taken by another user; what the server prints goes to the journal, and only `--status` is scrubbed of stored
  values; and `npm run start` cannot receive a secret, because a package script is not covered by a pin.
- **`public`** names stored values that you marked public when you imported them (`ozbox secrets import .env.staging --project shop
  --env staging --public NEXT_PUBLIC_ANON_KEY --public NEXT_PUBLIC_APP_URL --box main`): a public URL, or a hosted backend's anonymous
  key, which looks like a secret and is public by design. A command or service that lists the name (and an `envs` list) receives it as
  plain environment. The mark is your word, but only for a known public kind: a JWT whose payload says `"role":"anon"`, a value
  starting `pk_test_`, `pk_live_`, `sb_publishable_` or `phc_`, or plain text such as a URL or an id. Anything that looks like a secret
  is refused (`sk-ant-`, `sk-proj-`, `sb_secret_`, a signed-in user's token, a service-role key, a PEM block and the like), and so is a
  name that says secret and a production-looking value. Nothing is imported when one is refused, and the check runs again when the
  value is handed out. A box with no second factor yet refuses a mark: import the value ordinarily, or enrol first. A public value is
  plain text (letters, digits and `. _ : / @ + , = -`, up to 2048 characters).
  Because it is public, a service shows it in `systemctl show`. A box that cannot read the mark tells you to upgrade first.
- **`tools`** are copied read-only into a folder named by the digest of its content, so one project cannot change what another runs.
  A project with a command that receives a secret must give each tool's digest, computed on your computer (`--tool node=DIR`). The
  box copies the box user's install only when it matches that digest, from the same read, so an install an agent changed is not
  copied. (The box does not yet install a tool itself from the catalog's release; the box user's install is the source, and your
  digest is what decides whether it is trusted.)
  **`browsers`** are Playwright's installed revisions, copied only when you approved that revision's digest
  (`browser_digests`); a revision the box user planted is not copied. Only a command marked `"browser": true` is told where they
  are. Install the browser as the box user first (the catalog's `playwright-browsers` entry does it; see [the tool catalogue](../tools.md)).
- **The folder** is readable by the command's own runner user and nothing else of yours is: it cannot see the box user's home, and
  `.git` is out of reach. Removing the declaration takes the access back.

**Underneath:** [ADR 0029](../adr/0029-production-secrets-have-no-standing-access.md) Amendments 10 and 12.
**Limits:** a service that receives a secret has the limits listed above, and Amendment 12 lists what to try on a real box first (the
credential from `/run/ozbox-cred`, `systemctl show`, the journal). A one-shot run ends after 30 minutes. Nothing here is proven on a real box: the private view (an empty
read-only tmpfs over the project folder with files and folders bound back into it) relies on systemd 255 on Ubuntu 24.04 creating
the bind destinations inside it, and the whole path is to be tried on one. Each unit does not have its own process space on that
systemd (the separate users are what protect the key). Whether a crash writes the command's environment to the system journal, and
whether the box user can read it, is to be checked. The session the minter writes (`.auth`) is a file the agent can read; the key is not. A box from before this format refuses the declaration (it says to
`ozbox upgrade`). Nothing here is proven on a real box yet: the browser under this sandbox and the ACL on 0600 files are the first
things to try.
**Status:** Preview.

## When a per-request sandbox is the better tool

Oz Box boxes are real virtual machines that start in minutes and bill by the hour in **your** cloud account. That is the
right shape for an agent that works for a while and keeps its state. It is the wrong shape for some jobs, and a
purpose-built sandbox service (a category of hosted products that run short pieces of untrusted code in isolated
containers or micro-VMs) is the better tool for those. Compare by properties, not brand:

| | An Oz Box | A per-request sandbox service |
|---|---|---|
| **Starts in** | minutes, whether a new box or a resumed one | typically milliseconds to seconds |
| **Lives for** | hours to months | typically one request, or a short session |
| **State** | a persistent encrypted `/work` disk that survives pause, resize and upgrade | usually none, or a short-lived scratch area |
| **Who hosts it** | you: your cloud account, your network, your keys; the project runs nothing | the service's provider |
| **Cost shape** | an hourly machine price while running, plus the disk while paused, billed by your cloud | usually per execution or per second of use |
| **What runs in it** | a full workstation: a browser, editors, your whole toolchain, long builds | a snippet, a script or a short job |
| **Isolation** | a machine of its own per box, with no inbound port and no `sudo`; agents on the same box share its user and are separated by memory and time limits, so give an untrusted agent its own box (a clone) | a container or micro-VM per request, built for strangers' code |

Choose a per-request sandbox when you run a high volume of short, stateless executions of untrusted code, such as
evaluating a model's generated snippet on every chat turn or grading submissions, where start time in milliseconds and a
price per execution matter and nothing needs to persist. Choose Oz Box when an agent needs a place to work: a repository
checked out, tools installed, a browser and a test suite, files that are still there tomorrow, your own account's network
and billing, and a person who can step in. The two combine well: an agent on a box can still call a sandbox service for
snippets, through the declared hosts in example 3.

## What is not done yet

- **A real cloud box and a real agent.** The agent-side controls are tested with fake boxes and a simulated agent, and a run
  on a real box goes through the box daemon, but none of it has been exercised end to end on real cloud hardware yet.
- **A network allow-list for the whole box.** Egress is limited for a project's declared commands, not for the agent's own
  shell.
- **A log writer the agent cannot reach.** The audit chain detects an edit; it does not stop one.
- **An engine-side permission hook.** The ask list is enforced by refusing those commands up front.
- **Model providers that use your cloud account** (Bedrock, Azure OpenAI, Vertex AI) through the credential broker.
- **Signed skills** from a publisher, and **memory shared between computers** as a feature.
