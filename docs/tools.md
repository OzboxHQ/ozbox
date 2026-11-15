# The tool catalogue

`ozbox tools list` shows every tool Oz Box can install on a box; this page is the same list, with how each one is checked.
Tools are installed after the box boots, from pinned sources, and the plan is shown first, and `--dry-run` stops there.
A tool whose source Oz Box could not confirm from the vendor's own documentation is listed too, but carries no install steps
and is never put in a plan.

Every tool installs for the box user and never touches your projects. Boxes run Ubuntu 24.04 on 64-bit x86 or Arm. Nothing here
installs on your own computer: Oz Box installs only on boxes.

## Editors

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `neovim` | Neovim | A fast terminal editor. | the operating system's signed package archive | 30 MB |
| `nano` | nano | A small, friendly terminal editor. | the operating system's signed package archive | 2 MB |
| `micro` | micro | A terminal editor with familiar keys. | the operating system's signed package archive | 12 MB |
| `zed-remote` | Zed remote server | Lets the Zed editor on your own computer open this box. Zed puts its server on the box itself the first time you connect. | installed by the program that needs it, not on the box | 0 MB |

## AI agents

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `claude-code` | Claude Code | Anthropic's coding agent for the terminal. | the vendor's package source, accepted only if its signing key matches the fingerprint the vendor publishes | 220 MB |
| `codex` | Codex CLI | OpenAI's coding agent for the terminal. | a package registry that checks the package's own integrity hash | 150 MB |
| `gemini-cli` | Gemini CLI | Google's coding agent for the terminal. | a package registry that checks the package's own integrity hash | 120 MB |
| `aider` | Aider | A pair-programming agent that edits files in your git repository. | a package registry that checks the package's own integrity hash | 250 MB |

## Local AI (GPU boxes)

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `vllm` | vLLM | Serves an open-weight model from a GPU box on the box's own loopback address, for the whole fleet's engines to use. | a package registry that checks the package's own integrity hash | 9000 MB |
| `ollama` | Ollama | Runs open-weight models from a GPU box on the box's own loopback address. | a download checked against a SHA-256 the vendor publishes | 5000 MB |

## File managers

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `thunar-xfce` | Thunar and a light XFCE desktop | A graphical file manager on a light desktop, for the box's remote desktop. | the operating system's signed package archive | 350 MB |
| `yazi` | yazi | A fast terminal file manager. It is built from source, which takes a few minutes. | a package registry that checks the package's own integrity hash | 900 MB |

## Languages

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `node` | Node.js 22 | The Node.js 22 long-term-support runtime with npm. | a download checked against a SHA-256 the vendor publishes | 190 MB |
| `pnpm` | pnpm | A fast, disk-efficient package manager for Node. | a package registry that checks the package's own integrity hash | 60 MB |
| `bun` | Bun | A fast JavaScript runtime, bundler and package manager. | a package registry that checks the package's own integrity hash | 110 MB |
| `deno` | Deno | A secure JavaScript and TypeScript runtime. | a package registry that checks the package's own integrity hash | 130 MB |
| `python` | Python 3.12 | Python 3.12 with pip and virtual environments. | the operating system's signed package archive | 60 MB |
| `uv` | uv | A very fast Python package and project manager. | a package registry that checks the package's own integrity hash | 60 MB |
| `jupyterlab` | JupyterLab | Notebooks in the browser, for data work. | a package registry that checks the package's own integrity hash | 300 MB |
| `rust` | Rust | The Rust toolchain, managed by rustup. | the operating system's signed package archive | 700 MB |
| `go` | Go | The Go toolchain from Ubuntu (1.22). | the operating system's signed package archive | 250 MB |
| `java` | Java 21 | OpenJDK 21 (headless) for building and running Java. | the operating system's signed package archive | 300 MB |

## Containers and databases

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `podman` | Podman and Compose | Rootless containers with a Docker-compatible command, and Compose. | the operating system's signed package archive | 250 MB |
| `postgresql-client` | PostgreSQL 16 client | psql and the PostgreSQL command-line tools. | the operating system's signed package archive | 30 MB |
| `redis-cli` | Redis CLI | redis-cli and the Redis command-line tools. | the operating system's signed package archive | 5 MB |
| `sqlite` | SQLite | The sqlite3 command-line shell. | the operating system's signed package archive | 3 MB |

## Cloud and infrastructure CLIs

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `github-cli` | GitHub CLI | Work with pull requests, issues and releases from the terminal. | the vendor's package source, accepted only if its signing key matches the fingerprint the vendor publishes | 45 MB |
| `packer` | Packer | Build machine images from a template. | the vendor's package source, accepted only if its signing key matches the fingerprint the vendor publishes | 90 MB |
| `helm` | Helm | The package manager for Kubernetes. | the vendor's package source, accepted only if its signing key matches the fingerprint the vendor publishes | 60 MB |
| `kubectl` | kubectl | The Kubernetes command-line tool. | a download checked against a SHA-256 the vendor publishes | 60 MB |
| `opentofu` | OpenTofu | Infrastructure as code with OpenTofu (the `tofu` command). | a download checked against a SHA-256 the vendor publishes | 220 MB |

## Browsers and test tools

| Id | Tool | What it is | How its source is checked | Size |
|---|---|---|---|---|
| `playwright-browsers` | Playwright and Chromium | Playwright with a Chromium browser for testing web pages. | a package registry that checks the package's own integrity hash | 900 MB |
| `jq` | jq | Process JSON on the command line. | the operating system's signed package archive | 2 MB |
| `ripgrep` | ripgrep | Very fast text search. | the operating system's signed package archive | 5 MB |
| `fd` | fd | A friendly, fast alternative to find (the program is named fdfind). | the operating system's signed package archive | 3 MB |
| `htop` | htop | An interactive process viewer. | the operating system's signed package archive | 2 MB |
| `btop` | btop | A resource monitor with graphs. | the operating system's signed package archive | 5 MB |

## Tools that cannot be installed yet

Some tools are in `ozbox tools list` but marked as not installable, each with the reason: their vendor does not publish
anything Oz Box can check the download against. They are left off this page on purpose, so that every tool above can be
installed as described. One that becomes checkable moves above in a later catalogue.

## OpenTofu

`opentofu` installs the `tofu` command from one pinned release (v1.13.9) on both architectures. The download's SHA-256 is
written into the catalogue; it is the digest in the release's own checksum file, and that file's signature was checked
against the project's release workflow when the version was pinned. `tofu init` downloads providers from the registry the
project names, at the time you run it; Oz Box does not check those.

## Playwright and Chromium

`playwright-browsers` installs three things, in this order:

1. **System libraries and fonts, as root,** from Ubuntu's signed package archive. The list is the one Playwright 1.65.0 itself
   gives for Chromium on Ubuntu 24.04 (what `playwright install-deps chromium` would install), written into the catalogue.
   Oz Box never runs Playwright's own installer as root.
2. **The `playwright` package, pinned to 1.65.0,** with the registry's integrity check. It needs `node`, which is installed
   first if it is missing.
3. **Chromium and its headless shell, as the box user,** into `~/.cache/ms-playwright`. About 340 MB is downloaded and about
   550 MB is written, on top of the libraries. **Playwright publishes no checksum for these builds**, so they come from
   Playwright's own download server over https and are not hash-checked. That is the weakest check in this catalogue. If it
   matters to you, pin the browser's digest in a project's declaration (`ozbox env policy pin --browser ...`), which refuses a
   browser that changed.

Firefox and WebKit are not installed. Add one with `playwright install firefox`; its system libraries are not on the list
above, so install them yourself first.

**On your own computer** Playwright works differently: it keeps browsers in `~/Library/Caches/ms-playwright` on macOS and
needs no system libraries, because macOS has them. A box is Linux, where the browser needs the libraries above, and a box has
no screen, so a headed test needs the virtual display (`xvfb-run`) the list includes.
