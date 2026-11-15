# Contributing to Oz Box

Thank you for your interest. Oz Box is in Beta and **issues and pull requests from everyone are welcome**: bug reports,
fixes, tests, documentation, and well-argued feature ideas.

## Before you start

- **A bug?** Open an [issue](https://github.com/OzboxHQ/ozbox/issues/new/choose) with the bug template: what you ran, what you
  expected, what happened, your `ozbox --version`, and the provider (AWS, Hetzner or the demo). **Never paste a key, a token or
  private data.**
- **A security problem?** Do not open an issue. Follow [SECURITY.md](SECURITY.md).
- **A feature or a bigger change?** Open a feature request (or a Discussion, once Discussions are on) before you write the
  code, so we can agree on the shape. A decision that changes a security boundary or a trade-off needs an
  [ADR](docs/adr/README.md); say so in the request.
- **A small fix** (a typo, an obvious bug with a test) can go straight to a pull request.

Be kind: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies everywhere.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. The sign-off is you certifying, under the
[Developer Certificate of Origin](https://developercertificate.org/), that you wrote the change or otherwise have the right to
submit it under the project's license (Apache-2.0), and that you understand the contribution is public and kept with your
name. Add it with `-s`:

```
git commit -s -m "fix: say what happened when a resize is refused"
```

That adds a `Signed-off-by: Your Name <you@example.com>` line, using your `user.name` and `user.email` from git. To fix a
commit that lacks it: `git commit --amend -s --no-edit` (the last one) or
`git rebase --signoff main` (a whole branch), then `git push --force-with-lease`. The **DCO** check on every pull request fails
until every commit has the line.

The sign-off is the whole of the legal step: **no Contributor License Agreement is required.** You keep the copyright in what
you contribute.

The name "Oz Box" and the logo are not part of the license; see [TRADEMARKS.md](TRADEMARKS.md).

## Pull requests

1. Fork the repository, branch from `main`, and make one logical change per pull request, with a clear description of what
   and why. Use conventional commit messages (`fix:`, `feat:`, `docs:`, `test:`, `chore:`).
2. Add tests for new behaviour. Tests that pass only on your machine do not count: CI runs on Linux.
3. Update the docs in the same pull request if anyone could notice the change (a command, a flag, a screen, a default, a
   security property). Keep the **Works / Preview / Planned** marks honest: **Works** means proven on a real box or account,
   not only in CI; a feature you could only test with fakes is **Preview**.
4. Fill in the pull request template. At least one maintainer reviews every pull request before it merges.

### How CI runs on your pull request

CI runs the Rust, dashboard, browser, infrastructure, documentation and safety checks. **For a first-time contributor, a
maintainer has to approve the run** before the workflows start (this is a GitHub setting for fork pull requests, to keep
untrusted code away from the runners). Expect a short wait on your first pull request; later ones from you run straight away.
If a check fails, the log says which; fix it and push again.

### Running the checks on your own machine

You need the Rust stable toolchain (`rust-toolchain.toml` selects it), Node 22, and a C compiler. Run one heavy command at a
time; a full build is large.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

cd packages/dashboard && npm ci && npm run typecheck && npm run lint && npm test && cd ../..

cd docs-site && npm ci && npm run check && cd ..      # only if you touched documentation

scripts/public-safety.sh && scripts/no-build-docs.sh   # each must print "clean"
```

Infrastructure changes also need `tofu fmt -check -recursive infra/` and `infra/tofu/check-no-ingress.sh`. Linux-only code
sits behind `cfg(target_os = "linux")` with a parser tested on fixture text, so the tests run on any system. Never create real
cloud resources from a test.

## What goes in this repository, and what does not

This repository is public, so it holds only what is meant to be read by everyone: the code, the README, the architecture
overview and the decision records ([ADRs](docs/adr/README.md)), the use-case guides, the changelog, and the infrastructure
notes. **Detailed design specs, internal plans, pricing or commercial notes, and anything about a particular company's own
deployment are kept private by the maintainers and are not added here.** A pull request that adds one will be asked to take it
out: put the idea in an issue or an ADR instead. `scripts/no-build-docs.sh` enforces an allow-list of document names, and
`scripts/public-safety.sh` fails on private names, account ids and keys. Use `example.com`, `123456789012` and `/ozbox/<box>/`
as placeholders. In code comments, give the reason in the comment, or point at an ADR; do not point at a document that is not
in the repository.

## Code conventions

- **Rust:** `unwrap()` is denied outside tests and `unsafe` is forbidden. Commands run as argv arrays, never a shell string.
  Env values and keys are secrets: never log, serialize, print or put one in an error.
- **Every change goes plan, then apply** ([ADR 0002](docs/adr/0002-plan-then-apply.md)); a provider implements the one
  interface and passes the conformance suite ([ADR 0003](docs/adr/0003-provider-interface.md)).
- **No inbound network** on any box ([ADR 0005](docs/adr/0005-no-inbound-network.md)); the infrastructure tests fail on one.
- **User-facing text** goes through the message catalogue, English first. The REST API, the CLI's commands and flags and every
  `--json` shape are stable from the first release: add a field, never rename one.

## Community

Questions and ideas: [GitHub Discussions](https://github.com/OzboxHQ/ozbox/discussions) (switched on when the repository goes
public). Bugs and requests: [GitHub Issues](https://github.com/OzboxHQ/ozbox/issues). What is planned: [ROADMAP.md](ROADMAP.md).
