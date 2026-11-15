## What and why

<!-- One logical change. What does it do, and why? Link the issue if there is one. -->

## Checklist

- [ ] **Every commit is signed off** (`git commit -s`): the DCO check fails otherwise. See CONTRIBUTING.md.
- [ ] Tests cover the new behaviour (CI runs on Linux), and `cargo fmt`, `clippy -D warnings` and `cargo test` pass.
- [ ] The docs say so if anyone could notice the change (command, flag, screen, default, security property), and the
      **Works / Preview / Planned** marks are honest: **Works** only if proven on a real box or account, otherwise **Preview**.
- [ ] No key, token, account id, private hostname or private document is added, and no code comment points at a document that
      is not in this repository. `scripts/public-safety.sh` and `scripts/no-build-docs.sh` print "clean".
- [ ] A security-relevant change updates the relevant ADR (and its "what is not covered" list) or adds one.

<!-- A security problem is not reported here: use the Security tab (private vulnerability reporting). -->
