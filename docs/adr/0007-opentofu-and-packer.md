# 0007 — OpenTofu and Packer

**Decision.** Infrastructure is OpenTofu modules, one per provider, with one state workspace per box. Images are built by Packer
and cloud-init from the same provisioning steps on every provider.

**Why.** Boxes are created and destroyed often; a declarative plan/destroy is safer than hand-written scripts. OpenTofu is
open source under a foundation.

**Cost.** OpenTofu becomes a runtime dependency of the CLI for lifecycle commands.
