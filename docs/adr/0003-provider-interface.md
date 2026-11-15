# 0003 — One provider interface, a fake provider first

**Decision.** Every place a box can run implements the `Provider` trait in `ozbox-core`. A file-backed fake provider is built
first and is what the test suite and the CLI's own tests run against. Lifecycle changes (create, destroy, resize of
infrastructure) go through OpenTofu modules; runtime actions (stop, start, snapshot) go through the provider's API.

**Why.** The CLI, and later the control plane, are tested end to end without spending money or needing credentials. Every real
adapter must pass the same conformance tests as the fake, so behaviour is identical across clouds.

**Cost.** The fake can drift from reality; the conformance suite and nightly real-box tests are what keep it honest.
