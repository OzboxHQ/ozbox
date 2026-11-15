# 0008 — Light dependencies in v0.1

**Decision.** v0.1 adapters call provider CLIs (`aws`, `tofu`) through an argv-only command runner and small HTTP clients,
instead of full cloud SDKs.

**Why.** Full SDKs add minutes and gigabytes to every build. Argv arrays (never shell strings) keep injection impossible, and the
runner is mocked in tests.

**Cost.** Parsing CLI JSON output; revisit once builds run on boxes.
