# 0010 — The dashboard is reached through a tunnel you bring yourself

**Decision.** `ozbox serve` always listens on loopback only. To reach it from elsewhere, the person runs an outbound tunnel
with their own account, token and domain: Cloudflare Tunnel, Tailscale Funnel or Serve, Caddy on a server they rent (behind a
reverse SSH tunnel the dashboard dials out), or ngrok. Giving `--public-url` turns on sign-in for that address (a passkey, or an
identity-aware proxy whose token is verified), and the address is the one source for the passkey's relying-party id, the allowed
Host and Origin, the cookie scope and the redirects. A tunnel token is write-only in the secret store and reaches the tunnel's
program in its environment, never in an argument list. Oz Box ships no default domain, account or relay.

**Why.** It keeps ADR 0005 true for the dashboard too, and it keeps the project free of any service we would have to run or
trust: people host their own dashboard on their own domain.

**Cost.** Each provider has its own account to set up, so the dashboard carries a step-by-step guide for each. A dashboard that
runs on a box goes down when that box is upgraded or paused, so it is best run from a machine that is not one of the fleet.

**The dashboard's program.** `ozbox dashboard install` never trusts an unverified program, and it prefers what is already on the
box. A box built from an Oz image carries `/usr/local/bin/ozbox`, and that image's release lists the program's sha256 in its
signed manifest (verified on your computer with cosign against the image workflow's identity). When the box's program has the
listed hash it is used as it is: nothing is downloaded or sent. Otherwise the image release's signed `ozbox-linux-<arch>` file is
downloaded on your computer (with your own GitHub sign-in, so a private repository works and the token never reaches the
box), checked against the manifest, sent to the box, and checked again there; then a CLI release of the same version, if one was
published; then `--binary-url` with `--binary-sha256` for a program you host. `--release` takes `0.3.0`,
`image-v0.3.0` or `v0.3.0` (the default is the box's own image release), and the plan says which source it used.
