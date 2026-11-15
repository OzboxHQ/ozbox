# Reaching your boxes over a tailnet you run

Oz Box can reach your boxes over a tailnet that you run yourself with [Headscale](https://headscale.net), instead of AWS
Session Manager or a Cloudflare tunnel. Nothing is opened inbound on a box (see [ADR 0005](adr/0005-no-inbound-network.md));
the design and its limits are in [ADR 0030](adr/0030-a-tailnet-you-run-yourself.md).

You need a Headscale server you run (on a machine of yours, or a small VM), the Tailscale client on your computer, and boxes
that already run an Oz image with the Tailscale programs installed. Headscale 0.26 or newer is assumed (users are addressed by
id). Every command below shows its plan first; `--dry-run` stops there and `--yes` skips the question.

## Set up

```sh
ozbox mesh setup --control-url https://headscale.example.com --user alice \
  --base-domain tail.example.com            # add --admin-host <ssh name> when Headscale runs elsewhere
ozbox mesh client                            # what to run on this computer to join
```

## Access rules, generated from your boxes

```sh
ozbox mesh policy                            # print the rules
ozbox mesh policy --out policy.json          # for a Headscale that loads a policy file; reload Headscale afterwards
ozbox mesh policy --apply                    # Headscale in database policy mode
```

You may open SSH (port 22) on every box. A box can open no connection to anything unless you say so:

```sh
ozbox mesh allow build dev --port 5432       # build may reach dev on 5432; dev may not reach build
ozbox mesh deny build dev
```

Regenerate and apply the policy after the fleet or a rule changes.

## Join a box

```sh
ozbox mesh join dev --ssh-key ~/.ssh/ozbox_ed25519.pub
ozbox mesh status
```

`join` first reads the access rules the server has loaded and stops unless they are exactly the deny-by-default ones `ozbox
mesh policy` makes from your boxes: Headscale with no rules lets every node reach every other, your computer included. Apply
them first (`ozbox mesh policy --apply`); a server in file mode cannot show them, so after loading `ozbox mesh policy --out FILE`
there, join with `--policy-managed-elsewhere`, which also covers rules you keep yourself.

It then asks Headscale for a key that works once, for one hour, and makes the node carry the box's tag. The key travels on
standard input of an SSH session you already have to the box (it is never in an argument), is used by one command and is
deleted. If you cannot let `ozbox` run the Headscale command, make a key yourself with `headscale preauthkeys create`, and keep
it for the box with `ozbox mesh key dev` (read from standard input; it is used once and removed). Such a key is used only if
Headscale lists it for your user as single use, unused, unexpired and tagged for the box
(`headscale preauthkeys create --user <id> --tags tag:ozbox-dev --expiration 1h`).

## Use it

`ozbox connect dev` writes an SSH entry whose route is the tailnet when `mesh.toml` exists. The dashboard and the web IDE stay on
the box's loopback; forward them over the same connection:

```sh
ozbox mesh forward dev --port 7878           # prints: ssh -N -L 7878:127.0.0.1:7878 ozbox-dev
```

## What has and has not been proven

The commands, policy and join script are tested against fakes. The Headscale command forms and the Tailscale client's
user-space TCP forwarding follow the vendors' documentation and have not been run against a real server and box yet, so
treat a first real join as a trial on one box.
