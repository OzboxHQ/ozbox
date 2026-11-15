# Writing a plugin

A plugin adds a **provider** (a place boxes run) or a **tunnel** (a way to reach the dashboard) without changing Oz Box. The
decision is [ADR 0031](adr/0031-plugins-are-programs-that-speak-a-versioned-protocol.md). Protocol version: **1**.

A plugin is a folder with two files:

```toml
# plugin.toml
name = "my-cloud"          # lowercase letters, digits, hyphens; at most 32
kind = "provider"          # or "tunnel"
api_version = 1
license = "Apache-2.0"     # required: your licence, as an SPDX identifier; shown before anyone adds or approves it
program = "my-cloud"       # a plain file name in this folder
description = "Optional."
```

## The protocol

A plugin is a separate program that speaks **JSON-RPC 2.0** on standard input and standard output, one message per line, the
way language servers and MCP servers do. Oz Box starts it, so any language works, and a plugin that crashes or hangs cannot
corrupt Oz Box: every wait has a time limit and a plugin that is late is killed.

For each call the host starts the program with an empty environment (only `PATH`) and the plugin's folder as its working
directory, then writes:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"api_version":1,"host":"ozbox"}}
```

and expects `{"jsonrpc":"2.0","id":1,"result":{"api_version":1}}` back (a plugin that speaks another version answers with an
error and is not used). Then it sends the request and reads the answer, then closes standard input, which is the plugin's cue to
exit:

```json
{"jsonrpc":"2.0","id":2,"method":"list","params":{}}
{"jsonrpc":"2.0","id":2,"result":[]}
{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"plain words for a person, never a secret","data":{"kind":"unsupported"}}}
```

Lines are at most 1 MiB; a call has a two-minute limit. Anything on standard error is dropped. Error kinds, in `data.kind`
(with the JSON-RPC number): `unsupported` (-32601), `bad_request` (-32602), `not_found` (-32001), `already_exists` (-32002),
`invalid_state` (-32003), `failed` (-32000). Unknown fields are ignored on both sides; within version 1 a field is only ever
added. The methods below are the `method` values.

### Provider operations

| method | params | result |
|---|---|---|
| `describe` | | `{"id": "...", "capabilities": {"resize": "power_off_resize", "online_disk_grow": true, "disk_shrink": false, "snapshots": true, "sizes": ["S","M"]}}` |
| `machine_choice` | `{"size": "M"}` | `{"machine_type": "...", "note": null}` |
| `list` | | a list of box records |
| `create` | `{"spec": ..., "machine_type": "..."}` | the box record |
| `destroy`, `power_off`, `power_on` | `{"record": ...}` | `null` |
| `set_size` | `{"record": ..., "size": "L", "machine_type": "..."}` | `null` |
| `grow_disk` | `{"record": ..., "gb": 300}` | `null` |
| `snapshot` | `{"record": ...}` | `{"id": "..."}` |
| `set_resume_after` | `{"record": ..., "on": true}` | `null` |

Box specs and records have the JSON shape of `ozbox list --json`. Rules a provider keeps (the provider interface, ADR 0003):
creating what already exists with the same size is a no-op, destroying what is gone is a no-op, snapshots are new each time, and
anything the provider cannot do is `unsupported`, never half done. Workflow features that need a provider's own API (the real-bill
view, forgotten-resource listing, image upgrades) are not available for a plugin.

### Tunnel operations

| method | params | result |
|---|---|---|
| `describe` | | `{"program": "...", "public": true}` |
| `start` | `{"port": 7878, "public_url": "https://..."}` | `null` |
| `stop` | | `null` |
| `status` | | `{"state": "stopped" \| "running" \| "failed", "code": null}` |
| `health` | `{"public_url": "https://..."}` | `{"ok": true, "code": "ok"}` |

## Writing one in Rust

The `ozbox-plugin` crate has the types and `sdk::serve`. Two complete examples are in `crates/ozbox-plugin/examples/`
(`dir_provider.rs`, a provider keeping boxes in a file, and `echo_tunnel.rs`).

## Writing one in another language

`examples/plugins/python-tunnel/` is a complete tunnel plugin in Python that uses no Oz Box library: about sixty lines that read
lines, answer lines and keep their state in a file. The tests run it through the same host as the Rust examples.

## Using one

```sh
ozbox plugin add ./my-cloud          # copies it in and shows the program's SHA-256; nothing runs
ozbox plugin approve my-cloud        # records that exact hash
```

Then select it in the configuration (`provider = "plugin"` and `plugin = "my-cloud"`). A program that changes after approval is
not run until you approve it again. A plugin runs with your own permissions: approve only what you have read. Running a plugin as a separate restricted user is
not built yet.

Selecting a tunnel plugin from `ozbox serve --tunnel` is not wired yet; the host side (`ozbox_plugin::host::TunnelPlugin`) and
the protocol are in place.
