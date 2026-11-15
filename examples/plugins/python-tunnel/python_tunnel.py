#!/usr/bin/env python3
"""An example Oz Box tunnel plugin, written without any Oz Box library.

Protocol (version 1): JSON-RPC 2.0, one message per line, on standard input and standard output. The host sends
`initialize`, then a request; it closes standard input when it is done. Anything printed to standard error is dropped.
A real tunnel plugin would start and supervise an outbound program in `start`.
"""
import json
import sys

API_VERSION = 1
STATE = "state.json"  # the working directory is the plugin's own folder


def state():
    try:
        with open(STATE) as f:
            return f.read().strip() or "stopped"
    except OSError:
        return "stopped"


def write_state(value):
    with open(STATE, "w") as f:
        f.write(value)


class Failure(Exception):
    def __init__(self, number, kind, message):
        self.number, self.kind, self.message = number, kind, message


def handle(method, params):
    if method == "initialize":
        if params.get("api_version") != API_VERSION:
            raise Failure(-32602, "bad_request", "this plugin speaks protocol %d" % API_VERSION)
        return {"api_version": API_VERSION}
    if method == "describe":
        return {"program": "python-tunnel", "public": False}
    if method == "start":
        if int(params.get("port", 0)) < 1024:
            raise Failure(-32602, "bad_request", "the port must be 1024 or more")
        write_state("running")
        return None
    if method == "stop":
        write_state("stopped")
        return None
    if method == "status":
        return {"state": state(), "code": None}
    if method == "health":
        return {"ok": state() == "running", "code": "ok"}
    raise Failure(-32601, "unsupported", "unknown method %s" % method)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            return 2
        out = {"jsonrpc": "2.0", "id": req.get("id")}
        try:
            out["result"] = handle(req.get("method", ""), req.get("params") or {})
        except Failure as f:
            out["error"] = {"code": f.number, "message": f.message, "data": {"kind": f.kind}}
        print(json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
