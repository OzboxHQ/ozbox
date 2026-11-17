#!/usr/bin/env python3
"""Independent computation of the channel's golden vectors: the canonical bytes and digest of an envelope (ADR 0041's encoding:
a version byte 1, then every field as a 4-byte big-endian length and its bytes), the hub's `ext`, and the sealing-key fingerprint.

It shares nothing with the crate's encoder (it uses only hashlib and struct), which is the point: the Rust constants in
`channel/tests.rs`, `hub/tests.rs` and `agent_mesh/tests.rs` are compared with what this prints. Run `python3 channel_golden_vectors.py`
and diff the output against those constants; change a constant only together with the wire format and the ADR.

Profiles covered: the channel's own test profile, the hub (`ozbox-hub-envelope-v1`) and the agent mesh (`ozbox-mesh-envelope`).
"""
import hashlib
import struct


def f(b):
    return struct.pack(">I", len(b)) + b


def t(s):
    return f(s.encode())


def u(n):
    return f(struct.pack(">Q", n))


def canonical(tag, e):
    out = bytes([1]) + t(tag)
    out += u(e["version"]) + t(e["kind"]) + t(e["from"]) + t(e["to"]) + t(e["receiver_fp"])
    out += u(e["sender_epoch"]) + u(e["receiver_epoch"]) + u(e["sender_inc"]) + u(e["receiver_inc"])
    out += u(e["seq"]) + u(e["ack_seq"]) + t(e["id"]) + u(e["ts_ms"]) + u(e["valid_until_ms"])
    out += f(e["nonce"]) + f(e["ext"]) + f(e["body"])
    return out


def digest(tag, canon):
    return hashlib.sha256(bytes([1]) + t(tag) + f(canon)).hexdigest()


def hub_ext(level, hops):
    out = bytes([1]) + t("ozbox-hub-ext-v1") + u(level) + u(len(hops))
    for b, k in hops:
        out += t(b) + t(k)
    return out


W1 = "bb00000000000000000000000000000000000000000000000000000000000001"
W2 = "bb00000000000000000000000000000000000000000000000000000000000002"

if __name__ == "__main__":
    # the test profile
    e = dict(version=1, kind="note", **{"from": "laptop"}, to="main", receiver_fp="0123abcd-0123abcd-0123abcd-0123abcd",
             sender_epoch=3, receiver_epoch=2, sender_inc=0x1111, receiver_inc=0x2222, seq=5, ack_seq=4, id="5-aabbccddeeff",
             ts_ms=1700000000000, valid_until_ms=1700000600000, nonce=bytes(range(16)), ext=b"task-1", body=b"hello")
    c = canonical("ozbox-test-channel", e)
    print("TEST_CANONICAL", c.hex())
    print("TEST_DIGEST", digest("ozbox-test-channel", c))
    # the sealing-key fingerprint (tag ozbox-seal-key/1)
    d = hashlib.sha256(b"ozbox-seal-key/1" + bytes(range(32))).hexdigest()[:32]
    print("FINGERPRINT", "-".join(d[i:i + 8] for i in range(0, 32, 8)))
    # the hub profile
    h = dict(version=1, kind="task.assign", **{"from": "main"}, to="worker-1", receiver_fp=W1, sender_epoch=7,
             receiver_epoch=1, sender_inc=0x1111, receiver_inc=0x2222, seq=3, ack_seq=2, id="main-worker-1-3",
             ts_ms=1700000000000, valid_until_ms=1700000600000, nonce=bytes(range(16)), ext=hub_ext(0, []), body=b"hello")
    hc = canonical("ozbox-hub-envelope-v1", h)
    print("HUB_EXT", hub_ext(0, []).hex())
    print("HUB_CANONICAL", hc.hex())
    print("HUB_DIGEST", digest("ozbox-hub-envelope-v1", hc))
    hv = dict(h, ext=hub_ext(2, [("worker-a", W2)]))
    print("HUB_EXT_VIA", hv["ext"].hex())
    print("HUB_CANONICAL_VIA", canonical("ozbox-hub-envelope-v1", hv).hex())
    # the agent-mesh profile: the signed ext is the task key, `origin/id`
    m = dict(version=1, kind="task", **{"from": "laptop"}, to="main", receiver_fp="0123abcd-0123abcd-0123abcd-0123abcd",
             sender_epoch=3, receiver_epoch=2, sender_inc=0x1111, receiver_inc=0x2222, seq=5, ack_seq=4, id="5-aabbccddeeff",
             ts_ms=1700000000000, valid_until_ms=1700000600000, nonce=bytes(range(16)), ext=b"laptop/task-1", body=b"hello")
    mc = canonical("ozbox-mesh-envelope", m)
    print("MESH_CANONICAL", mc.hex())
    print("MESH_DIGEST", digest("ozbox-mesh-envelope", mc))
