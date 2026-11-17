#!/usr/bin/env python3
"""Independent generator of the golden vectors for ozbox_core::approval_subject (ADR 0041 section 4).

It implements the encoding from the ADR's text alone, not from the Rust code: one version byte, then length-prefixed
(4-byte big-endian) fields: the domain tag, the box id, the store id, the scope, then the scope's own fields in the order
of the ADR's table. Run `python3 approval_subject_golden.py` to rewrite approval_subject_golden.json; the Rust test
`golden_vectors_from_the_committed_file` reads that file and must produce every digest. The laptop crate must produce the
same ones (the file is the contract).
"""
import hashlib
import json
import os
import struct

TAG = "ozbox-approval-subject-v1"
BOX, STORE = "box-1", "store-1"


def lp(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return struct.pack(">I", len(b)) + b


def u64(n):
    return lp(struct.pack(">Q", n))


def flag(b):
    return lp(bytes([1 if b else 0]))


def count(n):
    return u64(n)


def head(tag, scope, box=BOX, store=STORE):
    return bytes([1]) + lp(tag) + lp(box) + lp(store) + lp(scope)


def sha(x):
    return hashlib.sha256(x).hexdigest()


def matches(ms):
    ms = sorted(ms, key=lambda m: (m["path"], m["line"], m["rule"], m["key_id"]))
    out = count(len(ms))
    for m in ms:
        out += lp(m["path"]) + u64(m["line"]) + lp(m["rule"]) + lp(m["key_id"])
    return out


def encode(s, box=BOX, store=STORE):
    sc = s["scope"]
    b = head(TAG, sc, box, store)
    if sc == "guard-override" and s["hook"] == "commit":
        b += lp("commit") + lp(s["repo_path_hash"]) + lp(s["hook_kind"]) + lp(s["tree_id"])
        b += matches(s["matches"]) + lp(s["scanned_text_hash"])
    elif sc == "guard-override":
        b += lp("push") + lp(s["repo_path_hash"]) + lp(s["remote_url"])
        refs = sorted(s["refs"], key=lambda r: (r["ref_name"], r["old"], r["new"]))
        b += count(len(refs))
        for r in refs:
            b += lp(r["ref_name"]) + lp(r["old"]) + lp(r["new"])
        b += matches(s["matches"]) + lp(s["scanned_text_hash"])
    elif sc == "import":
        b += lp(s["project"]) + lp(s["environment"]) + flag(s.get("production", False))
        names = sorted(s["names"], key=lambda n: n["name"])
        b += count(len(names))
        for n in names:
            b += lp(n["name"]) + lp(n["classification"]) + lp(n["value_digest"])
        b += u64(s["store_generation"])
    elif sc == "policy":
        b += lp(s["policy_sha256"]) + lp(s["predecessor_sha256"]) + lp(s["sensitivity"]) + lp(s["project"])
    elif sc == "tunnel-token":
        b += lp(s["kind"]) + lp(s["token_sha256"]) + lp(s.get("account_tag", "")) + lp(s.get("tunnel_id", ""))
    elif sc == "box-secrets":
        b += lp(s["address"]) + lp(s["action"]) + lp(s.get("change_digest", "")) + flag(s.get("first_setting", False))
    elif sc == "host-guard":
        b += lp(s["action"]) + flag(s["loosening"]) + count(len(s["fields"]))
        for k, v in s["fields"]:
            b += lp(k) + lp(v)
    elif sc == "signer-enroll":
        b += lp(s["action"]) + lp(s["key_name"]) + lp(s["key_type"]) + lp(s["public_half"]) + lp(s.get("attestation_digest", ""))
    elif sc == "worker-keys":
        b += lp(s["orchestration_id"])
        names = sorted(s["names"])
        b += count(len(names))
        for n in names:
            b += lp(n)
        b += lp(s["environment"]) + u64(s["max_workers"]) + u64(s["ttl_s"])
    elif sc in ("setup-code", "kek-export"):
        b += lp(s["challenge"])
    else:
        raise SystemExit("unknown scope " + sc)
    return b


def h(c):
    return c * 64


def commit(tree="a" * 40, ms=None, rp=None):
    return {"scope": "guard-override", "hook": "commit", "repo_path_hash": rp or h("1"), "hook_kind": "pre-commit",
            "tree_id": tree, "matches": ms or [], "scanned_text_hash": h("2")}


def push(url="https://example.test/r.git", refs=None, ms=None):
    return {"scope": "guard-override", "hook": "push", "repo_path_hash": h("1"), "remote_url": url,
            "refs": refs or [{"ref_name": "refs/heads/main", "old": "a" * 40, "new": "b" * 40}],
            "matches": ms or [], "scanned_text_hash": h("2")}


def imp(names, env="staging", gen=3, production=False):
    return {"scope": "import", "project": "app", "environment": env, "production": production,
            "names": [{"name": n, "classification": c, "value_digest": h("a")} for n, c in names], "store_generation": gen}


def tun(tag="acct1", tid="tun1", kind="ide"):
    return {"scope": "tunnel-token", "kind": kind, "token_sha256": h("c"), "account_tag": tag, "tunnel_id": tid}


M2 = [{"path": "src/b.rs", "line": 9, "rule": "stored-value", "key_id": "k2"},
      {"path": "src/a.rs", "line": 3, "rule": "stored-value", "key_id": "k1"}]

VECTORS = [
    ("setup-code", {"scope": "setup-code", "challenge": "00112233445566778899aabbccddeeff"}),
    ("kek-export", {"scope": "kek-export", "challenge": "00112233445566778899aabbccddeeff"}),
    ("import: two names listed out of order", imp([("B", "secret"), ("A", "secret")])),
    ("import: the same two names in order (the same digest)", imp([("A", "secret"), ("B", "secret")])),
    ("import: a public mark is another digest", imp([("A", "public"), ("B", "secret")])),
    ("import: another store generation is another digest", imp([("A", "secret"), ("B", "secret")], gen=4)),
    ("import: the filer says production", imp([("A", "secret")], production=True)),
    ("tunnel-token", tun()),
    ("tunnel-token: a field moved across a boundary (account ab, tunnel c)", tun(tag="ab", tid="c")),
    ("tunnel-token: the same characters the other way (account a, tunnel bc)", tun(tag="a", tid="bc")),
    ("tunnel-token: empty account tag", tun(tag="", tid="tun1")),
    ("tunnel-token: empty tunnel id", tun(tag="acct1", tid="")),
    ("policy", {"scope": "policy", "project": "app", "policy_sha256": h("d"), "predecessor_sha256": h("e"), "sensitivity": "ordinary"}),
    ("policy: widens a guarded scope", {"scope": "policy", "project": "app", "policy_sha256": h("d"), "predecessor_sha256": h("e"), "sensitivity": "widens-guarded"}),
    ("guard-override commit: one match", commit(ms=[M2[1]])),
    ("guard-override commit: two matches out of order", commit(ms=M2)),
    ("guard-override commit: the same two in order (the same digest)", commit(ms=[M2[1], M2[0]])),
    ("guard-override commit: a lying path is another digest", commit(ms=[dict(M2[1], path="src/c.rs")])),
    ("guard-override push", push()),
    ("guard-override push: another remote url", push(url="https://evil.test/r.git")),
    ("guard-override push: a lookalike letter in the url (Cyrillic a)", push(url="https://exаmple.test/r.git")),
    ("guard-override push: two refs out of order",
     push(refs=[{"ref_name": "refs/heads/z", "old": "c" * 40, "new": "d" * 40}, {"ref_name": "refs/heads/a", "old": "a" * 40, "new": "b" * 40}], ms=M2)),
    ("box-secrets: set", {"scope": "box-secrets", "address": "a1", "action": "set", "change_digest": h("3"), "first_setting": False}),
    ("box-secrets: set, a first setting", {"scope": "box-secrets", "address": "a1", "action": "set", "change_digest": h("3"), "first_setting": True}),
    ("box-secrets: remove", {"scope": "box-secrets", "address": "a1", "action": "remove", "change_digest": "", "first_setting": False}),
    ("host-guard: a loosening with two fields", {"scope": "host-guard", "action": "open-port", "loosening": True, "fields": [["port", "8080"], ["proto", "tcp"]]}),
    ("signer-enroll: enrol a software key", {"scope": "signer-enroll", "action": "enrol", "key_name": "laptop-2", "key_type": "ed25519", "public_half": h("9"), "attestation_digest": ""}),
    ("signer-enroll: enrol a presence key with its attestation", {"scope": "signer-enroll", "action": "enrol", "key_name": "yubi", "key_type": "sk-ssh-ed25519", "public_half": h("9"), "attestation_digest": h("7")}),
    ("signer-enroll: revoke", {"scope": "signer-enroll", "action": "revoke", "key_name": "laptop-2", "key_type": "ed25519", "public_half": h("9"), "attestation_digest": ""}),
    ("worker-keys: names out of order", {"scope": "worker-keys", "orchestration_id": "orch-1", "names": ["B", "A"], "environment": "staging", "max_workers": 4, "ttl_s": 3600}),
]

# refused before any digest: a duplicate name, a lookalike in a name, a name with a separator, tightening a host guard,
# a production environment in worker-keys, a control character in a text field
REFUSED = [
    ("import: a duplicate name", imp([("A", "secret"), ("A", "public")])),
    ("import: a lookalike letter in a name (Cyrillic a)", imp([("аpp", "secret")])),
    ("import: a name with a separator", imp([("A B", "secret")])),
    ("host-guard: tightening is not filed", {"scope": "host-guard", "action": "open-port", "loosening": False, "fields": []}),
    ("worker-keys: production is a secret-use", {"scope": "worker-keys", "orchestration_id": "orch-1", "names": ["A"], "environment": "production", "max_workers": 4, "ttl_s": 3600}),
    ("worker-keys: an unlisted environment", {"scope": "worker-keys", "orchestration_id": "orch-1", "names": ["A"], "environment": "qa", "max_workers": 4, "ttl_s": 3600}),
    ("guard-override push: a newline in the url", push(url="https://example.test/r.git\nHost: evil")),
    ("guard-override push: a direction override in the url", push(url="https://example.test/‮r.git")),
]


def other_domain(tag, fields):
    out = bytes([1]) + lp(tag)
    for f in fields:
        out += lp(f)
    return sha(out)


def main():
    vectors = [{"name": n, "box_id": BOX, "store_id": STORE, "subject": s, "digest": sha(encode(s))} for n, s in VECTORS]
    # the same change on another box and another store
    vectors.append({"name": "import on another box", "box_id": "box-2", "store_id": STORE, "subject": VECTORS[2][1],
                    "digest": sha(encode(VECTORS[2][1], box="box-2"))})
    vectors.append({"name": "import on another store", "box_id": BOX, "store_id": "store-2", "subject": VECTORS[2][1],
                    "digest": sha(encode(VECTORS[2][1], store="store-2"))})
    refused = [{"name": n, "box_id": BOX, "store_id": STORE, "subject": s} for n, s in REFUSED]
    d7 = bytes([7]) * 32
    challenges = []
    # the decide challenge names the outcome: one vector for each, so an assertion for one cannot decide another
    for outcome in ("approve", "deny", "revoke"):
        ch = other_domain("ozbox-approval-decide-v1", [BOX, STORE, "REQ1", d7, outcome])
        challenges.append({"name": "decide challenge: " + outcome, "kind": "decide", "request_id": "REQ1",
                           "digest_hex": d7.hex(), "outcome": outcome, "expect": ch,
                           # the text a laptop key signs: the head, a newline, the hex of the challenge
                           "message": "ozbox-approval-decide\n" + ch})
    challenges.append({"name": "key enrolment challenge", "kind": "key-enrol", "request_id": "REQ1", "digest_hex": d7.hex(),
                       "expect": other_domain("ozbox-key-enrol-v1", [BOX, STORE, "REQ1", d7])})
    # a full envelope: the box and the store are inside the signed text, in this field order, compact
    subject = commit(ms=M2)
    envelope_obj = {
        "box_id": BOX, "store_id": STORE, "origin": "local", "id": "REQ1", "scope": "guard-override",
        "subject": subject, "subject_digest": sha(encode(subject)),
        "requester": {"kind": "box-user", "uid": 1000, "key_id": None, "run_id": None, "engine": None, "claimed": None},
        "expires_at_ms": 1700000900000, "state": "pending", "epoch": "epoch-1",
    }
    canonical = json.dumps(envelope_obj, separators=(",", ":"), ensure_ascii=False)
    envelope = {"canonical": canonical, "message": other_domain("ozbox-approval-envelope-v1", [canonical])}
    out = {"vectors": vectors, "refused": refused, "challenges": challenges, "envelope": envelope}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "approval_subject_golden.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=True)
        f.write("\n")
    print("wrote", path, len(vectors), "vectors")


if __name__ == "__main__":
    main()
