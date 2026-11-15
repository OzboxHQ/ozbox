import sys, os, subprocess, socket, struct, base64, hashlib, json, time
S = sys.argv[1]
BIN = S + '/inst/bin/'
SO = S + '/ossh-src/openssh-10.6p2/regress/misc/sk-dummy/sk-dummy.so'
W = S + '/work/'
env = dict(os.environ, SSH_SK_PROVIDER=SO)
env.pop('SSH_AUTH_SOCK', None)
def rs(b, o):
    n = struct.unpack('>I', b[o:o+4])[0]; return b[o+4:o+4+n], o+4+n
def st(b): return struct.pack('>I', len(b)) + b
def run(args, **k):
    r = subprocess.run(args, env=env, capture_output=True, **k)
    if r.returncode: raise SystemExit('FAIL %s: %s' % (args[0].split('/')[-1], r.stderr.decode()))
    return r
os.chdir(W)  # sun_path limit: use relative socket name
sock = 'agent.sock'
if os.path.exists(sock): os.unlink(sock)
ag = subprocess.Popen([BIN+'ssh-agent', '-D', '-a', sock, '-P', SO], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(50):
    if os.path.exists(sock): break
    time.sleep(0.1)
env['SSH_AUTH_SOCK'] = sock
tooln = subprocess.run([BIN+'ssh-keygen', '-V'], capture_output=True, text=True) # not valid; ignore
ver = subprocess.run([BIN+'ssh', '-V'], capture_output=True, text=True).stderr.strip()
tool = 'OpenSSH portable ' + ver + ' (ssh-keygen/ssh-agent/ssh-add built from source) + sk-dummy.so from same tree'
def mpint_val(b):
    return int.from_bytes(b, 'big')
def agent_sign(keyblob, msg):
    c = socket.socket(socket.AF_UNIX); c.connect(sock)
    body = bytes([13]) + st(keyblob) + st(msg) + struct.pack('>I', 0)
    c.sendall(struct.pack('>I', len(body)) + body)
    n = struct.unpack('>I', c.recv(4))[0]
    d = b''
    while len(d) < n: d += c.recv(n - len(d))
    c.close()
    assert d[0] == 14, d[:1]
    sig, _ = rs(d, 1)
    return sig
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, utils
from cryptography.hazmat.primitives import hashes
out = {'ssh_sk_ed25519': [], 'ssh_ecdsa_sk': []}
cases = [
 ('ed25519-sk', 'default', [], 'ssh:'),
 ('ed25519-sk', 'verify-required', ['-O','verify-required'], 'ssh:'),
 ('ed25519-sk', 'application=ssh:work', ['-O','application=ssh:work'], 'ssh:work'),
 ('ed25519-sk', 'no-touch-required', ['-O','no-touch-required'], 'ssh:'),
 ('ecdsa-sk', 'default', [], 'ssh:'),
 ('ecdsa-sk', 'verify-required', ['-O','verify-required'], 'ssh:'),
 ('ecdsa-sk', 'application=ssh:work', ['-O','application=ssh:work'], 'ssh:work'),
 ('ecdsa-sk', 'no-touch-required', ['-O','no-touch-required'], 'ssh:'),
]
n = 0
try:
  for kt, label, opts, app in cases:
    kf = W + 'k_%s_%s' % (kt, label.replace(':','_').replace('=','_'))
    for f in (kf, kf+'.pub'):
        if os.path.exists(f): os.unlink(f)
    run([BIN+'ssh-keygen','-q','-t',kt,'-f',kf,'-N','']+opts)
    run([BIN+'ssh-add', kf])
    pub = open(kf+'.pub').read().strip()
    blob = base64.b64decode(pub.split()[1])
    alg, o = rs(blob, 0)
    if kt == 'ed25519-sk':
        pk, o = rs(blob, o); appb, o = rs(blob, o)
    else:
        curve, o = rs(blob, o); pk, o = rs(blob, o); appb, o = rs(blob, o)
    assert appb.decode() == app
    for i in range(2):
        n += 1
        M = b'ozbox-approval-decide\n' + hashlib.sha256(b'vector-%d' % n).hexdigest().encode()
        sig = agent_sign(blob, M)
        salg, o2 = rs(sig, 0); inner, o2 = rs(sig, o2)
        flags = sig[o2]; counter = struct.unpack('>I', sig[o2+1:o2+5])[0]
        assert o2 + 5 == len(sig)
        payload = hashlib.sha256(appb).digest() + bytes([flags]) + struct.pack('>I', counter) + hashlib.sha256(M).digest()
        e = {'tool': tool, 'key_type': alg.decode(), 'sig_algorithm': salg.decode(), 'label': label,
             'public_key_line': pub, 'public_key_blob': blob.hex(), 'public_key_raw': pk.hex(),
             'application': app, 'message': M.hex(), 'agent_signature_blob': sig.hex(),
             'flags': flags, 'counter': counter, 'signed_payload': payload.hex()}
        if kt == 'ed25519-sk':
            e['raw_signature'] = inner.hex()
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(inner, payload); e['self_verified'] = 'cryptography Ed25519 verify OK'
            except Exception as x: e['self_verified'] = 'FAILED %r' % x
            out['ssh_sk_ed25519'].append(e)
        else:
            r, p = rs(inner, 0); s, p = rs(inner, p); assert p == len(inner)
            ri, si = mpint_val(r), mpint_val(s)
            der = utils.encode_dss_signature(ri, si)
            e.update({'r_mpint': r.hex(), 's_mpint': s.hex(), 'r': '%064x' % ri, 's': '%064x' % si, 'der_signature': der.hex(), 'raw_signature': inner.hex()})
            try:
                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk).verify(der, payload, ec.ECDSA(hashes.SHA256())); e['self_verified'] = 'cryptography ECDSA P-256/SHA-256 verify OK'
            except Exception as x: e['self_verified'] = 'FAILED %r' % x
            out['ssh_ecdsa_sk'].append(e)
    run([BIN+'ssh-add','-d',kf+'.pub'])
finally:
    ag.terminate(); ag.wait()
json.dump(out, open(W+'ssh.json','w'), indent=1)
for k in out:
    for e in out[k]: print(k, e['label'], 'flags', e['flags'], 'ctr', hex(e['counter']), e['self_verified'])
