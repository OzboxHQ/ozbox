import json, sys, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
S=sys.argv[1]
ssh=json.load(open(S+'/work/ssh.json')); wa=json.load(open(S+'/work/webauthn.json'))
for e in wa:
    e['registration']['fmt']='packed' if e['registration']['attestationObject'].count('')>0 and bytes.fromhex(e['registration']['attestationObject'])[:20].find(b'fmt')>=0 and b'packed' in bytes.fromhex(e['registration']['attestationObject'])[:40] else e['registration']['fmt']
    ad=bytes.fromhex(e['authenticatorData']); cd=bytes.fromhex(e['clientDataJSON_hex'])
    assert ad[:32]==hashlib.sha256(b'localhost').digest()
    pk=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04'+bytes.fromhex(e['public_key_x'])+bytes.fromhex(e['public_key_y']))
    pk.verify(bytes.fromhex(e['signature']), ad+hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    e['self_verified']='cryptography ECDSA P-256/SHA-256 over authenticatorData||SHA256(clientDataJSON) OK'
notes=[
"sk-dummy.so (OpenSSH test provider) always returns counter 0x12345678 (constant), so counter progression is NOT visible in the ssh_sk vectors; a real token increments it.",
"sk-dummy sets flags from the key's enrol options: default UP=0x01, verify-required UP|UV=0x05, no-touch-required 0x00.",
"The agent signature blob for sk keys is string(alg) || string(sig) || byte flags || uint32 counter (flags/counter follow the sig string at the TOP level, not inside a second wrapped string as described in the brief); for ecdsa-sk the sig string holds mpint r, mpint s (PROTOCOL.u2f). The JSON records this exact layout.",
"ssh_sk signatures come from OpenSSH's software test provider, not a hardware FIDO2 token (none attached); signing is otherwise real ssh-agent -> ssh-sk-helper -> sk-dummy.so path on a raw message with flags 0.",
"OpenSSH tarball sha256 computed (9ae44872090cf2f06b3cf9ff147e7f16f309671340763ed2f99248398ae29d5b) but could not be compared to a published sha256 listing (site lists only .asc PGP signature; gpg verification not done).",
"WebAuthn assertions come from Chrome's CDP virtual authenticator (software), counters start at 2 after registration then increment. Attestation fmt is 'packed'. Credential A registered with UV required, B with UV discouraged; assertions with requested_userVerification 'discouraged' give flags 0x01 (UV clear), 'required'/'preferred' give 0x05.",
"All assertion signatures and all ssh_sk signatures were self-verified with python cryptography 48.0.1 (verification result recorded per entry).",
]
json.dump({'ssh_sk_ed25519':ssh['ssh_sk_ed25519'],'ssh_ecdsa_sk':ssh['ssh_ecdsa_sk'],'webauthn_assertion':wa,'notes':notes}, open(S+'/real_tool_vectors.json','w'), indent=1)
print(len(ssh['ssh_sk_ed25519']), len(ssh['ssh_ecdsa_sk']), len(wa), set(e['registration']['fmt'] for e in wa))
