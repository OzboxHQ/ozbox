import { describe, expect, it } from 'vitest';

import { assertionJson, b64urlToBytes, bytesToB64url, creationOptions, registrationJson, requestOptions, wasCancelled } from './webauthn';

const buf = (...n: number[]) => new Uint8Array(n).buffer;

describe('webauthn conversions', () => {
  it('round-trips base64url, with no padding and url-safe characters', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 1, 2]);
    const s = bytesToB64url(bytes);
    expect(s).toBe('-__-AQI');
    expect(Array.from(b64urlToBytes(s))).toEqual(Array.from(bytes));
    expect(bytesToB64url(new Uint8Array([]))).toBe('');
  });

  it('turns the server options into buffers, keeping the user-verification and resident-key demands', () => {
    const o = creationOptions({
      rp: { id: 'box.example.com', name: 'Oz Box' },
      user: { id: bytesToB64url(new TextEncoder().encode('owner')), name: 'Owner', displayName: 'Owner' },
      challenge: bytesToB64url(new Uint8Array([1, 2, 3])),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      attestation: 'none',
      excludeCredentials: [{ type: 'public-key', id: bytesToB64url(new Uint8Array([9])) }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
    expect(new TextDecoder().decode(o.user.id as ArrayBuffer)).toBe('owner');
    expect(Array.from(new Uint8Array(o.challenge as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(o.attestation).toBe('none');
    expect(o.authenticatorSelection?.userVerification).toBe('required');
    expect(o.excludeCredentials).toHaveLength(1);
    const r = requestOptions({ rpId: 'box.example.com', challenge: bytesToB64url(new Uint8Array([7])), userVerification: 'required' });
    expect(r.allowCredentials).toEqual([]);
    expect(r.userVerification).toBe('required');
  });

  it('sends the credential back as base64url JSON', () => {
    const reg = registrationJson({ id: 'cid', response: { clientDataJSON: buf(1), attestationObject: buf(2, 3) } });
    expect(reg).toEqual({ id: 'cid', response: { clientDataJSON: 'AQ', attestationObject: 'AgM' } });
    const a = assertionJson({ id: 'cid', response: { clientDataJSON: buf(1), authenticatorData: buf(2), signature: buf(3), userHandle: null } });
    expect(a.response.userHandle).toBe('');
  });

  it('treats a closed prompt as a cancel, not a failure', () => {
    expect(wasCancelled(new DOMException('x', 'NotAllowedError'))).toBe(true);
    expect(wasCancelled(new Error('x'))).toBe(false);
  });
});
