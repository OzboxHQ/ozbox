/** WebAuthn in the browser: the server speaks base64url JSON, the browser wants byte buffers. Pure conversions here. */

export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface Descriptor {
  type: 'public-key';
  id: string;
}

export interface CreationJson {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  excludeCredentials?: Descriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
}

export interface RequestJson {
  rpId: string;
  challenge: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: Descriptor[];
}

const desc = (d: Descriptor): PublicKeyCredentialDescriptor => ({ type: d.type, id: b64urlToBytes(d.id) });

export function creationOptions(o: CreationJson): PublicKeyCredentialCreationOptions {
  const out: PublicKeyCredentialCreationOptions = {
    rp: o.rp,
    user: { id: b64urlToBytes(o.user.id), name: o.user.name, displayName: o.user.displayName },
    challenge: b64urlToBytes(o.challenge),
    pubKeyCredParams: o.pubKeyCredParams,
    excludeCredentials: (o.excludeCredentials ?? []).map(desc),
  };
  if (o.timeout !== undefined) out.timeout = o.timeout;
  if (o.attestation) out.attestation = o.attestation;
  if (o.authenticatorSelection) out.authenticatorSelection = o.authenticatorSelection;
  return out;
}

export function requestOptions(o: RequestJson): PublicKeyCredentialRequestOptions {
  const out: PublicKeyCredentialRequestOptions = {
    rpId: o.rpId,
    challenge: b64urlToBytes(o.challenge),
    allowCredentials: (o.allowCredentials ?? []).map(desc),
  };
  if (o.timeout !== undefined) out.timeout = o.timeout;
  if (o.userVerification) out.userVerification = o.userVerification;
  return out;
}

export interface RegistrationJson {
  id: string;
  response: { clientDataJSON: string; attestationObject: string };
}

export interface AssertionJson {
  id: string;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string };
}

export function registrationJson(c: { id: string; response: { clientDataJSON: ArrayBuffer; attestationObject: ArrayBuffer } }): RegistrationJson {
  return {
    id: c.id,
    response: { clientDataJSON: bytesToB64url(c.response.clientDataJSON), attestationObject: bytesToB64url(c.response.attestationObject) },
  };
}

export function assertionJson(c: {
  id: string;
  response: { clientDataJSON: ArrayBuffer; authenticatorData: ArrayBuffer; signature: ArrayBuffer; userHandle: ArrayBuffer | null };
}): AssertionJson {
  return {
    id: c.id,
    response: {
      clientDataJSON: bytesToB64url(c.response.clientDataJSON),
      authenticatorData: bytesToB64url(c.response.authenticatorData),
      signature: bytesToB64url(c.response.signature),
      userHandle: c.response.userHandle ? bytesToB64url(c.response.userHandle) : '',
    },
  };
}

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials;
}

/** A person closing the browser's passkey prompt is not an error worth a red banner. */
export function wasCancelled(e: unknown): boolean {
  return e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError');
}

export async function createPasskey(o: CreationJson): Promise<RegistrationJson> {
  const cred = await navigator.credentials.create({ publicKey: creationOptions(o) });
  if (!(cred instanceof PublicKeyCredential) || !(cred.response instanceof AuthenticatorAttestationResponse)) throw new Error('no passkey was created');
  return registrationJson({ id: cred.id, response: cred.response });
}

export async function getPasskey(o: RequestJson): Promise<AssertionJson> {
  const cred = await navigator.credentials.get({ publicKey: requestOptions(o) });
  if (!(cred instanceof PublicKeyCredential) || !(cred.response instanceof AuthenticatorAssertionResponse)) throw new Error('no passkey was returned');
  return assertionJson({ id: cred.id, response: cred.response });
}
