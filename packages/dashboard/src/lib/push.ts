import type { ApiClient } from '../api/client';

/** The browser wants the server's key as bytes. */
export function urlBase64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  const raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

export function pushSupported(): boolean {
  return typeof window !== 'undefined' && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

export type PushOutcome = { ok: true; id: string } | { ok: false; reason: 'unsupported' | 'denied' | 'failed' };

/** Ask permission, subscribe this browser with the server's key, and hand the subscription to the server. */
export async function turnOnThisDevice(client: ApiClient, person: string, label: string): Promise<PushOutcome> {
  if (!pushSupported()) return { ok: false, reason: 'unsupported' };
  try {
    const permission = Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
    if (permission !== 'granted') return { ok: false, reason: 'denied' };
    const key = await client.pushKey();
    const reg = await navigator.serviceWorker.ready;
    const existing = await reg.pushManager.getSubscription();
    // A subscription made with another key would be refused by the push service; start clean.
    if (existing) await existing.unsubscribe();
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToBytes(key) });
    const id = await client.addPushDevice({ person, label, subscription: sub.toJSON() });
    return { ok: true, id };
  } catch {
    return { ok: false, reason: 'failed' };
  }
}
