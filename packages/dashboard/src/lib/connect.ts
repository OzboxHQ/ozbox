import type { BoxRecord } from '../api/types';

export interface ConnectInfo {
  /** The web IDE address, when one can be offered. */
  ideUrl: string | null;
  /** The command that says how to reach the box. Always available. */
  command: string;
  /** Why the IDE button is off, in words; null when it is on. */
  reason: string | null;
}

const DOMAIN = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

export function connectInfo(box: BoxRecord, domain: string | null | undefined): ConnectInfo {
  const command = `ozbox connect ${box.spec.name} --shell`;
  if (!domain || !DOMAIN.test(domain)) {
    return { ideUrl: null, command, reason: 'No domain is configured, so the box has no web address yet.' };
  }
  if (box.state !== 'running') {
    return { ideUrl: null, command, reason: `The box is ${box.state}. Resume it to open the IDE.` };
  }
  return { ideUrl: `https://${box.spec.name}.${domain}`, command, reason: null };
}

/**
 * Why "Open in" is off, in words; null when it can be tried. An AWS box is reached through Session Manager and needs
 * no domain. Anything else needs a domain and tunnel. The server has the last word: it names a missing route.
 */
export function openInReason(box: BoxRecord, domain: string | null | undefined): string | null {
  if (box.state !== 'running') return `The box is ${box.state}. Resume it first.`;
  if (box.provider === 'aws' && box.provider_id) return null;
  if (!domain) return 'No SSH route yet: this box needs a configured domain and tunnel.';
  return null;
}
