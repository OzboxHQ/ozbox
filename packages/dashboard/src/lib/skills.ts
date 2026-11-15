import type { BoxHold, SkillAskKey } from '../api/memory';
import type { MessageKey } from './i18n';
import type { Problem } from './skill-compose';

/** Who an install applies to, in words: a scope is `fleet`, `box:<name>` or `project:<name>`. */
export function skillScopeLabel(scope: string, t: (k: 'skills.scope_fleet' | 'skills.scope_box' | 'skills.scope_project', v?: Record<string, string | number>) => string): string {
  if (scope === 'fleet') return t('skills.scope_fleet');
  const [kind, ...rest] = scope.split(':');
  const name = rest.join(':');
  if (kind === 'box' && name) return t('skills.scope_box', { name });
  if (kind === 'project' && name) return t('skills.scope_project', { name });
  return scope;
}

/** Whether a copy on a box is the library's, a different version, or no longer trustworthy. */
export function holdKey(h: Pick<BoxHold, 'state' | 'matches_library' | 'origin'>): 'skills.hold_matches' | 'skills.hold_differs' | 'skills.hold_not_in_library' | 'skills.hold_not_in_library_box' | 'skills.hold_modified' | 'skills.hold_missing' {
  if (h.state === 'modified') return 'skills.hold_modified';
  if (h.state === 'missing') return 'skills.hold_missing';
  if (h.matches_library === null) return h.origin === 'box' ? 'skills.hold_not_in_library_box' : 'skills.hold_not_in_library';
  return h.matches_library ? 'skills.hold_matches' : 'skills.hold_differs';
}

/** Where a copy on a box came from, by this dashboard's own record. */
export function originKey(h: Pick<BoxHold, 'origin'>): 'skills.origin_dashboard' | 'skills.origin_box' {
  return h.origin === 'dashboard' ? 'skills.origin_dashboard' : 'skills.origin_box';
}

/** The message for each thing a skill can ask an agent program to do. */
export const ASK_KEY = {
  hooks: { what: 'skills.ask_hooks', ack: 'skills.ack_hooks' },
  'allowed-tools': { what: 'skills.ask_allowed_tools', ack: 'skills.ack_allowed_tools' },
  shell: { what: 'skills.ask_shell', ack: 'skills.ack_shell' },
  agent: { what: 'skills.ask_agent', ack: 'skills.ack_agent' },
  'shell-injection': { what: 'skills.ask_shell_injection', ack: 'skills.ack_shell_injection' },
} as const satisfies Record<SkillAskKey, { what: MessageKey; ack: MessageKey }>;

export const VIA_KEY = {
  page_upload: 'skills.via_page_upload',
  page_editor: 'skills.via_page_editor',
  cli: 'skills.via_cli',
  restore: 'skills.via_restore',
  folder: 'skills.via_folder',
} as const;

/** The `t` argument for a problem found before sending: which message, and what fills it. */
export function problemMessage(p: Problem): { key: MessageKey; vars?: Record<string, string | number> } {
  switch (p.code) {
    case 'too_many':
    case 'too_big':
      return { key: `skills.p_${p.code}` as MessageKey, vars: { max: p.max } };
    case 'file_too_big':
      return { key: 'skills.p_file_too_big', vars: { path: p.path, max: p.max } };
    case 'file_type':
    case 'file_name':
    case 'hidden':
      return { key: `skills.p_${p.code}` as MessageKey, vars: { path: p.path } };
    default:
      return { key: `skills.p_${p.code}` as MessageKey };
  }
}
