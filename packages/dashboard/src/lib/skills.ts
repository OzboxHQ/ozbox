/** Who an install applies to, in words: a scope is `fleet`, `box:<name>` or `project:<name>`. */
export function skillScopeLabel(scope: string, t: (k: 'skills.scope_fleet' | 'skills.scope_box' | 'skills.scope_project', v?: Record<string, string | number>) => string): string {
  if (scope === 'fleet') return t('skills.scope_fleet');
  const [kind, ...rest] = scope.split(':');
  const name = rest.join(':');
  if (kind === 'box' && name) return t('skills.scope_box', { name });
  if (kind === 'project' && name) return t('skills.scope_project', { name });
  return scope;
}
