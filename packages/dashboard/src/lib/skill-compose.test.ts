import { describe, expect, it } from 'vitest';

import { checkSkill, composeSkillMd, fileKind, pickedPaths, readFrontMatter } from './skill-compose';

const fields = { name: 'my-skill', description: 'Does a thing.', version: '2', license: 'MIT', instructions: 'Do it.\n\n' };

describe('composeSkillMd', () => {
  it('writes a front matter the reader reads back, one line per value', () => {
    const md = composeSkillMd({ ...fields, description: 'Line one\nline: two' });
    expect(readFrontMatter(md)).toEqual({ name: 'my-skill', description: 'Line one line: two', version: '2' });
    expect(md.endsWith('Do it.\n')).toBe(true);
  });
  it('leaves out a version or licence that was not given', () => {
    expect(composeSkillMd({ ...fields, version: '', license: '' })).not.toMatch(/version|license/);
  });
});

describe('checkSkill', () => {
  const ok = { 'SKILL.md': composeSkillMd(fields), 'notes/a.md': 'x', 'run.sh': 'echo hi' };
  it('passes a good skill', () => expect(checkSkill(ok)).toEqual([]));
  it('names the first things to fix', () => {
    expect(checkSkill({ 'SKILL.md': composeSkillMd({ ...fields, name: 'bad name' }) })[0]).toEqual({ code: 'name' });
    expect(checkSkill({ 'SKILL.md': composeSkillMd({ ...fields, description: '' }) })[0]).toEqual({ code: 'description' });
    expect(checkSkill({ 'a.md': 'x' })).toEqual([{ code: 'no_skill_md' }]);
  });
  it('refuses paths that escape, types that are not text, and hidden characters', () => {
    for (const p of ['../x.md', 'a/../b.md', '/abs.md', '.hid.md', 'a//b.md', 'a/b/c/d/e.md']) expect(checkSkill({ ...ok, [p]: 'x' }).some((q) => q.code === 'file_name'), p).toBe(true);
    expect(checkSkill({ ...ok, 'tool.exe': 'x' }).some((q) => q.code === 'file_type')).toBe(true);
    expect(checkSkill({ ...ok, 'n.md': 'a‮b' }).some((q) => q.code === 'hidden')).toBe(true);
    expect(checkSkill({ ...ok, 'n.md': 'a\u0000b' }).some((q) => q.code === 'hidden')).toBe(true);
    expect(checkSkill({ ...ok, 'n.md': 'tab\tand\r\nnewline' }).some((q) => q.code === 'hidden')).toBe(false);
  });
  it('enforces the limits', () => {
    expect(checkSkill({ ...ok, 'big.md': 'x'.repeat(128 * 1024 + 1) }).some((q) => q.code === 'file_too_big')).toBe(true);
    const many = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`f${i}.md`, 'x']));
    expect(checkSkill({ ...ok, ...many }).some((q) => q.code === 'too_many')).toBe(true);
    const total = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`t${i}.md`, 'x'.repeat(120 * 1024)]));
    expect(checkSkill({ ...ok, ...total }).some((q) => q.code === 'too_big')).toBe(true);
  });
});

describe('fileKind and pickedPaths', () => {
  it('marks what an agent may run', () => {
    expect(fileKind('SKILL.md')).toBe('instructions');
    expect(fileKind('scripts/run.py')).toBe('script');
    expect(fileKind('notes/a.md')).toBe('text');
  });
  it('drops the folder a picker adds, and keeps loose files as they are', () => {
    expect(pickedPaths([{ name: 'SKILL.md', webkitRelativePath: 'demo/SKILL.md' }, { name: 'a.md', webkitRelativePath: 'demo/notes/a.md' }])).toEqual(['SKILL.md', 'notes/a.md']);
    expect(pickedPaths([{ name: 'SKILL.md', webkitRelativePath: '' }, { name: 'a.md' }])).toEqual(['SKILL.md', 'a.md']);
  });
});
