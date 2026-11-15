import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { HIDDEN_RANGES } from './skill-hidden';
import { checkSkill, composeSkillMd, fileKind, hasHidden, pickedPaths, readFrontMatter, skillNameOk } from './skill-compose';

const fields = { name: 'my-skill', description: 'Does a thing.', version: '2', license: 'MIT', instructions: 'Do it.\n\n' };

describe('composeSkillMd', () => {
  it('writes a front matter the reader reads back, one line per value', () => {
    const md = composeSkillMd({ ...fields, description: 'Line one\nline: two' });
    expect(readFrontMatter(md)).toEqual({ name: 'my-skill', description: 'Line one line: two', version: '2' });
    expect(md.endsWith('Do it.\n')).toBe(true);
  });
  it('quotes values so that a colon or a hash in them cannot change what the YAML means', () => {
    const md = composeSkillMd({ ...fields, description: 'Use for: a # b', version: '1: 2' });
    expect(readFrontMatter(md)).toEqual({ name: 'my-skill', description: 'Use for: a # b', version: '1: 2' });
  });
  it('does not take a nested name for the skill\'s', () => {
    expect(readFrontMatter('---\nname: demo\ndescription: x\nmetadata:\n  name: evil\n---\n').name).toBe('demo');
  });
  it('leaves out a version or licence that was not given', () => {
    expect(composeSkillMd({ ...fields, version: '', license: '' })).not.toMatch(/version|license/);
  });
});

describe('skillNameOk', () => {
  it('is lower-case letters and digits with single dashes, as the server has it', () => {
    for (const ok of ['demo', 'pdf-tools', 'a1', 'x-1-y']) expect(skillNameOk(ok), ok).toBe(true);
    for (const bad of ['Demo', 'my_skill', 'a--b', '-a', 'a-', 'a.b', '', 'a'.repeat(65)]) expect(skillNameOk(bad), bad).toBe(false);
  });
});

describe('the hidden-character table', () => {
  it('refuses each class the server refuses', () => {
    for (const cp of [0x0, 0x1b, 0x85, 0xad, 0x34f, 0x61c, 0x115f, 0x1160, 0x180b, 0x200b, 0x202e, 0x2028, 0x2029, 0x206a, 0x2800, 0x3164, 0xe000, 0xfe0f, 0xfeff, 0xffa0, 0xfff9, 0x1bca0, 0x1d173, 0xe0041, 0xe0100, 0xe01ef, 0xf0000, 0x378]) {
      expect(hasHidden(`a${String.fromCodePoint(cp)}b`), cp.toString(16)).toBe(true);
    }
    for (const ok of ['tabs\tand\r\nlines é 日本 ö', 'emoji 😀 ½ — “quotes”']) expect(hasHidden(ok), ok).toBe(false);
  });
  it('is the same table the server uses', () => {
    const rust = readFileSync(new URL('../../../../crates/ozbox-core/src/skill_hidden.rs', import.meta.url), 'utf8');
    const ranges = [...rust.matchAll(/\(0x([0-9A-F]+), 0x([0-9A-F]+)\),/g)].map((m) => [parseInt(m[1] as string, 16), parseInt(m[2] as string, 16)]);
    expect(ranges.length).toBeGreaterThan(100);
    expect(HIDDEN_RANGES.map((r) => [...r])).toEqual(ranges);
  });
});

describe('checkSkill', () => {
  const ok = { 'SKILL.md': composeSkillMd(fields), 'notes/a.md': 'x', 'run.sh': 'echo hi' };
  it('passes a good skill', () => expect(checkSkill(ok)).toEqual([]));
  it('names the first things to fix', () => {
    expect(checkSkill({ 'SKILL.md': composeSkillMd({ ...fields, name: 'Bad_Name' }) })[0]).toEqual({ code: 'name' });
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
