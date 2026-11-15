import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// WCAG 2.2 AA asks 4.5:1 for text. The solid red of a destructive button or badge was 3.6:1 with white text in the light theme;
// these checks read the theme's own tokens, so a change to the red cannot quietly bring that back.

const css = readFileSync(join(__dirname, '..', 'index.css'), 'utf8');

type Rgb = [number, number, number];

function tokens(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of block.matchAll(/--([a-z-]+):\s*([^;]+);/g)) out[m[1]!] = m[2]!.trim();
  return out;
}

function themeBlock(selector: ':root' | '.dark'): Record<string, string> {
  const start = css.indexOf(`${selector} {`);
  const end = css.indexOf('\n  }', start);
  return tokens(css.slice(start, end));
}

function hsl(value: string): Rgb {
  const [h, s, l] = value.split(/\s+/).map((x) => parseFloat(x)) as [number, number, number];
  const sat = s / 100;
  const light = l / 100;
  const a = sat * Math.min(light, 1 - light);
  const f = (n: number) => {
    const k = (n + h / 30) % 12;
    return 255 * (light - a * Math.max(-1, Math.min(k - 3, 9 - k, 1)));
  };
  return [f(0), f(8), f(4)];
}

const lum = ([r, g, b]: Rgb) => {
  const c = (v: number) => {
    const x = v / 255;
    return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b);
};

function ratio(a: Rgb, b: Rgb): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const over = (c: Rgb, bg: Rgb, alpha: number): Rgb => [0, 1, 2].map((i) => c[i]! * alpha + bg[i]! * (1 - alpha)) as Rgb;

describe.each([[':root' as const], ['.dark' as const]])('%s theme: red meets 4.5:1', (sel) => {
  const t = themeBlock(sel);
  const get = (n: string) => hsl(t[n]!);

  it('white text on a solid destructive fill, also on hover (the fill fades by a tenth)', () => {
    expect(ratio(get('destructive-foreground'), get('destructive'))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(get('destructive-foreground'), over(get('destructive'), get('background'), 0.9))).toBeGreaterThanOrEqual(4.5);
  });

  it('red text (alerts, inline errors) on the page and on cards', () => {
    expect(ratio(get('destructive-text'), get('background'))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(get('destructive-text'), get('card'))).toBeGreaterThanOrEqual(4.5);
  });
});

it('no destructive badge or button fades its fill by more than a tenth on hover', () => {
  for (const f of ['components/ui/badge.tsx', 'components/ui/button.tsx']) {
    const src = readFileSync(join(__dirname, '..', '..', f), 'utf8');
    expect(src).not.toMatch(/hover:bg-destructive\/(?:[0-8]\d?|[1-9])\b/);
  }
});
