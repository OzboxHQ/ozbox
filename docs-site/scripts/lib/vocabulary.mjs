// Words that must never reach a public docs page. Patterns are assembled from parts so this file does not match itself.
// Each entry: [what it gives away, pattern].
const p = (...parts) => parts.join('');
export const FORBIDDEN_ANYWHERE = [
  ['a private product or company name', new RegExp(p('cli', 'nik'), 'i')],
  ['a private product or company name', new RegExp(p('bett', 'ar'), 'i')],
  ['a private product or company name', new RegExp(p('oz', 'ni'), 'i')],
  ['a private database vendor project', new RegExp(p('supa', 'base'), 'i')],
  ['a private path', new RegExp(p('/clini', 'kehr/'), 'i')],
  ['a private hostname', /\b[\w-]+\.(internal|corp|intranet)\b/i],
  ['a private cloud host name', /\bec2-\d+-\d+-\d+-\d+\./i],
  ['a person\'s account name', new RegExp(p('jem', 'agaji'), 'i')],
];

// A compliance or certification claim is never made about the project: controls are described, not certifications.
const frameworks = p('HIP', 'AA|SOC ?2|ISO[ /A-Z]*27001|ISO ?27701|HIT', 'RUST|PCI[ -]?DSS|GD', 'PR|Fed', 'RAMP');
const claims = 'compliant|certified|compliance|certification|attested|attestation|audited';
FORBIDDEN_ANYWHERE.push([
  'a compliance or certification claim (describe the control instead)',
  new RegExp(`(${frameworks})[ -]+(${claims})|(${claims})[ ]+(with|to|for|against)[ ]+(${frameworks})`, 'i'),
]);

// Only checked in prose (outside code), because a code sample may show a placeholder account id.
export const FORBIDDEN_IN_PROSE = [
  ['an AWS account id', /(?<![\d.])\d{12}(?![\d.])/],
];
