import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
const [,, S] = process.argv;
const require = createRequire(S + '/pptr/package.json');
const puppeteer = require('puppeteer-core');
const html = `<!doctype html><meta charset=utf-8><title>t</title><script>
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const fromb64u=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
window.reg=async(ch,uv)=>{const c=await navigator.credentials.create({publicKey:{challenge:fromb64u(ch),rp:{name:'Vec',id:'localhost'},user:{id:new Uint8Array([1,2,3,4]),name:'vec',displayName:'vec'},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{userVerification:uv,residentKey:'discouraged'},attestation:'direct'}});
 return {id:b64u(c.rawId),att:b64u(c.response.attestationObject),cd:b64u(c.response.clientDataJSON),spki:b64u(c.response.getPublicKey())}};
window.get=async(ch,id,uv)=>{const c=await navigator.credentials.get({publicKey:{challenge:fromb64u(ch),rpId:'localhost',allowCredentials:[{type:'public-key',id:fromb64u(id)}],userVerification:uv}});
 return {cd:b64u(c.response.clientDataJSON),ad:b64u(c.response.authenticatorData),sig:b64u(c.response.signature)}};
</script>`;
const srv = http.createServer((q, r) => { r.setHeader('content-type', 'text/html'); r.end(html); });
await new Promise(r => srv.listen(0, '127.0.0.1', r));
const port = srv.address().port;
const exe = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const browser = await puppeteer.launch({ executablePath: exe, headless: true, args: ['--no-first-run', '--user-data-dir=' + S + '/work/chrome-profile'] });
const out = [];
try {
  const ver = await browser.version();
  const page = await browser.newPage();
  await page.goto('http://localhost:' + port + '/');
  const cdp = await page.createCDPSession();
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const b64u = b => Buffer.from(b).toString('base64url');
  for (const [cred, regUV] of [['A', 'required'], ['B', 'discouraged']]) {
    const rch = crypto.randomBytes(32);
    const reg = await page.evaluate((c, u) => window.reg(c, u), b64u(rch), regUV);
    const attObj = Buffer.from(reg.att, 'base64url');
    const fmtM = attObj.toString('latin1').match(/fmt.(\w+)/);
    const spki = Buffer.from(reg.spki, 'base64url');
    const xy = spki.subarray(spki.length - 64);
    const credEntries = [];
    for (const uv of cred === 'A' ? ['required', 'required', 'required', 'preferred', 'discouraged'] : ['discouraged', 'discouraged', 'required']) {
      const ch = crypto.randomBytes(32);
      const a = await page.evaluate((c, i, u) => window.get(c, i, u), b64u(ch), reg.id, uv);
      const cd = Buffer.from(a.cd, 'base64url'), ad = Buffer.from(a.ad, 'base64url');
      out.push({
        tool: 'Google Chrome ' + ver + ' via puppeteer-core ' + require(S + '/pptr/node_modules/puppeteer-core/package.json').version + ', CDP WebAuthn virtual authenticator (ctap2/internal, UV capable)',
        credential_label: cred, requested_userVerification: uv, rpId: 'localhost', origin: 'http://localhost:' + port,
        credential_id: Buffer.from(reg.id, 'base64url').toString('hex'),
        public_key_x: xy.subarray(0, 32).toString('hex'), public_key_y: xy.subarray(32).toString('hex'),
        public_key_spki: spki.toString('hex'),
        challenge: ch.toString('hex'), challenge_b64url: b64u(ch),
        clientDataJSON_hex: cd.toString('hex'), clientDataJSON_utf8: cd.toString('utf8'),
        authenticatorData: ad.toString('hex'), flags: ad[32], counter: ad.readUInt32BE(33),
        signature: Buffer.from(a.sig, 'base64url').toString('hex'),
        registration: { requested_userVerification: regUV, challenge_b64url: b64u(rch), attestationObject: attObj.toString('hex'), fmt: fmtM && fmtM[1], clientDataJSON_utf8: Buffer.from(reg.cd, 'base64url').toString('utf8') },
      });
    }
  }
} finally { await browser.close(); srv.close(); }
fs.writeFileSync(S + '/work/webauthn.json', JSON.stringify(out, null, 1));
for (const e of out) console.log(e.credential_label, e.requested_userVerification, 'flags', e.flags, 'ctr', e.counter, e.registration.fmt);
