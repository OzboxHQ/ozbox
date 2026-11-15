// A local stand-in for a tunnel, for testing the dashboard's public-address logic: it answers HTTPS for a fake
// host name (with a throwaway certificate made here) and forwards every request, with its Host and Origin headers
// untouched, to a loopback `ozbox serve`. It never listens on anything but 127.0.0.1.
//
//   node scripts/local-public-proxy.mjs --listen 8443 --upstream 4177 --host ozbox.example.test
//
// Prints "ready" once it is listening. The browser under test maps the fake host name to 127.0.0.1 itself
// (Chromium --host-resolver-rules) and accepts the throwaway certificate.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const listen = Number(arg('listen', '8443'));
const upstream = Number(arg('upstream', '4177'));
const host = arg('host', 'ozbox.example.test');
if (!/^[a-z0-9.-]+$/.test(host) || !Number.isInteger(listen) || !Number.isInteger(upstream)) {
  console.error('local-public-proxy: bad arguments');
  process.exit(2);
}

const dir = mkdtempSync(join(tmpdir(), 'ozbox-proxy-'));
try {
  execFileSync(
    'openssl',
    ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2', '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host}`, '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')],
    { stdio: 'ignore' },
  );
} catch {
  console.error('local-public-proxy: openssl is needed to make the throwaway certificate');
  process.exit(3);
}
const tls = { key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) };
rmSync(dir, { recursive: true, force: true });

const server = https.createServer(tls, (req, res) => {
  const out = http.request({ host: '127.0.0.1', port: upstream, method: req.method, path: req.url, headers: req.headers }, (back) => {
    res.writeHead(back.statusCode ?? 502, back.headers);
    back.pipe(res);
  });
  out.on('error', () => {
    res.writeHead(502);
    res.end();
  });
  req.pipe(out);
});
server.listen(listen, '127.0.0.1', () => console.log('ready'));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
