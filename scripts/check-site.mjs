// Checks the built site (dist/site) the way GitHub Pages serves it: under
// /hush-zero-knowledge-vault/ on a plain static server.
//
//   node scripts/build-site.mjs && node scripts/check-site.mjs
//
// 1. Every src/href in index.html and every relative import in the served
//    modules resolves to a file (no absolute paths that would escape the base).
// 2. In headless Edge, the inspector seals, opens, and rejects both tampered
//    packages, with no console errors or CSP violations.

import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchBrowser } from './lib/browser.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const site = join(root, 'dist', 'site');
const basePath = '/hush-zero-knowledge-vault/';
const port = Number(process.env.HUSH_SITE_PORT ?? 5148);
const cdpPort = Number(process.env.HUSH_CDP_PORT ?? 5147);
const types = /** @type {Record<string, string>} */ ({
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png',
});

/** @param {boolean} condition @param {string} message */
function check(condition, message) {
  if (!condition) {
    throw new Error(`check failed: ${message}`);
  }
  console.log(`  ok - ${message}`);
}

if (!existsSync(join(site, 'index.html'))) {
  throw new Error('dist/site is missing; run node scripts/build-site.mjs first');
}

console.log('static references');
const html = readFileSync(join(site, 'index.html'), 'utf8');
const refs = [...html.matchAll(/\s(?:src|href)="([^"]+)"/g)].map((m) => /** @type {string} */ (m[1]));
const local = refs.filter((ref) => !/^https?:\/\//.test(ref));
check(local.every((ref) => !ref.startsWith('/')), 'no root-relative URLs in index.html');
for (const ref of local.filter((r) => r !== './')) {
  check(existsSync(join(site, ref)), `index.html -> ${ref}`);
}
for (const module of ['inspector.js', 'core/crypto.js', 'core/format.js', 'core/bytes.js']) {
  const source = readFileSync(join(site, module), 'utf8');
  for (const [, spec] of source.matchAll(/from '([^']+)'/g)) {
    check(existsSync(join(site, dirname(module), /** @type {string} */ (spec))), `${module} imports ${spec}`);
  }
}

const server = createServer((request, response) => {
  const path = decodeURIComponent(new URL(request.url ?? '/', 'http://x').pathname);
  if (!path.startsWith(basePath)) {
    response.writeHead(404).end();
    return;
  }
  let file = normalize(join(site, path.slice(basePath.length)));
  if (!file.startsWith(site)) {
    response.writeHead(403).end();
    return;
  }
  if (path.endsWith('/')) {
    file = join(file, 'index.html');
  }
  if (!existsSync(file)) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream' });
  response.end(readFileSync(file));
});
await new Promise((done) => server.listen(port, '127.0.0.1', () => done(undefined)));

const work = mkdtempSync(join(tmpdir(), 'hush-site-'));
const { browser, cdp, problems } = await launchBrowser({ cdpPort, profileDir: join(work, 'profile') });
const byId = (/** @type {string} */ id) => `document.getElementById(${JSON.stringify(id)})`;
const text = (/** @type {string} */ id) => cdp.evaluate(`${byId(id)}.textContent`);

try {
  console.log(`inspector under http://127.0.0.1:${port}${basePath}`);
  await cdp.navigate(`http://127.0.0.1:${port}${basePath}`);
  check(await cdp.evaluate(`[...document.images].every((i) => i.complete && i.naturalWidth > 0)`), 'logo and screenshots load');

  await cdp.evaluate(`${byId('inspect-password')}.value = 'pässwörd'; ${byId('inspect-seal')}.click(); true`);
  await cdp.until(`!${byId('inspect-output')}.hidden && ${byId('inspect-roundtrip')}.textContent !== ''`);
  check((await text('inspect-roundtrip')).includes('matches byte for byte'), 'sealed and opened again in the page');
  check((await text('inspect-hex')).startsWith('48 55 53 48 01 01'), 'header starts with "HUSH", version 1, password flag');
  check((await text('inspect-link')).length > 43, 'link shows a fragment key');

  await cdp.evaluate(`${byId('tamper-header')}.click(); true`);
  await cdp.until(`${byId('tamper-result')}.className !== ''`);
  check((await text('tamper-result')).includes('Refused: authentication'), 'flipped header bit is refused');
  await cdp.evaluate(`${byId('tamper-result')}.className = ''; ${byId('tamper-chunk')}.click(); true`);
  await cdp.until(`${byId('tamper-result')}.className !== ''`);
  check((await text('tamper-result')).includes('Refused: authentication'), 'flipped ciphertext bit is refused');

  check(problems.length === 0, `no console errors or CSP violations${problems.length ? `: ${problems.join(' | ')}` : ''}`);
  console.log('site check passed');
} finally {
  await cdp.send('Browser.close').catch(() => undefined);
  browser.kill();
  server.close();
  setTimeout(() => rmSync(work, { recursive: true, force: true }), 500).unref();
}
