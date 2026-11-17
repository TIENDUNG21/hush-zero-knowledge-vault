// End-to-end check in a real browser (headless Edge or Chrome over the
// DevTools protocol) against the real PHP server.
//
//   node scripts/browser-check.mjs [--screenshots docs/screenshots]
//
// It creates text, password-protected and file secrets through the UI, opens
// them, opens a link made by bin/hush, checks that a wrong password does not
// consume a view, and fails on any console error or CSP violation.

import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchBrowser, sleep, waitFor } from './lib/browser.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
/** @param {string} name */
const option = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const screenshotDir = option('--screenshots');
const appPort = Number(process.env.HUSH_E2E_PORT ?? 5146);
const cdpPort = Number(process.env.HUSH_CDP_PORT ?? 5147);
const php = process.env.PHP_BINARY ?? 'php';
const base = `http://127.0.0.1:${appPort}`;

const work = mkdtempSync(join(tmpdir(), 'hush-e2e-'));
const env = { ...process.env, HUSH_DB_PATH: join(work, 'hush.sqlite') };
/** @type {import('node:child_process').ChildProcess[]} */
const children = [];

function cleanup() {
  for (const child of children) {
    child.kill();
  }
  setTimeout(() => rmSync(work, { recursive: true, force: true }), 500).unref();
}

/**
 * @param {import('./lib/browser.mjs').Cdp} cdp
 * @param {string} name
 */
async function screenshot(cdp, name) {
  if (!screenshotDir) {
    return;
  }
  await sleep(250);
  const { data } = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  mkdirSync(resolve(root, screenshotDir), { recursive: true });
  writeFileSync(resolve(root, screenshotDir, `${name}.png`), Buffer.from(data, 'base64'));
  console.log(`  screenshot ${screenshotDir}/${name}.png`);
}

/** @param {boolean} condition @param {string} message */
function check(condition, message) {
  if (!condition) {
    throw new Error(`check failed: ${message}`);
  }
  console.log(`  ok - ${message}`);
}

const byId = (/** @type {string} */ id) => `document.getElementById(${JSON.stringify(id)})`;
const visible = (/** @type {string} */ id) => `!${byId(id)}.hidden`;

async function main() {
  const migrate = spawnSync(php, ['bin/hush-admin', 'migrate'], { cwd: root, env, encoding: 'utf8' });
  if (migrate.status !== 0) {
    throw new Error(`migrate failed: ${migrate.stderr}`);
  }
  const server = spawn(php, ['-S', `127.0.0.1:${appPort}`, 'public/index.php'], { cwd: root, env, stdio: 'ignore' });
  children.push(server);
  await waitFor(`${base}/healthz`);

  const { browser, cdp, problems } = await launchBrowser({
    cdpPort,
    profileDir: join(work, 'profile'),
    // API errors the UI handles on purpose (gone secret, wrong password) are expected.
    expected: (entry) => entry.source === 'network' && /\/api\/secrets\//.test(entry.url ?? ''),
  });
  children.push(browser);

  console.log('create a text secret in the browser');
  const secret = 'Production DB password: 7w!Kq-Hush-2026\nVPN recovery code: 4821-9930-1175';
  await cdp.navigate(`${base}/`);
  await cdp.evaluate(`${byId('secret-text')}.value = ${JSON.stringify(secret)}; ${byId('views')}.value = '1'; true`);
  await screenshot(cdp, 'create');
  await cdp.evaluate(`${byId('create-button')}.click(); true`);
  await cdp.until(visible('result'));
  const link = await cdp.evaluate(`${byId('share-link')}.value`);
  check(/^http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/.test(link), 'share link has the id in the path and the key in the fragment');
  await cdp.evaluate(`document.querySelector('.server-view').open = true; true`);
  await screenshot(cdp, 'created');

  console.log('open it in the browser');
  await cdp.navigate(link);
  await cdp.until(visible('view-locked'));
  await screenshot(cdp, 'view');
  await cdp.evaluate(`${byId('reveal-button')}.click(); true`);
  await cdp.until(visible('view-revealed'));
  check(await cdp.evaluate(`${byId('secret-output')}.textContent`) === secret, 'decrypted text equals the input');
  check(!(await cdp.evaluate('location.href')).includes('#'), 'key removed from the address bar after reveal');
  await screenshot(cdp, 'revealed');
  await cdp.navigate(link);
  await cdp.until(visible('view-error'));
  check((await cdp.evaluate(`${byId('view-error')}.textContent`)).includes('already been viewed'), 'second open reports the secret as gone');

  console.log('password-protected secret: a wrong password must not burn the view');
  await cdp.navigate(`${base}/`);
  await cdp.evaluate(`${byId('secret-text')}.value = 'ssh passphrase: correct horse'; ${byId('password')}.value = 'Mật khẩu'.normalize('NFD'); true`);
  await cdp.evaluate(`${byId('create-button')}.click(); true`);
  await cdp.until(visible('result'));
  const protectedLink = await cdp.evaluate(`${byId('share-link')}.value`);
  await cdp.navigate(protectedLink);
  await cdp.until(visible('view-locked'));
  await cdp.evaluate(`${byId('view-password')}.value = 'wrong'; ${byId('reveal-button')}.click(); true`);
  await cdp.until(visible('view-error'));
  check((await cdp.evaluate(`${byId('view-error')}.textContent`)).includes('No view was used'), 'wrong password is reported before any view is spent');
  await cdp.evaluate(`${byId('view-password')}.value = 'Mật khẩu'.normalize('NFC'); ${byId('reveal-button')}.click(); true`);
  await cdp.until(visible('view-revealed'));
  check(await cdp.evaluate(`${byId('secret-output')}.textContent`) === 'ssh passphrase: correct horse', 'NFC password opens a secret sealed with the NFD spelling');

  console.log('a 1.5 MB file goes up in 512 KiB chunks and comes back intact');
  await cdp.navigate(`${base}/`);
  const uploadedHash = await cdp.evaluate(`(async () => {
    const data = new Uint8Array(1_500_000);
    for (let i = 0; i < data.length; i += 65536) crypto.getRandomValues(data.subarray(i, i + 65536));
    const transfer = new DataTransfer();
    transfer.items.add(new File([data], 'quarterly report.pdf', { type: 'application/pdf' }));
    const input = ${byId('secret-file')};
    input.files = transfer.files;
    input.dispatchEvent(new Event('change'));
    ${byId('tab-file')}.click();
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
  })()`);
  await screenshot(cdp, 'file');
  await cdp.evaluate(`${byId('create-button')}.click(); true`);
  await cdp.until(visible('result'));
  check((await cdp.evaluate(`${byId('server-view')}.textContent`)).includes('3 chunks'), 'file was uploaded as 3 encrypted chunks');
  const fileLink = await cdp.evaluate(`${byId('share-link')}.value`);
  await cdp.navigate(fileLink);
  await cdp.until(visible('view-locked'));
  check((await cdp.evaluate(`${byId('facts')}.textContent`)).includes('quarterly report.pdf'), 'file name is decrypted from the metadata before the view is spent');
  // connect-src 'self' forbids fetching blob: URLs, so capture the Blob as the page creates it.
  await cdp.evaluate(`window.capturedBlobs = []; const original = URL.createObjectURL;
    URL.createObjectURL = (blob) => { window.capturedBlobs.push(blob); return original.call(URL, blob); }; true`);
  await cdp.evaluate(`${byId('reveal-button')}.click(); true`);
  await cdp.until(visible('view-revealed'));
  const downloadedHash = await cdp.evaluate(`(async () => {
    const link = ${byId('download-link')};
    const data = new Uint8Array(await window.capturedBlobs[0].arrayBuffer());
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    return [link.download, Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')].join(' ');
  })()`);
  check(downloadedHash === `quarterly report.pdf ${uploadedHash}`, 'downloaded file has the same name and SHA-256');
  await screenshot(cdp, 'file-revealed');

  console.log('open a link created by bin/hush (OpenSSL) in the browser (WebCrypto)');
  const cliText = 'sent from bin/hush: Mật khẩu \u{1F510}';
  const sent = spawnSync(php, ['bin/hush', 'send', '--server', base], { cwd: root, env, input: cliText, encoding: 'utf8' });
  check(sent.status === 0, `bin/hush send exited 0 ${sent.stderr}`);
  await cdp.navigate(sent.stdout.trim());
  await cdp.until(visible('view-locked'));
  await cdp.evaluate(`${byId('reveal-button')}.click(); true`);
  await cdp.until(visible('view-revealed'));
  check(await cdp.evaluate(`${byId('secret-output')}.textContent`) === cliText, 'browser decrypts what the PHP CLI encrypted');

  console.log('a damaged link is explained');
  await cdp.navigate(link.replace(/#.*/, '#short'));
  await cdp.until(visible('view-error'));
  check((await cdp.evaluate(`${byId('view-error')}.textContent`)).length > 10, 'damaged link shows an error message');

  check(problems.length === 0, `no console errors or CSP violations${problems.length ? `: ${problems.join(' | ')}` : ''}`);
  await cdp.send('Browser.close').catch(() => undefined);
}

main().then(
  () => {
    console.log('browser check passed');
    cleanup();
  },
  (error) => {
    console.error(error instanceof Error ? error.message : error);
    cleanup();
    process.exitCode = 1;
  },
);
