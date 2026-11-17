// End-to-end check in a real browser (headless Edge or Chrome over the
// DevTools protocol) against the real PHP server.
//
//   node scripts/browser-check.mjs [--screenshots docs/screenshots] [--cli-link <url> --cli-text <text>]
//
// It creates a text secret and a password-protected secret through the UI,
// opens both links, checks the decrypted text, checks that a wrong password
// does not consume a view, and fails on any console error or CSP violation.

import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
const browserPath = process.env.BROWSER_PATH
  ?? (process.platform === 'win32' ? 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' : 'google-chrome');
const base = `http://127.0.0.1:${appPort}`;
const sleep = (/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms));

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

async function waitFor(/** @type {string} */ url, /** @type {number} */ timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return response;
      }
    } catch {
      // not up yet
    }
    await sleep(150);
  }
  throw new Error(`${url} did not respond`);
}

/** Minimal DevTools protocol client over Node's built-in WebSocket. */
class Cdp {
  /** @param {string} url */
  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolveOpen, rejectOpen) => {
      socket.addEventListener('open', resolveOpen, { once: true });
      socket.addEventListener('error', rejectOpen, { once: true });
    });
    return new Cdp(socket);
  }

  /** @param {WebSocket} socket */
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    /** @type {Map<number, {resolve: (v: any) => void, reject: (e: Error) => void}>} */
    this.pending = new Map();
    /** @type {Array<(method: string, params: any) => void>} */
    this.listeners = [];
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id && this.pending.has(message.id)) {
        const { resolve: done, reject } = /** @type {any} */ (this.pending.get(message.id));
        this.pending.delete(message.id);
        if (message.error) {
          reject(new Error(message.error.message));
        } else {
          done(message.result);
        }
      } else if (message.method) {
        for (const listener of this.listeners) {
          listener(message.method, message.params);
        }
      }
    });
  }

  /** @param {string} method @param {object} [params] @returns {Promise<any>} */
  send(method, params = {}) {
    const id = this.nextId++;
    this.socket.send(JSON.stringify({ id, method, params }));
    return new Promise((done, reject) => this.pending.set(id, { resolve: done, reject }));
  }

  /** @param {string} expression */
  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) {
      throw new Error(`evaluate failed: ${result.exceptionDetails.text} ${expression}`);
    }
    return result.result.value;
  }

  /** @param {string} expression @param {number} [timeoutMs] */
  async until(expression, timeoutMs = 20000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await this.evaluate(expression)) {
        return;
      }
      await sleep(100);
    }
    throw new Error(`timed out waiting for: ${expression}`);
  }

  /**
   * Full navigation with a load event (via about:blank, so a URL that differs
   * from the current one only by its fragment still loads a fresh page).
   * @param {string} url
   */
  async navigate(url) {
    await this.load('about:blank');
    await this.load(url);
  }

  /** @param {string} url */
  async load(url) {
    const loaded = new Promise((done) => {
      const listener = (/** @type {string} */ method) => {
        if (method === 'Page.loadEventFired') {
          this.listeners.splice(this.listeners.indexOf(listener), 1);
          done(undefined);
        }
      };
      this.listeners.push(listener);
    });
    await this.send('Page.navigate', { url });
    await loaded;
  }

  /** @param {string} name */
  async screenshot(name) {
    if (!screenshotDir) {
      return;
    }
    await sleep(250);
    const { data } = await this.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    mkdirSync(resolve(root, screenshotDir), { recursive: true });
    writeFileSync(resolve(root, screenshotDir, `${name}.png`), Buffer.from(data, 'base64'));
    console.log(`  screenshot ${screenshotDir}/${name}.png`);
  }
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

  const browser = spawn(browserPath, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
    `--remote-debugging-port=${cdpPort}`, `--user-data-dir=${join(work, 'profile')}`, '--window-size=1200,860', 'about:blank',
  ], { stdio: 'ignore' });
  children.push(browser);
  await waitFor(`http://127.0.0.1:${cdpPort}/json/version`);
  const targets = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
  const page = targets.find((/** @type {any} */ t) => t.type === 'page');
  const cdp = await Cdp.connect(page.webSocketDebuggerUrl);

  /** @type {string[]} */
  const problems = [];
  cdp.listeners.push((method, params) => {
    if (method === 'Runtime.exceptionThrown') {
      problems.push(`exception: ${params.exceptionDetails.exception?.description ?? params.exceptionDetails.text}`);
    }
    if (method === 'Runtime.consoleAPICalled' && params.type === 'error') {
      problems.push(`console.error: ${params.args.map((/** @type {any} */ a) => a.value ?? a.description).join(' ')}`);
    }
    if (method === 'Log.entryAdded' && (params.entry.level === 'error' || params.entry.source === 'security')) {
      // API errors the UI handles on purpose (gone secret, wrong password) are expected.
      const expected = params.entry.source === 'network' && /\/api\/secrets\//.test(params.entry.url ?? '');
      if (!expected) {
        problems.push(`log: ${params.entry.text} ${params.entry.url ?? ''}`);
      }
    }
  });
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Log.enable');
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1200, height: 860, deviceScaleFactor: 1, mobile: false });

  console.log('create a text secret in the browser');
  const secret = 'Production DB password: 7w!Kq-Hush-2026\nVPN recovery code: 4821-9930-1175';
  await cdp.navigate(`${base}/`);
  await cdp.evaluate(`${byId('secret-text')}.value = ${JSON.stringify(secret)}; ${byId('views')}.value = '1'; true`);
  await cdp.screenshot('create');
  await cdp.evaluate(`${byId('create-button')}.click(); true`);
  await cdp.until(visible('result'));
  const link = await cdp.evaluate(`${byId('share-link')}.value`);
  check(/^http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/.test(link), 'share link has the id in the path and the key in the fragment');
  await cdp.evaluate(`document.querySelector('.server-view').open = true; true`);
  await cdp.screenshot('created');

  console.log('open it in the browser');
  await cdp.navigate(link);
  await cdp.until(visible('view-locked'));
  await cdp.screenshot('view');
  await cdp.evaluate(`${byId('reveal-button')}.click(); true`);
  await cdp.until(visible('view-revealed'));
  check(await cdp.evaluate(`${byId('secret-output')}.textContent`) === secret, 'decrypted text equals the input');
  check(!(await cdp.evaluate('location.href')).includes('#'), 'key removed from the address bar after reveal');
  await cdp.screenshot('revealed');
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

  const cliLink = option('--cli-link');
  if (cliLink) {
    console.log('open a link created by bin/hush');
    await cdp.navigate(cliLink);
    await cdp.until(visible('view-locked'));
    await cdp.evaluate(`${byId('reveal-button')}.click(); true`);
    await cdp.until(visible('view-revealed'));
    check(await cdp.evaluate(`${byId('secret-output')}.textContent`) === option('--cli-text'), 'browser decrypts what the PHP CLI encrypted');
  }

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
