// Headless Edge or Chrome driven over the DevTools protocol, shared by
// scripts/browser-check.mjs and scripts/check-site.mjs.

import { spawn } from 'node:child_process';

export const sleep = (/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms));

export const defaultBrowserPath = process.env.BROWSER_PATH
  ?? (process.platform === 'win32' ? 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' : 'google-chrome');

export async function waitFor(/** @type {string} */ url, /** @type {number} */ timeoutMs = 15000) {
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
export class Cdp {
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
}

/**
 * Starts a headless browser with a fresh profile and connects to its first
 * page. Every uncaught exception, console.error and security log entry is
 * collected in `problems`, except log entries for which `expected` is true.
 *
 * @param {{cdpPort: number, profileDir: string, browserPath?: string, expected?: (entry: any) => boolean}} options
 */
export async function launchBrowser({ cdpPort, profileDir, browserPath = defaultBrowserPath, expected = () => false }) {
  const browser = spawn(browserPath, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
    `--remote-debugging-port=${cdpPort}`, `--user-data-dir=${profileDir}`, '--window-size=1200,860',
    // Ubuntu 24.04 CI runners restrict the user namespaces Chrome's sandbox needs;
    // the pages loaded there are our own.
    ...(process.env.CI ? ['--no-sandbox'] : []),
    'about:blank',
  ], { stdio: 'ignore' });
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
    if (method === 'Log.entryAdded' && (params.entry.level === 'error' || params.entry.source === 'security') && !expected(params.entry)) {
      problems.push(`log: ${params.entry.text} ${params.entry.url ?? ''}`);
    }
  });
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Log.enable');
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1200, height: 860, deviceScaleFactor: 1, mobile: false });
  return { browser, cdp, problems };
}
