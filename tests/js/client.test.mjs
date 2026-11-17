import assert from 'node:assert/strict';
import { test } from 'node:test';

import { fromBase64Url, randomBytes, toBase64Url } from '../../resources/assets/js/core/bytes.js';
import { openPackage, sealSecret } from '../../resources/assets/js/core/crypto.js';
import { EnvelopeError, packPackage } from '../../resources/assets/js/core/format.js';
import { ApiError, HushApi } from '../../resources/assets/js/client/api.js';
import {
  LinkError,
  buildDeleteLink,
  buildShareLink,
  idFromPath,
  keyFromFragment,
  parseShareLink,
  tokenFromFragment,
} from '../../resources/assets/js/client/links.js';
import { inspectSecret, revealSecret, uploadSealed } from '../../resources/assets/js/client/transfer.js';

const ID = 'AbCdEfGhIjKlMnOpQrStUv';
const TOKEN = 'T'.repeat(43);

/**
 * A fetch stand-in that records requests and replays scripted responses.
 * @param {Array<(url: string, init: RequestInit) => Response | Promise<Response>>} script
 */
function fakeFetch(script) {
  /** @type {Array<{url: string, init: RequestInit}>} */
  const calls = [];
  /** @type {import('../../resources/assets/js/client/api.js').FetchLike} */
  const impl = async (url, init = {}) => {
    calls.push({ url, init });
    const next = script.shift();
    if (!next) {
      throw new Error(`unexpected request ${init.method} ${url}`);
    }
    return next(url, init);
  };
  return { impl, calls };
}

/** @param {unknown} data @param {number} [status] */
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

test('share links carry the key only in the fragment', () => {
  const key = randomBytes(32);
  const link = buildShareLink('https://hush.example/', ID, key);
  assert.equal(link, `https://hush.example/s/${ID}#${toBase64Url(key)}`);
  const parsed = parseShareLink(link);
  assert.equal(parsed.origin, 'https://hush.example');
  assert.equal(parsed.id, ID);
  assert.deepEqual(parsed.key, key);
  assert.equal(new URL(link).pathname.includes(toBase64Url(key)), false);
  assert.equal(buildDeleteLink('https://hush.example', ID, TOKEN), `https://hush.example/d/${ID}#${TOKEN}`);
});

test('damaged links are explained, not crashed on', () => {
  assert.throws(() => keyFromFragment(''), LinkError);
  assert.throws(() => keyFromFragment('#abc'), /wrong length|damaged/);
  assert.throws(() => keyFromFragment('#' + 'A'.repeat(42)), LinkError);
  assert.throws(() => keyFromFragment('#a+b'), /damaged/);
  assert.throws(() => idFromPath('/s/short', 's'), LinkError);
  assert.throws(() => idFromPath(`/x/${ID}`, 's'), LinkError);
  assert.throws(() => tokenFromFragment('#nope'), LinkError);
  assert.equal(tokenFromFragment('#' + TOKEN), TOKEN);
  assert.throws(() => parseShareLink('not a url'), LinkError);
});

test('api uses the right verbs, headers and no credentials', async () => {
  const header = randomBytes(36);
  const meta = randomBytes(284);
  const { impl, calls } = fakeFetch([
    () => json({ id: ID, deletionToken: TOKEN, expiresAt: 10, uploadDeadline: 5, chunkCount: 1 }, 201),
    () => new Response(null, { status: 204 }),
    () => json({ id: ID, state: 'sealed' }),
    () => new Response(null, { status: 204 }),
  ]);
  const api = new HushApi('https://hush.example/', impl);

  const created = await api.create({ header, meta, expiresIn: 3600, maxViews: 1 });
  assert.deepEqual(created, { id: ID, deletionToken: TOKEN, expiresAt: 10, uploadDeadline: 5, chunkCount: 1 });
  await api.putChunk(ID, 0, new Uint8Array([1, 2, 3]), TOKEN);
  await api.seal(ID, TOKEN);
  await api.remove(ID, TOKEN);

  const [create, put, seal, remove] = calls.map((c) => c);
  assert.ok(create && put && seal && remove);
  assert.equal(create.url, 'https://hush.example/api/secrets');
  assert.equal(create.init.method, 'POST');
  assert.deepEqual(JSON.parse(String(create.init.body)), { header: toBase64Url(header), meta: toBase64Url(meta), expiresIn: 3600, maxViews: 1 });
  assert.equal(create.init.credentials, 'omit');
  assert.equal(create.init.redirect, 'error');
  assert.equal(put.init.method, 'PUT');
  assert.equal(put.url, `https://hush.example/api/secrets/${ID}/chunks/0`);
  assert.deepEqual(put.init.headers, { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${TOKEN}` });
  assert.equal(seal.url, `https://hush.example/api/secrets/${ID}/seal`);
  assert.equal(remove.init.method, 'DELETE');
});

test('api maps error bodies and network failures to ApiError', async () => {
  const { impl } = fakeFetch([
    () => json({ error: { code: 'rate_limited', message: 'Too many requests.' } }, 429),
    () => new Response('<html>bad gateway</html>', { status: 502 }),
    () => { throw new TypeError('connection refused'); },
  ]);
  const api = new HushApi('', impl);

  await assert.rejects(() => api.status(ID), (e) => e instanceof ApiError && e.status === 429 && e.code === 'rate_limited' && !e.retryable);
  await assert.rejects(() => api.status(ID), (e) => e instanceof ApiError && e.status === 502 && e.code === 'http_502' && e.retryable);
  await assert.rejects(() => api.status(ID), (e) => e instanceof ApiError && e.status === 0 && e.code === 'network');
});

test('upload creates, sends every chunk with progress, retries once, then seals', async () => {
  const sealed = await sealSecret({ kind: 'file', data: randomBytes(2500), name: 'a.bin', type: null }, { chunkSize: 1024 });
  /** @type {Uint8Array[]} */
  const stored = [];
  let failedOnce = false;
  const { impl, calls } = fakeFetch([
    () => json({ id: ID, deletionToken: TOKEN, expiresAt: 10, uploadDeadline: 5, chunkCount: 3 }, 201),
    ...[0, 1, 2].map(() => async (/** @type {string} */ _url, /** @type {RequestInit} */ init) => {
      if (!failedOnce) {
        failedOnce = true;
        return new Response(null, { status: 503 });
      }
      stored.push(new Uint8Array(/** @type {Uint8Array} */ (init.body)));
      return new Response(null, { status: 204 });
    }),
    async (_url, init) => {
      stored.push(new Uint8Array(/** @type {Uint8Array} */ (init.body)));
      return new Response(null, { status: 204 });
    },
    () => json({ id: ID, state: 'sealed' }),
  ]);
  /** @type {Array<[number, number]>} */
  const progress = [];

  const created = await uploadSealed(new HushApi('', impl), sealed, {
    expiresIn: 600,
    maxViews: 1,
    onProgress: (done, total) => progress.push([done, total]),
  });

  assert.equal(created.id, ID);
  assert.deepEqual(progress, [[0, 3], [1, 3], [2, 3], [3, 3]]);
  assert.equal(calls.filter((c) => c.init.method === 'PUT').length, 4, 'one retry');
  assert.equal(calls.at(-1)?.url, `/api/secrets/${ID}/seal`);
  const opened = await openPackage(packPackage({ headerBytes: sealed.headerBytes, meta: sealed.metaRecord, chunks: /** @type {any} */ (stored) }), sealed.fragmentKey);
  assert.equal(opened.data.length, 2500);
});

test('upload does not retry client errors', async () => {
  const sealed = await sealSecret({ kind: 'text', text: 'x' }, { chunkSize: 1024 });
  const { impl } = fakeFetch([
    () => json({ id: ID, deletionToken: TOKEN, expiresAt: 10, uploadDeadline: 5, chunkCount: 1 }, 201),
    () => json({ error: { code: 'invalid_chunk_length', message: 'bad' } }, 422),
  ]);
  await assert.rejects(() => uploadSealed(new HushApi('', impl), sealed, { expiresIn: 600, maxViews: 1 }), (e) => e instanceof ApiError && e.code === 'invalid_chunk_length');
});

test('inspect checks the password before a view is spent; reveal decrypts', async () => {
  const sealed = await sealSecret({ kind: 'text', text: 'the vault code is 0451' }, { chunkSize: 1024, password: 'pw', iterations: 100000 });
  const pkg = await sealed.toPackage();
  const statusBody = {
    id: ID, passwordProtected: true, expiresAt: 99, viewsLeft: 1, chunkCount: 1, ciphertextBytes: pkg.length,
    header: toBase64Url(sealed.headerBytes), meta: toBase64Url(sealed.metaRecord),
  };
  const { impl, calls } = fakeFetch([
    () => json(statusBody),
    () => json(statusBody),
    () => new Response(pkg, { status: 200, headers: { 'X-Hush-Views-Left': '0' } }),
  ]);
  const api = new HushApi('', impl);

  await assert.rejects(() => inspectSecret(api, ID, sealed.fragmentKey, 'wrong'), (e) => e instanceof EnvelopeError && e.reason === 'authentication');
  const { status, meta } = await inspectSecret(api, ID, sealed.fragmentKey, 'pw');
  assert.equal(status.passwordProtected, true);
  assert.equal(meta.kind, 'text');
  assert.equal(calls.filter((c) => c.url.endsWith('/open')).length, 0, 'no view consumed yet');

  const { opened, viewsLeft } = await revealSecret(api, ID, sealed.fragmentKey, 'pw');
  assert.equal(opened.text, 'the vault code is 0451');
  assert.equal(viewsLeft, 0);
  assert.deepEqual(fromBase64Url(statusBody.header), sealed.headerBytes);
});

test('a 1.2 MB file uploads as three default-sized chunks and decrypts', async () => {
  const data = randomBytes(1_200_000);
  const sealed = await sealSecret({ kind: 'file', data, name: 'backup.tar.gz', type: 'application/gzip' });
  assert.equal(sealed.header.chunkSize, 524288);
  assert.equal(sealed.chunkCount, 3);
  /** @type {Uint8Array[]} */
  const stored = [];
  const { impl } = fakeFetch([
    () => json({ id: ID, deletionToken: TOKEN, expiresAt: 10, uploadDeadline: 5, chunkCount: 3 }, 201),
    ...[0, 1, 2].map(() => async (/** @type {string} */ _url, /** @type {RequestInit} */ init) => {
      stored.push(new Uint8Array(/** @type {Uint8Array} */ (init.body)));
      return new Response(null, { status: 204 });
    }),
    () => json({ id: ID, state: 'sealed' }),
  ]);
  await uploadSealed(new HushApi('', impl), sealed, { expiresIn: 600, maxViews: 1 });

  assert.deepEqual(stored.map((c) => c.length), [524288 + 28, 524288 + 28, 151552 + 28]);
  assert.equal(sealed.ciphertextBytes, sealed.metaRecord.length + stored.reduce((n, c) => n + c.length, 0));
  const pkg = packPackage({ headerBytes: sealed.headerBytes, meta: sealed.metaRecord, chunks: /** @type {any} */ (stored) });
  const opened = await openPackage(pkg, sealed.fragmentKey);
  assert.deepEqual(opened.data, data);
  assert.equal(opened.name, 'backup.tar.gz');
});
