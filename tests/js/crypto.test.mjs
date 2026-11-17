import assert from 'node:assert/strict';
import { test } from 'node:test';

import { randomBytes } from '../../resources/assets/js/core/bytes.js';
import { openEnvelope, openMeta, openPackage, sealSecret } from '../../resources/assets/js/core/crypto.js';
import { EnvelopeError, unpackPackage } from '../../resources/assets/js/core/format.js';

const FAST = { chunkSize: 1024, iterations: 100000 };

/**
 * @param {() => Promise<unknown>} fn
 * @param {string} reason
 */
async function rejectsWith(fn, reason) {
  await assert.rejects(fn, (error) => {
    assert.ok(error instanceof EnvelopeError, String(error));
    assert.equal(error.reason, reason, error.message);
    return true;
  });
}

test('text round-trips byte-exact, including astral and zero-width characters', async () => {
  const text = 'Mật khẩu: \u{1F510} \u{20000}\r\nzero​width';
  const sealed = await sealSecret({ kind: 'text', text }, FAST);
  const opened = await openPackage(await sealed.toPackage(), sealed.fragmentKey);
  assert.equal(opened.kind, 'text');
  assert.equal(opened.text, text);
  assert.equal(opened.name, null);
});

test('NFC and NFD text stay distinct: content is never normalized', async () => {
  const nfd = 'Mật'.normalize('NFD');
  const sealed = await sealSecret({ kind: 'text', text: nfd }, FAST);
  const opened = await openPackage(await sealed.toPackage(), sealed.fragmentKey);
  assert.equal(opened.text, nfd);
  assert.notEqual(opened.text, 'Mật'.normalize('NFC'));
});

test('short secrets produce packages of identical size', async () => {
  const a = await (await sealSecret({ kind: 'text', text: 'no' }, FAST)).toPackage();
  const b = await (await sealSecret({ kind: 'text', text: 'y'.repeat(250) }, FAST)).toPackage();
  assert.equal(a.length, b.length);
});

test('multi-chunk file round-trip keeps name and type', async () => {
  const data = randomBytes(2500);
  const sealed = await sealSecret({ kind: 'file', data, name: 'scan.png', type: 'image/png' }, FAST);
  assert.equal(sealed.chunkCount, 3);
  const opened = await openPackage(await sealed.toPackage(), sealed.fragmentKey);
  assert.deepEqual(opened.data, data);
  assert.equal(opened.name, 'scan.png');
  assert.equal(opened.type, 'image/png');
  assert.equal(opened.text, null);
});

test('empty file and exact chunk multiples', async () => {
  const empty = await sealSecret({ kind: 'file', data: new Uint8Array(), name: 'empty', type: null }, FAST);
  assert.equal((await openPackage(await empty.toPackage(), empty.fragmentKey)).data.length, 0);
  const exact = await sealSecret({ kind: 'file', data: randomBytes(2048), name: 'x', type: null }, FAST);
  assert.equal(exact.chunkCount, 2);
});

test('password is required, checked, and NFC-normalized', async () => {
  const nfc = 'Mật khẩu';
  const sealed = await sealSecret({ kind: 'text', text: 'pin 4321' }, { ...FAST, password: nfc.normalize('NFD') });
  const pkg = await sealed.toPackage();
  assert.equal(sealed.header.passwordProtected, true);
  assert.equal((await openPackage(pkg, sealed.fragmentKey, nfc)).text, 'pin 4321');
  await rejectsWith(() => openPackage(pkg, sealed.fragmentKey), 'password_required');
  await rejectsWith(() => openPackage(pkg, sealed.fragmentKey, 'Mat khau'), 'authentication');
  await rejectsWith(() => openPackage(pkg, randomBytes(32), nfc), 'authentication');
});

test('wrong or malformed link keys fail', async () => {
  const sealed = await sealSecret({ kind: 'text', text: 'x' }, FAST);
  const pkg = await sealed.toPackage();
  await rejectsWith(() => openPackage(pkg, randomBytes(32)), 'authentication');
  await rejectsWith(() => openPackage(pkg, randomBytes(31)), 'format');
});

test('openMeta verifies key and password without touching chunks', async () => {
  const sealed = await sealSecret({ kind: 'file', data: randomBytes(10), name: 'a.txt', type: 'text/plain' }, { ...FAST, password: 'pw' });
  const { meta } = await openMeta(sealed.headerBytes, sealed.metaRecord, sealed.fragmentKey, 'pw');
  assert.deepEqual(meta, { kind: 'file', name: 'a.txt', type: 'text/plain', size: 10 });
  await rejectsWith(() => openMeta(sealed.headerBytes, sealed.metaRecord, sealed.fragmentKey, 'nope'), 'authentication');
});

/** @param {Uint8Array} bytes @param {number} offset */
function flip(bytes, offset) {
  const copy = bytes.slice();
  copy[offset] = (copy[offset] ?? 0) ^ 1;
  return copy;
}

test('tampering of any kind is detected', async () => {
  const sealed = await sealSecret({ kind: 'file', data: randomBytes(2500), name: 'a.bin', type: null }, FAST);
  const env = unpackPackage(await sealed.toPackage());
  const [c0, c1, c2] = /** @type {[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]} */ (env.chunks);
  const key = sealed.fragmentKey;
  const cases = [
    ['swap chunks', { ...env, chunks: [c1, c0, c2] }, 'authentication'],
    ['drop last chunk', { ...env, chunks: [c0, c1] }, 'integrity'],
    ['duplicate chunk', { ...env, chunks: [c0, c0, c2] }, 'authentication'],
    ['flip ciphertext bit', { ...env, chunks: [c0, flip(c1, 40), c2] }, 'authentication'],
    ['flip nonce bit', { ...env, chunks: [flip(c0, 0), c1, c2] }, 'authentication'],
    ['flip tag bit', { ...env, chunks: [c0, c1, flip(c2, c2.length - 1)] }, 'authentication'],
    ['flip meta bit', { ...env, meta: flip(env.meta, 20) }, 'authentication'],
    ['flip salt bit', { ...env, headerBytes: flip(env.headerBytes, 13) }, 'authentication'],
  ];
  for (const [name, envelope, reason] of cases) {
    await rejectsWith(() => openEnvelope(/** @type {any} */ (envelope), key), /** @type {string} */ (reason));
    assert.ok(name);
  }
});

test('records from another envelope with the same key are rejected', async () => {
  const fragmentKey = randomBytes(32);
  const one = await sealSecret({ kind: 'text', text: 'one' }, { ...FAST, fragmentKey });
  const two = await sealSecret({ kind: 'text', text: 'two' }, { ...FAST, fragmentKey });
  const mixed = { headerBytes: one.headerBytes, meta: one.metaRecord, chunks: [await two.encryptChunk(0)] };
  await rejectsWith(() => openEnvelope(mixed, fragmentKey), 'authentication');
});

test('fresh key, salt and nonces on every seal', async () => {
  const a = await sealSecret({ kind: 'text', text: 'same' }, FAST);
  const b = await sealSecret({ kind: 'text', text: 'same' }, FAST);
  assert.notDeepEqual(a.fragmentKey, b.fragmentKey);
  assert.notDeepEqual(a.header.salt, b.header.salt);
  assert.notDeepEqual(a.metaRecord.subarray(0, 12), b.metaRecord.subarray(0, 12));
  assert.notDeepEqual(await a.encryptChunk(0), await a.encryptChunk(0));
});

test('chunk index is range checked', async () => {
  const sealed = await sealSecret({ kind: 'text', text: 'x' }, FAST);
  await assert.rejects(() => sealed.encryptChunk(1), RangeError);
  await assert.rejects(() => sealed.encryptChunk(-1), RangeError);
});
