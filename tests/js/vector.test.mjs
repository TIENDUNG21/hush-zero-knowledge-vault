// The JavaScript implementation must reproduce, byte for byte, the packages
// that the PHP implementation wrote to tests/fixtures/vector-v1.json.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { fromBase64Url, fromHex, toBase64Url } from '../../resources/assets/js/core/bytes.js';
import { openPackage, sealSecret } from '../../resources/assets/js/core/crypto.js';

const fixture = JSON.parse(readFileSync(new URL('../fixtures/vector-v1.json', import.meta.url), 'utf8'));

/** @param {any} vector */
function input(vector) {
  return vector.input.kind === 'text'
    ? { kind: /** @type {const} */ ('text'), text: vector.input.text }
    : { kind: /** @type {const} */ ('file'), data: fromHex(vector.input.dataHex), name: vector.input.name, type: vector.input.type };
}

for (const vector of fixture.vectors) {
  test(`seal reproduces PHP vector: ${vector.name}`, async () => {
    const nonces = vector.nonces.map((/** @type {string} */ hex) => fromHex(hex));
    const sealed = await sealSecret(input(vector), {
      password: vector.password ?? undefined,
      iterations: vector.iterations,
      chunkSize: vector.chunkSize,
      fragmentKey: fromHex(vector.fragmentKey),
      salt: fromHex(vector.salt),
      nonces: () => nonces.shift(),
    });
    assert.equal(toBase64Url(await sealed.toPackage()), vector.package);
    assert.equal(toBase64Url(sealed.fragmentKey), vector.linkKey);
  });

  test(`open recovers PHP vector: ${vector.name}`, async () => {
    const opened = await openPackage(fromBase64Url(vector.package), fromBase64Url(vector.linkKey), vector.password);
    const expected = input(vector);
    if (expected.kind === 'text') {
      assert.equal(opened.text, expected.text);
    } else {
      assert.deepEqual(opened.data, expected.data);
      assert.equal(opened.name, expected.name);
      assert.equal(opened.type, expected.type);
    }
  });
}

test('the Vietnamese password vector also opens with its NFD spelling', async () => {
  const vector = fixture.vectors.find((/** @type {any} */ v) => v.name === 'text with Vietnamese password');
  assert.ok(vector);
  const nfd = vector.password.normalize('NFD');
  assert.notEqual(nfd, vector.password);
  const opened = await openPackage(fromBase64Url(vector.package), fromBase64Url(vector.linkKey), nfd);
  assert.equal(opened.text, vector.input.text);
});
