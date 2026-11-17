import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  bytesEqual,
  concatBytes,
  fromBase64Url,
  fromHex,
  randomBytes,
  readU32,
  toBase64Url,
  toHex,
  u32be,
  utf8Decode,
  utf8Encode,
} from '../../resources/assets/js/core/bytes.js';

test('base64url known vector and empty input', () => {
  assert.equal(toBase64Url(new Uint8Array([0xfb, 0xff])), '-_8');
  assert.deepEqual(fromBase64Url('-_8'), new Uint8Array([0xfb, 0xff]));
  assert.equal(toBase64Url(new Uint8Array()), '');
  assert.equal(fromBase64Url('').length, 0);
});

test('base64url round-trips every length up to 300 bytes', () => {
  for (let length = 0; length <= 300; length++) {
    const bytes = randomBytes(length);
    const text = toBase64Url(bytes);
    assert.match(text, /^[A-Za-z0-9_-]*$/);
    assert.ok(bytesEqual(fromBase64Url(text), bytes));
  }
});

test('base64url rejects the standard alphabet, padding, bad lengths and non-canonical bits', () => {
  for (const bad of ['ab+c', 'ab/c', 'YQ==', 'YW Jj', 'abcde', 'YR']) {
    assert.throws(() => fromBase64Url(bad), TypeError, bad);
  }
});

test('large buffers encode without stack overflow', () => {
  const big = randomBytes(1 << 20);
  assert.ok(bytesEqual(fromBase64Url(toBase64Url(big)), big));
});

test('u32be and readU32 are inverse and range checked', () => {
  for (const value of [0, 1, 255, 256, 65535, 0x12345678, 0xffffffff]) {
    assert.equal(readU32(u32be(value), 0), value);
  }
  assert.deepEqual(u32be(0x01020304), new Uint8Array([1, 2, 3, 4]));
  assert.throws(() => u32be(-1), RangeError);
  assert.throws(() => u32be(2 ** 32), RangeError);
  assert.throws(() => u32be(1.5), RangeError);
  assert.throws(() => readU32(new Uint8Array(3), 0), RangeError);
});

test('readU32 honours subarray offsets', () => {
  const backing = new Uint8Array([9, 9, 0, 0, 1, 0]);
  assert.equal(readU32(backing.subarray(2), 0), 256);
});

test('concatBytes joins parts in order', () => {
  const joined = concatBytes(new Uint8Array([1]), new Uint8Array(), new Uint8Array([2, 3]));
  assert.deepEqual(joined, new Uint8Array([1, 2, 3]));
});

test('utf8 round-trips astral characters and rejects malformed input', () => {
  const text = 'Mật khẩu \u{1F510} \u{20000}';
  assert.equal(utf8Decode(utf8Encode(text)), text);
  assert.throws(() => utf8Decode(new Uint8Array([0xc3, 0x28])), TypeError);
});

test('hex helpers round-trip and validate', () => {
  const bytes = new Uint8Array([0, 15, 16, 255]);
  assert.equal(toHex(bytes), '000f10ff');
  assert.deepEqual(fromHex('000f10ff'), bytes);
  assert.throws(() => fromHex('abc'), TypeError);
  assert.throws(() => fromHex('ZZ'), TypeError);
});

test('randomBytes fills buffers larger than the getRandomValues limit', () => {
  const bytes = randomBytes(200000);
  assert.equal(bytes.length, 200000);
  assert.ok(bytes.subarray(150000).some((b) => b !== 0));
});
