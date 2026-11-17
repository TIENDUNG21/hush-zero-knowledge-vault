import assert from 'node:assert/strict';
import { test } from 'node:test';

import { concatBytes, u32be, utf8Decode, utf8Encode } from '../../resources/assets/js/core/bytes.js';
import {
  EnvelopeError,
  chooseChunkSize,
  chunkCountFor,
  encodeHeader,
  encodeMeta,
  packPackage,
  paddedLength,
  parseHeader,
  parseMeta,
  recordAad,
  reservedBytes,
  safeFileMeta,
  unpackPackage,
} from '../../resources/assets/js/core/format.js';

const salt = new Uint8Array(16).fill(7);
const baseHeader = { passwordProtected: false, iterations: 0, salt, chunkSize: 1024, chunkCount: 1 };

/**
 * @param {() => unknown} fn
 * @param {string} reason
 * @param {RegExp} [message]
 */
function assertEnvelopeError(fn, reason, message) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof EnvelopeError, String(error));
    assert.equal(error.reason, reason);
    if (message) {
      assert.match(error.message, message);
    }
    return true;
  });
}

test('header round-trips and matches the documented layout', () => {
  const header = { passwordProtected: true, iterations: 600000, salt, chunkSize: 524288, chunkCount: 3 };
  const bytes = encodeHeader(header);
  assert.equal(bytes.length, 36);
  assert.equal(utf8Decode(bytes.subarray(0, 4)), 'HUSH');
  assert.deepEqual([...bytes.subarray(4, 8)], [1, 1, 0, 0]);
  assert.deepEqual(bytes.subarray(8, 12), u32be(600000));
  assert.deepEqual(parseHeader(bytes), header);
});

test('malformed headers are rejected with a reason', () => {
  const valid = encodeHeader(baseHeader);
  /** @param {number} offset @param {number[]} values */
  const patched = (offset, values) => {
    const copy = valid.slice();
    copy.set(values, offset);
    return copy;
  };
  assertEnvelopeError(() => parseHeader(valid.subarray(0, 35)), 'format', /36 bytes/);
  assertEnvelopeError(() => parseHeader(patched(0, [0x58])), 'format', /magic/);
  assertEnvelopeError(() => parseHeader(patched(4, [2])), 'format', /version 2/);
  assertEnvelopeError(() => parseHeader(patched(5, [2])), 'format', /flags 0x02/);
  assertEnvelopeError(() => parseHeader(patched(6, [0, 1])), 'format', /Reserved/);
  assertEnvelopeError(() => parseHeader(patched(8, [0, 0, 0, 5])), 'format', /must be 0/);
  assertEnvelopeError(() => parseHeader(patched(5, [1])), 'format', /iterations/);
  assertEnvelopeError(() => parseHeader(concatBytes(patched(5, [1]).subarray(0, 8), u32be(0xffffffff), valid.subarray(12))), 'format', /iterations/);
  assertEnvelopeError(() => parseHeader(patched(28, [0, 0, 4, 1])), 'format', /multiple of 256/);
  assertEnvelopeError(() => parseHeader(patched(28, [0, 0x10, 0x01, 0])), 'format', /Chunk size/);
  assertEnvelopeError(() => parseHeader(patched(32, [0, 0, 0, 0])), 'format', /Chunk count/);
});

test('padding hides short lengths and chunk counts follow', () => {
  assert.equal(paddedLength(0), 256);
  assert.equal(paddedLength(1), 256);
  assert.equal(paddedLength(256), 256);
  assert.equal(paddedLength(257), 512);
  assert.equal(chunkCountFor(2560, 1024), 3);
  assert.equal(chunkCountFor(1024, 1024), 1);
});

test('AAD binds header, kind and index', () => {
  assert.deepEqual([...recordAad(new Uint8Array([0x48]), 1, 258)], [0x48, 1, 0, 0, 1, 2]);
});

test('meta encodes as padded JSON with a fixed key order and parses back', () => {
  const meta = /** @type {const} */ ({ kind: 'file', name: 'bảng lương.xlsx', type: 'application/vnd.ms-excel', size: 12 });
  const bytes = encodeMeta(meta);
  assert.equal(bytes.length, 256);
  assert.ok(utf8Decode(bytes).startsWith('{"kind":"file","name":"bảng lương.xlsx","type":"application/vnd.ms-excel","size":12}'));
  assert.deepEqual(parseMeta(bytes), meta);
});

test('malformed meta is rejected', () => {
  /** @param {string} json */
  const pad = (json) => {
    const raw = utf8Encode(json);
    const out = new Uint8Array(Math.ceil(raw.length / 256) * 256).fill(0x20);
    out.set(raw);
    return out;
  };
  assertEnvelopeError(() => parseMeta(utf8Encode('{"kind":"text","name":null,"type":null,"size":1}')), 'integrity');
  assertEnvelopeError(() => parseMeta(pad('{kind')), 'integrity', /JSON/);
  assertEnvelopeError(() => parseMeta(pad('{"size":1,"kind":"text","name":null,"type":null}')), 'integrity', /exactly/);
  assertEnvelopeError(() => parseMeta(pad('{"kind":"text","name":null,"type":null,"size":"1"}')), 'integrity', /types/);
  assertEnvelopeError(() => parseMeta(pad('{"kind":"text","name":"a","type":null,"size":1}')), 'format', /no file name/);
  assertEnvelopeError(() => parseMeta(pad('{"kind":"file","name":"a\\u0000b","type":null,"size":1}')), 'format', /printable/);
  assertEnvelopeError(() => parseMeta(pad('{"kind":"file","name":"a","type":"text","size":1}')), 'format', /media type/);
  assertEnvelopeError(() => parseMeta(pad('{"kind":"file","name":"a","type":null,"size":1.5}')), 'format', /Size/);
});

test('browser file names are made safe without losing the extension', () => {
  assert.deepEqual(safeFileMeta('report.pdf', 'application/pdf'), { name: 'report.pdf', type: 'application/pdf' });
  assert.deepEqual(safeFileMeta('a\u0007b.txt', ''), { name: 'ab.txt', type: null });
  assert.deepEqual(safeFileMeta('   ', 'text/plain; charset=x'), { name: 'file', type: null });
  const long = safeFileMeta(`${'\u{1F510}'.repeat(300)}.tar.gz`, 'application/gzip');
  assert.equal(Array.from(long.name).length, 255);
  assert.ok(long.name.endsWith('.gz'));
});

test('package round-trips and rejects truncation and extra chunks', () => {
  const headerBytes = encodeHeader({ ...baseHeader, chunkCount: 2 });
  const envelope = { headerBytes, meta: new Uint8Array(284).fill(1), chunks: [new Uint8Array(1052).fill(2), new Uint8Array(60).fill(3)] };
  const bytes = packPackage(envelope);
  assert.equal(bytes.length, 36 + 4 + 284 + 4 + 1052 + 4 + 60);
  const parsed = unpackPackage(bytes);
  assert.deepEqual(parsed.meta, envelope.meta);
  assert.deepEqual(parsed.chunks, envelope.chunks);

  assertEnvelopeError(() => unpackPackage(new Uint8Array()), 'format', /header/);
  assertEnvelopeError(() => unpackPackage(headerBytes), 'format', /length prefix/);
  assertEnvelopeError(() => unpackPackage(bytes.subarray(0, 100)), 'format', /inside a record/);
  assertEnvelopeError(() => unpackPackage(bytes.subarray(0, bytes.length - 1)), 'format', /inside a record/);
  const extra = concatBytes(bytes, u32be(60), new Uint8Array(60));
  assertEnvelopeError(() => unpackPackage(extra), 'format', /more chunks/);
  const tiny = concatBytes(headerBytes, u32be(28), new Uint8Array(28));
  assertEnvelopeError(() => unpackPackage(tiny), 'format', /out of range/);
});

test('chunk size is right-sized for small payloads and capped for large ones', () => {
  assert.equal(chooseChunkSize(0), 1024);
  assert.equal(chooseChunkSize(5000), 5120);
  assert.equal(chooseChunkSize(10 * 1024 * 1024), 524288);
  assert.equal(reservedBytes(300), 1024);
  assert.equal(reservedBytes(32 * 1024 * 1024), 32 * 1024 * 1024);
  assert.equal(reservedBytes(32 * 1024 * 1024 + 1), 32 * 1024 * 1024 + 524288);
});
