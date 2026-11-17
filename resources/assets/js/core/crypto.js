// Envelope encryption on WebCrypto. Runs unchanged in browsers and in Node 22.
// Mirror of src/Crypto/{KeySchedule,RecordCipher,SecretSealer,SecretOpener}.php.

import { concatBytes, randomBytes, utf8Decode, utf8Encode } from './bytes.js';
import {
  DEFAULT_ITERATIONS,
  EnvelopeError,
  HKDF_INFO,
  KEY_LENGTH,
  KIND_CHUNK,
  KIND_META,
  MIN_ITERATIONS,
  NONCE_LENGTH,
  RECORD_OVERHEAD,
  SALT_LENGTH,
  chooseChunkSize,
  chunkCountFor,
  encodeHeader,
  encodeMeta,
  packPackage,
  paddedLength,
  parseHeader,
  parseMeta,
  recordAad,
  unpackPackage,
} from './format.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */
/** @typedef {import('./format.js').Header} Header */
/** @typedef {import('./format.js').Meta} Meta */

/**
 * @typedef {{kind: 'text', text: string} | {kind: 'file', data: Bytes, name: string, type: string | null}} PlainInput
 *
 * @typedef {object} SealOptions
 * @property {string} [password] empty or absent means no password
 * @property {number} [iterations]
 * @property {number} [chunkSize]
 * @property {Bytes} [fragmentKey] test vectors only
 * @property {Bytes} [salt] test vectors only
 * @property {() => Bytes} [nonces] test vectors only
 *
 * @typedef {object} Sealed
 * @property {Bytes} fragmentKey 32 random bytes that go into the URL fragment
 * @property {Header} header
 * @property {Bytes} headerBytes
 * @property {Bytes} metaRecord
 * @property {number} chunkCount
 * @property {(index: number) => Promise<Bytes>} encryptChunk fresh nonce per call
 * @property {() => Promise<Bytes>} toPackage
 *
 * @typedef {object} Opened
 * @property {'text' | 'file'} kind
 * @property {Bytes} data
 * @property {string | null} text decoded text for text secrets
 * @property {string | null} name
 * @property {string | null} type
 */

function subtle() {
  const api = globalThis.crypto?.subtle;
  if (!api) {
    throw new EnvelopeError('unsupported', 'WebCrypto is not available (a secure context is required)');
  }
  return api;
}

/** @returns {Bytes} */
export function generateFragmentKey() {
  return randomBytes(KEY_LENGTH);
}

/**
 * pw  = PBKDF2-HMAC-SHA256(NFC(password), salt, iterations, 32)  (with a password)
 * key = HKDF-SHA256(fragmentKey || pw, salt, "hush/v1 content key", 32)
 *
 * @param {Bytes} fragmentKey
 * @param {Header} header
 * @param {string | null | undefined} password
 * @returns {Promise<CryptoKey>}
 */
export async function deriveContentKey(fragmentKey, header, password) {
  if (fragmentKey.length !== KEY_LENGTH) {
    throw new EnvelopeError('format', 'The link key must be 32 bytes');
  }
  let ikm = fragmentKey;
  if (header.passwordProtected) {
    if (password === null || password === undefined || password === '') {
      throw new EnvelopeError('password_required', 'This secret is protected by a password.');
    }
    if (header.iterations < MIN_ITERATIONS) {
      throw new EnvelopeError('format', 'PBKDF2 iteration count is too low');
    }
    // NFC: "é" typed as one code point or as e + combining accent derives the same key.
    const passwordKey = await subtle().importKey('raw', utf8Encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle().deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: header.salt, iterations: header.iterations },
      passwordKey,
      KEY_LENGTH * 8,
    );
    ikm = concatBytes(fragmentKey, new Uint8Array(bits));
  }
  const hkdfKey = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: header.salt, info: utf8Encode(HKDF_INFO) },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * @param {CryptoKey} key
 * @param {Bytes} aad
 * @param {Bytes} plaintext
 * @param {Bytes} nonce
 * @returns {Promise<Bytes>} nonce || ciphertext || tag
 */
export async function sealRecord(key, aad, plaintext, nonce) {
  if (nonce.length !== NONCE_LENGTH) {
    throw new EnvelopeError('format', 'Nonce must be 12 bytes');
  }
  const sealed = await subtle().encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, plaintext);
  return concatBytes(nonce, new Uint8Array(sealed));
}

/**
 * @param {CryptoKey} key
 * @param {Bytes} aad
 * @param {Bytes} record
 * @returns {Promise<Bytes>}
 */
export async function openRecord(key, aad, record) {
  if (record.length <= RECORD_OVERHEAD) {
    throw new EnvelopeError('format', 'Record is too short');
  }
  try {
    const plain = await subtle().decrypt(
      { name: 'AES-GCM', iv: record.subarray(0, NONCE_LENGTH), additionalData: aad, tagLength: 128 },
      key,
      record.subarray(NONCE_LENGTH),
    );
    return new Uint8Array(plain);
  } catch {
    throw new EnvelopeError('authentication', 'Decryption failed: wrong key or password, or the data was modified.');
  }
}

/**
 * Encrypts text or a file into a HUSH v1 envelope. Chunks are encrypted on
 * demand so large files can be uploaded with progress and modest memory.
 *
 * @param {PlainInput} input
 * @param {SealOptions} [options]
 * @returns {Promise<Sealed>}
 */
export async function sealSecret(input, options = {}) {
  const data = input.kind === 'text' ? utf8Encode(input.text) : input.data;
  /** @type {Meta} */
  const meta = input.kind === 'text'
    ? { kind: 'text', name: null, type: null, size: data.length }
    : { kind: 'file', name: input.name, type: input.type, size: data.length };

  const hasPassword = typeof options.password === 'string' && options.password !== '';
  const chunkSize = options.chunkSize ?? chooseChunkSize(data.length);
  const padded = paddedLength(data.length);
  const fragmentKey = options.fragmentKey ?? generateFragmentKey();
  /** @type {Header} */
  const header = {
    passwordProtected: hasPassword,
    iterations: hasPassword ? options.iterations ?? DEFAULT_ITERATIONS : 0,
    salt: options.salt ?? randomBytes(SALT_LENGTH),
    chunkSize,
    chunkCount: chunkCountFor(padded, chunkSize),
  };
  const headerBytes = encodeHeader(header);
  const nonce = options.nonces ?? (() => randomBytes(NONCE_LENGTH));
  const key = await deriveContentKey(fragmentKey, header, options.password);
  const metaRecord = await sealRecord(key, recordAad(headerBytes, KIND_META, 0), encodeMeta(meta), nonce());

  /** @param {number} index */
  const encryptChunk = async (index) => {
    if (!Number.isInteger(index) || index < 0 || index >= header.chunkCount) {
      throw new RangeError(`Chunk ${index} does not exist`);
    }
    const offset = index * chunkSize;
    const length = Math.min(chunkSize, padded - offset);
    const plain = new Uint8Array(length); // zero-filled: the padding
    plain.set(data.subarray(offset, Math.min(offset + length, data.length)));
    return sealRecord(key, recordAad(headerBytes, KIND_CHUNK, index), plain, nonce());
  };

  const toPackage = async () => {
    /** @type {Bytes[]} */
    const chunks = [];
    for (let i = 0; i < header.chunkCount; i++) {
      chunks.push(await encryptChunk(i));
    }
    return packPackage({ headerBytes, meta: metaRecord, chunks });
  };

  return { fragmentKey, header, headerBytes, metaRecord, chunkCount: header.chunkCount, encryptChunk, toPackage };
}

/**
 * Decrypts only the metadata record. Used before a view is consumed, to
 * check the link key and password and to show what is about to be revealed.
 *
 * @param {Bytes} headerBytes
 * @param {Bytes} metaRecord
 * @param {Bytes} fragmentKey
 * @param {string | null} [password]
 * @returns {Promise<{header: Header, meta: Meta, key: CryptoKey}>}
 */
export async function openMeta(headerBytes, metaRecord, fragmentKey, password = null) {
  const header = parseHeader(headerBytes);
  const key = await deriveContentKey(fragmentKey, header, password);
  const meta = parseMeta(await openRecord(key, recordAad(headerBytes, KIND_META, 0), metaRecord));
  return { header, meta, key };
}

/**
 * Decrypts and verifies a whole envelope.
 *
 * @param {import('./format.js').Envelope} envelope
 * @param {Bytes} fragmentKey
 * @param {string | null} [password]
 * @returns {Promise<Opened>}
 */
export async function openEnvelope(envelope, fragmentKey, password = null) {
  const { header, meta, key } = await openMeta(envelope.headerBytes, envelope.meta, fragmentKey, password);
  if (envelope.chunks.length !== header.chunkCount) {
    throw new EnvelopeError('integrity', `Expected ${header.chunkCount} chunks, got ${envelope.chunks.length}`);
  }
  const padded = paddedLength(meta.size);
  if (chunkCountFor(padded, header.chunkSize) !== header.chunkCount) {
    throw new EnvelopeError('integrity', 'Payload length does not match the metadata');
  }

  const data = new Uint8Array(padded);
  let offset = 0;
  const last = header.chunkCount - 1;
  for (let index = 0; index < envelope.chunks.length; index++) {
    const record = /** @type {Bytes} */ (envelope.chunks[index]);
    const plain = await openRecord(key, recordAad(envelope.headerBytes, KIND_CHUNK, index), record);
    const expectedFull = index < last;
    if ((expectedFull && plain.length !== header.chunkSize) || (!expectedFull && plain.length > header.chunkSize)
      || offset + plain.length > padded) {
      throw new EnvelopeError('integrity', `Chunk ${index} has an unexpected length`);
    }
    data.set(plain, offset);
    offset += plain.length;
  }
  if (offset !== padded) {
    throw new EnvelopeError('integrity', 'Payload length does not match the metadata');
  }

  const payload = data.slice(0, meta.size);
  let text = null;
  if (meta.kind === 'text') {
    try {
      text = utf8Decode(payload);
    } catch {
      throw new EnvelopeError('integrity', 'Text payload is not valid UTF-8');
    }
  }
  return { kind: meta.kind, data: payload, text, name: meta.name, type: meta.type };
}

/**
 * @param {Bytes} packageBytes
 * @param {Bytes} fragmentKey
 * @param {string | null} [password]
 * @returns {Promise<Opened>}
 */
export async function openPackage(packageBytes, fragmentKey, password = null) {
  return openEnvelope(unpackPackage(packageBytes), fragmentKey, password);
}
