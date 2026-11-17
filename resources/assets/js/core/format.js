// HUSH v1 envelope format: byte layout, padding and validation.
// Mirror of src/Crypto/{Format,Header,Meta,Package}.php; both are pinned by
// tests/fixtures/vector-v1.json.

import { concatBytes, readU32, u32be, utf8Decode, utf8Encode } from './bytes.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */

export const MAGIC = 'HUSH';
export const VERSION = 1;
export const HEADER_LENGTH = 36;
export const FLAG_PASSWORD = 0x01;
export const KEY_LENGTH = 32;
export const SALT_LENGTH = 16;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const RECORD_OVERHEAD = NONCE_LENGTH + TAG_LENGTH;
export const PAD_BLOCK = 256;
export const META_MAX_LENGTH = 4096;
export const MIN_ITERATIONS = 100_000;
export const MAX_ITERATIONS = 5_000_000;
export const DEFAULT_ITERATIONS = 600_000;
export const MIN_CHUNK_SIZE = 1024;
export const MAX_CHUNK_SIZE = 1_048_576;
export const DEFAULT_CHUNK_SIZE = 524_288;
export const KIND_META = 0;
export const KIND_CHUNK = 1;
export const HKDF_INFO = 'hush/v1 content key';

/**
 * Error with a machine-readable reason, matching the PHP CryptoException:
 * format | authentication | integrity | password_required | unsupported.
 */
export class EnvelopeError extends Error {
  /**
   * @param {'format' | 'authentication' | 'integrity' | 'password_required' | 'unsupported'} reason
   * @param {string} message
   */
  constructor(reason, message) {
    super(message);
    this.name = 'EnvelopeError';
    this.reason = reason;
  }
}

/**
 * @typedef {object} Header
 * @property {boolean} passwordProtected
 * @property {number} iterations
 * @property {Bytes} salt
 * @property {number} chunkSize
 * @property {number} chunkCount
 */

/**
 * @param {Header} header
 * @returns {Header}
 */
export function validateHeader(header) {
  const { passwordProtected, iterations, salt, chunkSize, chunkCount } = header;
  if (passwordProtected && !(Number.isInteger(iterations) && iterations >= MIN_ITERATIONS && iterations <= MAX_ITERATIONS)) {
    throw new EnvelopeError('format', `PBKDF2 iterations must be between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}`);
  }
  if (!passwordProtected && iterations !== 0) {
    throw new EnvelopeError('format', 'Iterations must be 0 when no password is used');
  }
  if (salt.length !== SALT_LENGTH) {
    throw new EnvelopeError('format', 'Salt must be 16 bytes');
  }
  if (!Number.isInteger(chunkSize) || chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE || chunkSize % PAD_BLOCK !== 0) {
    throw new EnvelopeError('format', `Chunk size must be a multiple of ${PAD_BLOCK} between ${MIN_CHUNK_SIZE} and ${MAX_CHUNK_SIZE} bytes`);
  }
  if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > 0xffffffff) {
    throw new EnvelopeError('format', 'Chunk count must be at least 1');
  }
  return header;
}

/**
 * @param {Header} header
 * @returns {Bytes}
 */
export function encodeHeader(header) {
  validateHeader(header);
  return concatBytes(
    utf8Encode(MAGIC),
    new Uint8Array([VERSION, header.passwordProtected ? FLAG_PASSWORD : 0, 0, 0]),
    u32be(header.iterations),
    header.salt,
    u32be(header.chunkSize),
    u32be(header.chunkCount),
  );
}

/**
 * @param {Bytes} bytes
 * @returns {Header}
 */
export function parseHeader(bytes) {
  if (bytes.length !== HEADER_LENGTH) {
    throw new EnvelopeError('format', `Header must be ${HEADER_LENGTH} bytes, got ${bytes.length}`);
  }
  if (bytes[0] !== 0x48 || bytes[1] !== 0x55 || bytes[2] !== 0x53 || bytes[3] !== 0x48) {
    throw new EnvelopeError('format', 'Not a Hush envelope (bad magic)');
  }
  if (bytes[4] !== VERSION) {
    throw new EnvelopeError('format', `Unsupported envelope version ${bytes[4]}`);
  }
  const flags = bytes[5] ?? 0;
  if ((flags & ~FLAG_PASSWORD) !== 0) {
    throw new EnvelopeError('format', `Unknown header flags 0x${flags.toString(16).padStart(2, '0')}`);
  }
  if (bytes[6] !== 0 || bytes[7] !== 0) {
    throw new EnvelopeError('format', 'Reserved header bytes must be zero');
  }
  return validateHeader({
    passwordProtected: (flags & FLAG_PASSWORD) !== 0,
    iterations: readU32(bytes, 8),
    salt: bytes.slice(12, 28),
    chunkSize: readU32(bytes, 28),
    chunkCount: readU32(bytes, 32),
  });
}

/**
 * Payload length after zero padding: a multiple of 256, at least 256.
 * @param {number} size
 * @returns {number}
 */
export function paddedLength(size) {
  return Math.max(PAD_BLOCK, Math.ceil(size / PAD_BLOCK) * PAD_BLOCK);
}

/**
 * @param {number} padded
 * @param {number} chunkSize
 * @returns {number}
 */
export function chunkCountFor(padded, chunkSize) {
  return Math.ceil(padded / chunkSize);
}

/**
 * header || kind || u32 index: binds a record to its envelope and position.
 * @param {Bytes} headerBytes
 * @param {number} kind
 * @param {number} index
 * @returns {Bytes}
 */
export function recordAad(headerBytes, kind, index) {
  return concatBytes(headerBytes, new Uint8Array([kind]), u32be(index));
}

/**
 * @typedef {object} Meta
 * @property {'text' | 'file'} kind
 * @property {string | null} name
 * @property {string | null} type
 * @property {number} size
 */

// eslint-disable-next-line no-control-regex -- rejecting control characters is the point
const NAME_PATTERN = /^[^\u0000-\u001f\u007f]{1,255}$/u;
const MEDIA_TYPE_PATTERN = /^[A-Za-z0-9!#$&^_.+-]{1,63}\/[A-Za-z0-9!#$&^_.+-]{1,63}$/;

/**
 * @param {string} type
 * @returns {boolean}
 */
export function isMediaType(type) {
  return MEDIA_TYPE_PATTERN.test(type);
}

/**
 * @param {Meta} meta
 * @returns {Meta}
 */
export function validateMeta(meta) {
  if (meta.kind !== 'text' && meta.kind !== 'file') {
    throw new EnvelopeError('format', `Unknown payload kind "${String(meta.kind)}"`);
  }
  if (meta.kind === 'text' && (meta.name !== null || meta.type !== null)) {
    throw new EnvelopeError('format', 'Text payloads carry no file name or type');
  }
  if (meta.name !== null && !NAME_PATTERN.test(meta.name)) {
    throw new EnvelopeError('format', 'File name must be 1-255 printable characters');
  }
  if (meta.type !== null && !isMediaType(meta.type)) {
    throw new EnvelopeError('format', 'Invalid media type');
  }
  if (!Number.isSafeInteger(meta.size) || meta.size < 0) {
    throw new EnvelopeError('format', 'Size must be a non-negative integer');
  }
  return meta;
}

/**
 * Makes a browser File's name and type acceptable to the format:
 * control characters removed, at most 255 code points (extension kept),
 * unknown or malformed media types dropped.
 * @param {string} name
 * @param {string} type
 * @returns {{name: string, type: string | null}}
 */
export function safeFileMeta(name, type) {
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  let clean = Array.from(name.replace(/[\u0000-\u001f\u007f]/g, '').trim());
  if (clean.length === 0) {
    clean = Array.from('file');
  }
  if (clean.length > 255) {
    const dot = clean.lastIndexOf('.');
    const extension = dot > 0 && clean.length - dot <= 16 ? clean.slice(dot) : [];
    clean = clean.slice(0, 255 - extension.length).concat(extension);
  }
  return { name: clean.join(''), type: isMediaType(type) ? type : null };
}

/**
 * JSON with a fixed key order, right-padded with spaces to a 256-byte multiple.
 * @param {Meta} meta
 * @returns {Bytes}
 */
export function encodeMeta(meta) {
  validateMeta(meta);
  const json = utf8Encode(JSON.stringify({ kind: meta.kind, name: meta.name, type: meta.type, size: meta.size }));
  const length = Math.ceil(json.length / PAD_BLOCK) * PAD_BLOCK;
  if (length > META_MAX_LENGTH) {
    throw new EnvelopeError('format', 'Metadata is too large');
  }
  const out = new Uint8Array(length).fill(0x20);
  out.set(json, 0);
  return out;
}

/**
 * @param {Bytes} bytes
 * @returns {Meta}
 */
export function parseMeta(bytes) {
  if (bytes.length === 0 || bytes.length % PAD_BLOCK !== 0 || bytes.length > META_MAX_LENGTH) {
    throw new EnvelopeError('integrity', 'Metadata has an invalid padded length');
  }
  /** @type {unknown} */
  let data;
  try {
    data = JSON.parse(utf8Decode(bytes));
  } catch {
    throw new EnvelopeError('integrity', 'Metadata is not valid JSON');
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new EnvelopeError('integrity', 'Metadata must be a JSON object');
  }
  const record = /** @type {Record<string, unknown>} */ (data);
  if (Object.keys(record).join(',') !== 'kind,name,type,size') {
    throw new EnvelopeError('integrity', 'Metadata must have exactly kind, name, type and size');
  }
  const { kind, name, type, size } = record;
  if ((kind !== 'text' && kind !== 'file') || !(typeof name === 'string' || name === null)
    || !(typeof type === 'string' || type === null) || typeof size !== 'number') {
    throw new EnvelopeError('integrity', 'Metadata fields have the wrong types');
  }
  return validateMeta({ kind, name, type, size });
}

/**
 * @typedef {object} Envelope
 * @property {Bytes} headerBytes
 * @property {Bytes} meta encrypted metadata record
 * @property {Bytes[]} chunks encrypted chunk records
 */

/**
 * header || u32 metaLength || meta || (u32 length || chunk)*
 * @param {Envelope} envelope
 * @returns {Bytes}
 */
export function packPackage(envelope) {
  /** @type {Bytes[]} */
  const parts = [envelope.headerBytes, u32be(envelope.meta.length), envelope.meta];
  for (const chunk of envelope.chunks) {
    parts.push(u32be(chunk.length), chunk);
  }
  return concatBytes(...parts);
}

/**
 * @param {Bytes} bytes
 * @returns {Envelope & {header: Header}}
 */
export function unpackPackage(bytes) {
  if (bytes.length < HEADER_LENGTH) {
    throw new EnvelopeError('format', 'Package is truncated before the end of the header');
  }
  const headerBytes = bytes.slice(0, HEADER_LENGTH);
  const header = parseHeader(headerBytes);
  let offset = HEADER_LENGTH;

  /** @param {number} maxLength */
  const readFrame = (maxLength) => {
    if (offset + 4 > bytes.length) {
      throw new EnvelopeError('format', 'Package is truncated inside a length prefix');
    }
    const length = readU32(bytes, offset);
    if (length <= RECORD_OVERHEAD || length > maxLength) {
      throw new EnvelopeError('format', `Record length ${length} is out of range`);
    }
    if (offset + 4 + length > bytes.length) {
      throw new EnvelopeError('format', 'Package is truncated inside a record');
    }
    const record = bytes.slice(offset + 4, offset + 4 + length);
    offset += 4 + length;
    return record;
  };

  const meta = readFrame(META_MAX_LENGTH + RECORD_OVERHEAD);
  /** @type {Bytes[]} */
  const chunks = [];
  while (offset < bytes.length) {
    if (chunks.length >= header.chunkCount) {
      throw new EnvelopeError('format', 'Package has more chunks than its header declares');
    }
    chunks.push(readFrame(header.chunkSize + RECORD_OVERHEAD));
  }
  return { headerBytes, header, meta, chunks };
}
