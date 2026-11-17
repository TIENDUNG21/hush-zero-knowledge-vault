// Byte helpers shared by the browser client, the static site and the Node tests.
// Everything here is synchronous and free of DOM access.

/** @typedef {Uint8Array<ArrayBuffer>} Bytes */

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * RFC 4648 section 5 base64url, no padding.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64Url(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Strict base64url decoding: rejects padding, the standard alphabet and
 * non-canonical trailing bits, so every byte string has exactly one encoding.
 * @param {string} text
 * @returns {Bytes}
 */
export function fromBase64Url(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new TypeError('base64url text contains characters outside [A-Za-z0-9_-]');
  }
  if (text.length % 4 === 1) {
    throw new TypeError('base64url text has an impossible length');
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  if (toBase64Url(out) !== text) {
    throw new TypeError('base64url text is not canonical');
  }
  return out;
}

/**
 * @param {...Uint8Array} parts
 * @returns {Bytes}
 */
export function concatBytes(...parts) {
  let length = 0;
  for (const part of parts) {
    length += part.length;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Big-endian unsigned 32-bit encoding.
 * @param {number} value
 * @returns {Bytes}
 */
export function u32be(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`value ${value} does not fit in an unsigned 32-bit integer`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {number}
 */
export function readU32(bytes, offset) {
  if (offset < 0 || offset + 4 > bytes.length) {
    throw new RangeError(`cannot read 4 bytes at offset ${offset} of ${bytes.length}`);
  }
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

/**
 * @param {string} text
 * @returns {Bytes}
 */
export function utf8Encode(text) {
  return encoder.encode(text);
}

/**
 * Decodes UTF-8 and throws on malformed input instead of inserting U+FFFD.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function utf8Decode(bytes) {
  return decoder.decode(bytes);
}

/**
 * @param {number} length
 * @returns {Bytes}
 */
export function randomBytes(length) {
  const out = new Uint8Array(length);
  // getRandomValues is limited to 65536 bytes per call.
  for (let offset = 0; offset < length; offset += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(length, offset + 65536)));
  }
  return out;
}

/**
 * Constant-time comparison is not needed for public data; this is for tests and checks.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function bytesEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * @param {string} hex
 * @returns {Bytes}
 */
export function fromHex(hex) {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) {
    throw new TypeError('hex text must be lowercase pairs of [0-9a-f]');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
