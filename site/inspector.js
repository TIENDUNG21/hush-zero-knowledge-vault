// Envelope inspector for the static site. It runs the same core modules the
// Hush pages load (copied next to this file by scripts/build-site.mjs), with
// no server: seal, show the bytes, open again, then tamper and watch it fail.

import { toBase64Url, toHex } from '../resources/assets/js/core/bytes.js';
import { openPackage, sealSecret } from '../resources/assets/js/core/crypto.js';
import { EnvelopeError, HEADER_LENGTH, parseHeader, unpackPackage } from '../resources/assets/js/core/format.js';

/** @typedef {import('../resources/assets/js/core/bytes.js').Bytes} Bytes */

/**
 * @template {HTMLElement} T
 * @param {string} id
 * @param {new () => T} type
 * @returns {T}
 */
function byId(id, type) {
  const element = document.getElementById(id);
  if (!(element instanceof type)) {
    throw new Error(`#${id} is missing`);
  }
  return element;
}

const form = byId('inspect-form', HTMLFormElement);
const textInput = byId('inspect-text', HTMLTextAreaElement);
const passwordInput = byId('inspect-password', HTMLInputElement);
const sealButton = byId('inspect-seal', HTMLButtonElement);
const output = byId('inspect-output', HTMLElement);
const linkOut = byId('inspect-link', HTMLElement);
const hexOut = byId('inspect-hex', HTMLElement);
const fieldsOut = byId('inspect-fields', HTMLTableSectionElement);
const sizesOut = byId('inspect-sizes', HTMLElement);
const roundTripOut = byId('inspect-roundtrip', HTMLElement);
const tamperHeader = byId('tamper-header', HTMLButtonElement);
const tamperChunk = byId('tamper-chunk', HTMLButtonElement);
const tamperOut = byId('tamper-result', HTMLElement);

/** Byte ranges of the 36-byte header, in order. */
const FIELDS = /** @type {const} */ ([
  ['magic', 0, 4],
  ['version', 4, 5],
  ['flags', 5, 6],
  ['reserved', 6, 8],
  ['iterations', 8, 12],
  ['salt', 12, 28],
  ['chunkSize', 28, 32],
  ['chunkCount', 32, 36],
]);

/** @type {{pkg: Bytes, key: Bytes, password: string | null} | null} */
let current = null;

/**
 * @param {HTMLElement} parent
 * @param {string} tag
 * @param {string} text
 * @param {string} [className]
 */
function append(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) {
    element.className = className;
  }
  parent.append(element);
  return element;
}

/** @param {Bytes} headerBytes */
function renderHeader(headerBytes) {
  const header = parseHeader(headerBytes);
  hexOut.replaceChildren();
  fieldsOut.replaceChildren();
  const values = {
    magic: '"HUSH"',
    version: String(headerBytes[4]),
    flags: header.passwordProtected ? '0x01 (password)' : '0x00',
    reserved: '0',
    iterations: header.iterations.toLocaleString('en-US'),
    salt: '16 random bytes',
    chunkSize: `${header.chunkSize.toLocaleString('en-US')} bytes`,
    chunkCount: String(header.chunkCount),
  };
  for (const [name, start, end] of FIELDS) {
    const hex = toHex(headerBytes.subarray(start, end)).replace(/(..)(?!$)/g, '$1 ');
    append(hexOut, 'span', hex, `f-${name}`);
    hexOut.append(' ');
    const row = document.createElement('tr');
    append(row, 'td', `${start}..${end - 1}`);
    append(row, 'td', name, `f-${name}`);
    append(row, 'td', values[name]);
    fieldsOut.append(row);
  }
}

/** @param {unknown} error */
function describe(error) {
  if (error instanceof EnvelopeError) {
    return `Refused: ${error.reason} (${error.message})`;
  }
  return `Refused: ${error instanceof Error ? error.message : String(error)}`;
}

/**
 * Flip one bit at `offset` and try to open the result.
 * @param {number} offset
 * @param {string} label
 */
async function tamper(offset, label) {
  if (!current) {
    return;
  }
  const copy = current.pkg.slice();
  copy[offset] = (copy[offset] ?? 0) ^ 0x01;
  tamperOut.textContent = 'Opening the modified package...';
  try {
    await openPackage(copy, current.key, current.password);
    tamperOut.textContent = `${label}: opened anyway. This should never happen.`;
    tamperOut.className = 'bad';
  } catch (error) {
    tamperOut.textContent = `${label}: ${describe(error)}`;
    tamperOut.className = 'good';
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void (async () => {
    sealButton.disabled = true;
    sealButton.textContent = 'Sealing...';
    tamperOut.textContent = '';
    try {
      const password = passwordInput.value === '' ? null : passwordInput.value;
      const text = textInput.value;
      const started = performance.now();
      const sealed = await sealSecret({ kind: 'text', text }, password === null ? {} : { password });
      const pkg = await sealed.toPackage();
      const sealMs = performance.now() - started;
      current = { pkg, key: sealed.fragmentKey, password };

      linkOut.textContent = `https://your-hush-server/s/<id from the server>#${toBase64Url(sealed.fragmentKey)}`;
      renderHeader(sealed.headerBytes);
      const plainBytes = new TextEncoder().encode(text).length;
      sizesOut.textContent = `${plainBytes} bytes of text became a ${pkg.length}-byte package: `
        + `${HEADER_LENGTH}-byte header, ${sealed.metaRecord.length}-byte metadata record, `
        + `${sealed.chunkCount} chunk record(s), plus 4-byte length prefixes. `
        + `Sealed in ${sealMs.toFixed(0)} ms${password === null ? '' : ' (most of it PBKDF2)'}.`;

      const opened = await openPackage(pkg, sealed.fragmentKey, password);
      const envelope = unpackPackage(pkg);
      roundTripOut.textContent = opened.text === text
        ? `Opened again with the key from the link: the text matches byte for byte (${envelope.chunks.length} chunk, authenticated).`
        : 'Opened, but the text differs. This should never happen.';
      roundTripOut.className = opened.text === text ? 'good' : 'bad';
      output.hidden = false;
    } catch (error) {
      roundTripOut.textContent = describe(error);
      roundTripOut.className = 'bad';
      output.hidden = false;
    } finally {
      sealButton.disabled = false;
      sealButton.textContent = 'Seal in this page';
    }
  })();
});

// Byte 12 is the first salt byte; the last byte of the package is the last tag byte.
tamperHeader.addEventListener('click', () => void tamper(12, 'One bit of the salt flipped'));
tamperChunk.addEventListener('click', () => {
  if (current) {
    void tamper(current.pkg.length - 1, 'One bit of the last chunk flipped');
  }
});
