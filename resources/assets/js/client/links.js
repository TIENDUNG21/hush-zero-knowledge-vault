// Share and delete links. Secrets travel in the URL fragment (after "#"),
// which browsers never send to the server.

import { fromBase64Url, toBase64Url } from '../core/bytes.js';
import { KEY_LENGTH } from '../core/format.js';

/** @typedef {import('../core/bytes.js').Bytes} Bytes */

const ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export class LinkError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'LinkError';
  }
}

/**
 * @param {string} origin e.g. "https://hush.example"
 * @param {string} id
 * @param {Bytes} fragmentKey
 * @returns {string}
 */
export function buildShareLink(origin, id, fragmentKey) {
  return `${origin.replace(/\/+$/, '')}/s/${id}#${toBase64Url(fragmentKey)}`;
}

/**
 * @param {string} origin
 * @param {string} id
 * @param {string} deletionToken
 * @returns {string}
 */
export function buildDeleteLink(origin, id, deletionToken) {
  return `${origin.replace(/\/+$/, '')}/d/${id}#${deletionToken}`;
}

/**
 * @param {string} hash location.hash, with or without "#"
 * @returns {Bytes}
 */
export function keyFromFragment(hash) {
  const text = hash.replace(/^#/, '');
  if (text === '') {
    throw new LinkError('The link has no key after "#". Ask the sender for the complete link.');
  }
  let key;
  try {
    key = fromBase64Url(text);
  } catch {
    throw new LinkError('The key after "#" is damaged. Ask the sender for the complete link.');
  }
  if (key.length !== KEY_LENGTH) {
    throw new LinkError('The key after "#" has the wrong length. The link may be cut off.');
  }
  return key;
}

/**
 * @param {string} hash
 * @returns {string}
 */
export function tokenFromFragment(hash) {
  const text = hash.replace(/^#/, '');
  if (!TOKEN_PATTERN.test(text)) {
    throw new LinkError('This delete link is incomplete.');
  }
  return text;
}

/**
 * @param {string} pathname e.g. "/s/AbC..."
 * @param {'s' | 'd'} prefix
 * @returns {string}
 */
export function idFromPath(pathname, prefix) {
  const match = new RegExp(`^/${prefix}/([^/]+)$`).exec(pathname);
  const id = match?.[1] ?? '';
  if (!ID_PATTERN.test(id)) {
    throw new LinkError('This link is not a valid Hush link.');
  }
  return id;
}

/**
 * @param {string} url a full share link
 * @returns {{origin: string, id: string, key: Bytes}}
 */
export function parseShareLink(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new LinkError('Not a URL.');
  }
  return { origin: parsed.origin, id: idFromPath(parsed.pathname, 's'), key: keyFromFragment(parsed.hash) };
}
