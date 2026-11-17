// Thin client for the Hush HTTP API. Sends only ciphertext and the public
// envelope header; never the link key or the password.

import { fromBase64Url, toBase64Url } from '../core/bytes.js';

/** @typedef {import('../core/bytes.js').Bytes} Bytes */

export class ApiError extends Error {
  /**
   * @param {number} status HTTP status, 0 for network failures
   * @param {string} code machine-readable error code from the server
   * @param {string} message
   */
  constructor(status, code, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }

  get retryable() {
    return this.status === 0 || this.status >= 500;
  }
}

/**
 * @typedef {object} Created
 * @property {string} id
 * @property {string} deletionToken
 * @property {number} expiresAt unix seconds
 * @property {number} uploadDeadline unix seconds
 * @property {number} chunkCount
 *
 * @typedef {object} Status
 * @property {string} id
 * @property {boolean} passwordProtected
 * @property {number} expiresAt
 * @property {number} viewsLeft
 * @property {number} chunkCount
 * @property {number} ciphertextBytes
 * @property {Bytes} header
 * @property {Bytes} meta
 */

/** @typedef {(input: string, init?: RequestInit) => Promise<Response>} FetchLike */

export class HushApi {
  /**
   * @param {string} [baseUrl] origin of the server, '' for same-origin
   * @param {FetchLike} [fetchImpl]
   */
  constructor(baseUrl = '', fetchImpl = (input, init) => globalThis.fetch(input, init)) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetchImpl = fetchImpl;
  }

  /**
   * @param {{header: Bytes, meta: Bytes, expiresIn: number, maxViews: number}} request
   * @returns {Promise<Created>}
   */
  async create({ header, meta, expiresIn, maxViews }) {
    const response = await this.#send('POST', '/api/secrets', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ header: toBase64Url(header), meta: toBase64Url(meta), expiresIn, maxViews }),
    });
    const data = await response.json();
    return {
      id: String(data.id),
      deletionToken: String(data.deletionToken),
      expiresAt: Number(data.expiresAt),
      uploadDeadline: Number(data.uploadDeadline),
      chunkCount: Number(data.chunkCount),
    };
  }

  /**
   * @param {string} id
   * @param {number} index
   * @param {Bytes} record
   * @param {string} token
   */
  async putChunk(id, index, record, token) {
    await this.#send('PUT', `/api/secrets/${id}/chunks/${index}`, {
      headers: { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${token}` },
      body: record,
    });
  }

  /**
   * @param {string} id
   * @param {string} token
   */
  async seal(id, token) {
    await this.#send('POST', `/api/secrets/${id}/seal`, { headers: { Authorization: `Bearer ${token}` } });
  }

  /**
   * Limits and the encrypted metadata; does not consume a view.
   * @param {string} id
   * @returns {Promise<Status>}
   */
  async status(id) {
    const data = await (await this.#send('GET', `/api/secrets/${id}`)).json();
    return {
      id: String(data.id),
      passwordProtected: data.passwordProtected === true,
      expiresAt: Number(data.expiresAt),
      viewsLeft: Number(data.viewsLeft),
      chunkCount: Number(data.chunkCount),
      ciphertextBytes: Number(data.ciphertextBytes),
      header: fromBase64Url(String(data.header)),
      meta: fromBase64Url(String(data.meta)),
    };
  }

  /**
   * Consumes one view and returns the encrypted package.
   * @param {string} id
   * @returns {Promise<{packageBytes: Bytes, viewsLeft: number}>}
   */
  async open(id) {
    const response = await this.#send('POST', `/api/secrets/${id}/open`);
    return {
      packageBytes: new Uint8Array(await response.arrayBuffer()),
      viewsLeft: Number(response.headers.get('X-Hush-Views-Left') ?? '0'),
    };
  }

  /**
   * @param {string} id
   * @param {string} token
   */
  async remove(id, token) {
    await this.#send('DELETE', `/api/secrets/${id}`, { headers: { Authorization: `Bearer ${token}` } });
  }

  /**
   * @param {string} method
   * @param {string} path
   * @param {{headers?: Record<string, string>, body?: string | Bytes}} [options]
   * @returns {Promise<Response>}
   */
  async #send(method, path, options = {}) {
    /** @type {RequestInit} */
    const init = {
      method,
      headers: options.headers ?? {},
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    };
    if (options.body !== undefined) {
      init.body = options.body;
    }
    /** @type {Response} */
    let response;
    try {
      response = await this.fetchImpl(this.baseUrl + path, init);
    } catch (error) {
      throw new ApiError(0, 'network', `Network error: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!response.ok) {
      let code = 'http_' + response.status;
      let message = `The server answered ${response.status}.`;
      try {
        const data = await response.json();
        if (data && typeof data.error === 'object' && data.error !== null) {
          code = String(data.error.code ?? code);
          message = String(data.error.message ?? message);
        }
      } catch {
        // not JSON; keep the generic message
      }
      throw new ApiError(response.status, code, message);
    }
    return response;
  }
}
