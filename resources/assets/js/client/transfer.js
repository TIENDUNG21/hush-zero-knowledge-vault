// Upload and download flows that combine the crypto core with the API client.

import { openMeta, openPackage } from '../core/crypto.js';
import { ApiError } from './api.js';

/** @typedef {import('./api.js').HushApi} HushApi */
/** @typedef {import('../core/crypto.js').Sealed} Sealed */

/**
 * Creates the secret, uploads every chunk (retrying a chunk once on a
 * network or server error) and seals it.
 *
 * @param {HushApi} api
 * @param {Sealed} sealed
 * @param {{expiresIn: number, maxViews: number, onProgress?: (done: number, total: number) => void}} options
 * @returns {Promise<import('./api.js').Created>}
 */
export async function uploadSealed(api, sealed, { expiresIn, maxViews, onProgress }) {
  const created = await api.create({ header: sealed.headerBytes, meta: sealed.metaRecord, expiresIn, maxViews });
  onProgress?.(0, sealed.chunkCount);
  for (let index = 0; index < sealed.chunkCount; index++) {
    const record = await sealed.encryptChunk(index);
    try {
      await api.putChunk(created.id, index, record, created.deletionToken);
    } catch (error) {
      if (!(error instanceof ApiError) || !error.retryable) {
        throw error;
      }
      await api.putChunk(created.id, index, record, created.deletionToken);
    }
    onProgress?.(index + 1, sealed.chunkCount);
  }
  await api.seal(created.id, created.deletionToken);
  return created;
}

/**
 * Step 1 of reading: fetch limits and the encrypted metadata, and check the
 * link key and password against it. Consumes no view.
 *
 * @param {HushApi} api
 * @param {string} id
 * @param {import('../core/bytes.js').Bytes} key
 * @param {string | null} password
 */
export async function inspectSecret(api, id, key, password) {
  const status = await api.status(id);
  const { meta } = await openMeta(status.header, status.meta, key, password);
  return { status, meta };
}

/**
 * Step 2 of reading: consume a view and decrypt everything.
 *
 * @param {HushApi} api
 * @param {string} id
 * @param {import('../core/bytes.js').Bytes} key
 * @param {string | null} password
 */
export async function revealSecret(api, id, key, password) {
  const { packageBytes, viewsLeft } = await api.open(id);
  const opened = await openPackage(packageBytes, key, password);
  return { opened, viewsLeft };
}
