// Measures the browser crypto module under Node's WebCrypto (the same code
// the pages load). Prints a Markdown table.
//
//   node scripts/bench.mjs

import { randomBytes } from '../resources/assets/js/core/bytes.js';
import { deriveContentKey, openPackage, sealSecret } from '../resources/assets/js/core/crypto.js';
import { DEFAULT_ITERATIONS } from '../resources/assets/js/core/format.js';

/**
 * @param {number} runs
 * @param {() => Promise<unknown>} work
 * @returns {Promise<number>} median milliseconds
 */
async function median(runs, work) {
  const times = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    await work();
    times.push(performance.now() - start);
  }
  times.sort((a, b) => a - b);
  return /** @type {number} */ (times[Math.floor(times.length / 2)]);
}

const header = { passwordProtected: true, iterations: DEFAULT_ITERATIONS, salt: randomBytes(16), chunkSize: 1024, chunkCount: 1 };
const derive = await median(5, () => deriveContentKey(randomBytes(32), header, 'correct horse battery staple'));

const data = randomBytes(32 * 1024 * 1024);
const input = /** @type {const} */ ({ kind: 'file', data, name: 'bench.bin', type: null });
const seal = await median(5, async () => (await sealSecret(input)).toPackage());
const sealed = await sealSecret(input);
const pkg = await sealed.toPackage();
const open = await median(5, () => openPackage(pkg, sealed.fragmentKey));

console.log(`| Operation (Node ${process.versions.node}, WebCrypto) | Median |`);
console.log('|---|---|');
console.log(`| PBKDF2-SHA256, 600,000 iterations + HKDF | ${derive.toFixed(0)} ms |`);
console.log(`| Seal 32 MiB (64 chunks of 512 KiB) | ${seal.toFixed(0)} ms (${(32 / (seal / 1000)).toFixed(0)} MiB/s) |`);
console.log(`| Open 32 MiB | ${open.toFixed(0)} ms (${(32 / (open / 1000)).toFixed(0)} MiB/s) |`);
