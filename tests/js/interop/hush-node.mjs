// Runs the browser modules under Node for the PHP interoperability tests.
// Input arrives as JSON on stdin (so Unicode passwords survive every OS),
// output is one JSON object on stdout.
//
//   node hush-node.mjs seal <out.hush>   stdin {secret, password?}         -> {key}
//   node hush-node.mjs open <in.hush>    stdin {key, password?}            -> {opened}
//   node hush-node.mjs send <origin>     stdin {secret, password?, views?} -> {link}
//   node hush-node.mjs get  <link>       stdin {password?}                 -> {opened}
//
// secret = {kind: "text", text} | {kind: "file", dataBase64, name, type}

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

import { fromBase64Url, toBase64Url } from '../../../resources/assets/js/core/bytes.js';
import { openPackage, sealSecret } from '../../../resources/assets/js/core/crypto.js';
import { HushApi } from '../../../resources/assets/js/client/api.js';
import { buildShareLink, parseShareLink } from '../../../resources/assets/js/client/links.js';
import { inspectSecret, revealSecret, uploadSealed } from '../../../resources/assets/js/client/transfer.js';

const [command, target] = process.argv.slice(2);
const input = JSON.parse(readFileSync(0, 'utf8') || '{}');

/** @param {any} secret */
function plain(secret) {
  return secret.kind === 'text'
    ? { kind: 'text', text: secret.text }
    : { kind: 'file', data: new Uint8Array(Buffer.from(secret.dataBase64, 'base64')), name: secret.name, type: secret.type ?? null };
}

/** @param {import('../../../resources/assets/js/core/crypto.js').Opened} opened */
function describe(opened) {
  return {
    kind: opened.kind,
    text: opened.text,
    name: opened.name,
    type: opened.type,
    size: opened.data.length,
    sha256: createHash('sha256').update(opened.data).digest('hex'),
  };
}

async function main() {
  const password = input.password ?? undefined;
  switch (command) {
    case 'seal': {
      const sealed = await sealSecret(/** @type {any} */ (plain(input.secret)), password ? { password } : {});
      writeFileSync(target, await sealed.toPackage());
      return { key: toBase64Url(sealed.fragmentKey) };
    }
    case 'open': {
      const opened = await openPackage(new Uint8Array(readFileSync(target)), fromBase64Url(input.key), password ?? null);
      return { opened: describe(opened) };
    }
    case 'send': {
      const sealed = await sealSecret(/** @type {any} */ (plain(input.secret)), password ? { password } : {});
      const api = new HushApi(target);
      const created = await uploadSealed(api, sealed, { expiresIn: 3600, maxViews: input.views ?? 1 });
      return { link: buildShareLink(target, created.id, sealed.fragmentKey) };
    }
    case 'get': {
      const { origin, id, key } = parseShareLink(target);
      const api = new HushApi(origin);
      await inspectSecret(api, id, key, password ?? null);
      const { opened } = await revealSecret(api, id, key, password ?? null);
      return { opened: describe(opened) };
    }
    default:
      throw new Error(`unknown command ${command}`);
  }
}

main().then(
  (result) => process.stdout.write(JSON.stringify(result)),
  (error) => {
    process.stderr.write(`${error?.name ?? 'Error'}: ${error?.message ?? error} ${error?.reason ?? ''}\n`);
    process.exitCode = 1;
  },
);
