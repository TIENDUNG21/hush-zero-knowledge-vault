// Builds the static GitHub Pages site into dist/site.
//
//   node scripts/build-site.mjs
//
// The page imports the app's core envelope modules. In the repository it
// points at resources/assets/js/core/ (so tsc and ESLint check the real
// import); the build copies those modules next to it and rewrites the path.
// All URLs in the output are relative, so the site works under any base
// path, including https://tiendung21.github.io/hush-zero-knowledge-vault/.

import { copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist', 'site');
const coreSource = '../resources/assets/js/core/';

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, 'core'), { recursive: true });
mkdirSync(join(out, 'img'), { recursive: true });

copyFileSync(join(root, 'site', 'index.html'), join(out, 'index.html'));
copyFileSync(join(root, 'site', 'site.css'), join(out, 'site.css'));
copyFileSync(join(root, 'assets', 'logo.svg'), join(out, 'logo.svg'));
for (const name of ['created.png', 'view.png']) {
  copyFileSync(join(root, 'docs', 'screenshots', name), join(out, 'img', name));
}

const coreDir = join(root, 'resources', 'assets', 'js', 'core');
for (const name of readdirSync(coreDir).filter((file) => file.endsWith('.js'))) {
  copyFileSync(join(coreDir, name), join(out, 'core', name));
}

const inspector = readFileSync(join(root, 'site', 'inspector.js'), 'utf8');
if (!inspector.includes(coreSource)) {
  throw new Error(`site/inspector.js no longer imports from ${coreSource}`);
}
writeFileSync(join(out, 'inspector.js'), inspector.replaceAll(coreSource, './core/'));
writeFileSync(join(out, '.nojekyll'), '');

console.log(`built ${out}`);
