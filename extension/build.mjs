// Build the MV3 extension (dist/chrome) and the Outlook add-in (dist/outlook-addin).
//   node build.mjs [--wasm-pkg <dir>]   (default: wasm/pkg-web, produced by wasm-bindgen --target web)
import * as esbuild from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argi = process.argv.indexOf('--wasm-pkg');
const pkg = path.resolve(argi > 0 ? process.argv[argi + 1] : path.join(here, 'wasm/pkg-web'));
for (const f of ['sealbox_wasm.js', 'sealbox_wasm_bg.wasm']) {
  if (!fs.existsSync(path.join(pkg, f))) {
    console.error(`missing ${path.join(pkg, f)} — run wasm-bindgen --target web first (scripts/gate_g28.sh does)`);
    process.exit(1);
  }
}
const dist = path.join(here, 'dist');
fs.rmSync(dist, { recursive: true, force: true });

const common = {
  bundle: true,
  minify: false,
  sourcemap: false,
  target: ['chrome120', 'firefox128'],
  alias: { 'sealbox-wasm': path.join(pkg, 'sealbox_wasm.js') },
  logLevel: 'warning',
  legalComments: 'none',
};

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const f of fs.readdirSync(src)) fs.copyFileSync(path.join(src, f), path.join(dst, f));
}

// A tiny solid PNG (no image tooling needed): Sealbox green rounded-ish square with a light dot.
function png(size) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  const r = size / 2;
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      const o = y * (size * 4 + 1) + 1 + x * 4;
      const dx = x - r + 0.5, dy = y - r + 0.5;
      const inSquare = Math.max(Math.abs(dx), Math.abs(dy)) < r * 0.92;
      const dot = Math.hypot(dx, dy) < r * 0.28;
      const [R, G, B] = dot ? [0xe6, 0xf4, 0xee] : [0x0b, 0x6e, 0x4f];
      raw.set([R, G, B, inSquare ? 255 : 0], o);
    }
  }
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(zlib.crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

// --- Chrome / Firefox MV3 ---------------------------------------------------------------
const chromeOut = path.join(dist, 'chrome');
copyDir(path.join(here, 'chrome/static'), chromeOut);
fs.copyFileSync(path.join(pkg, 'sealbox_wasm_bg.wasm'), path.join(chromeOut, 'sealbox_wasm_bg.wasm'));
for (const s of [48, 128]) fs.writeFileSync(path.join(chromeOut, `icon-${s}.png`), png(s));
await esbuild.build({
  ...common,
  entryPoints: ['background', 'options', 'compose', 'reader'].map((n) => path.join(here, `chrome/src/${n}.js`)),
  outdir: chromeOut,
  format: 'esm',
});
// Content scripts are classic scripts, not modules.
await esbuild.build({ ...common, entryPoints: [path.join(here, 'chrome/src/content.js')], outdir: chromeOut, format: 'iife' });

// --- Firefox: same files, manifest with an event-page background (Firefox has no MV3
// service workers) and the gecko settings. Chrome rejects neither, but each browser gets
// exactly the keys it supports so both lints are clean.
const ffOut = path.join(dist, 'firefox');
copyDir(chromeOut, ffOut);
{
  const m = JSON.parse(fs.readFileSync(path.join(chromeOut, 'manifest.json'), 'utf8'));
  m.background = { scripts: ['background.js'], type: 'module' };
  m.browser_specific_settings = {
    gecko: { id: 'sealbox@sealbox.invalid', strict_min_version: '142.0', data_collection_permissions: { required: ['none'] } },
  };
  fs.writeFileSync(path.join(ffOut, 'manifest.json'), JSON.stringify(m, null, 2) + '\n');
}

// --- Outlook add-in ---------------------------------------------------------------------
const olOut = path.join(dist, 'outlook-addin');
copyDir(path.join(here, 'outlook-addin/static'), olOut);
fs.copyFileSync(path.join(here, 'outlook-addin/manifest.xml'), path.join(olOut, 'manifest.xml'));
fs.copyFileSync(path.join(pkg, 'sealbox_wasm_bg.wasm'), path.join(olOut, 'sealbox_wasm_bg.wasm'));
for (const s of [16, 32, 64, 80, 128]) fs.writeFileSync(path.join(olOut, `icon-${s}.png`), png(s));
await esbuild.build({ ...common, entryPoints: [path.join(here, 'outlook-addin/src/taskpane.js')], outdir: olOut, format: 'esm' });

const size = (d) => fs.readdirSync(d).reduce((n, f) => n + fs.statSync(path.join(d, f)).size, 0);
console.log(`built dist/chrome (${(size(chromeOut) / 1e6).toFixed(2)} MB), dist/firefox and dist/outlook-addin (${(size(olOut) / 1e6).toFixed(2)} MB)`);
