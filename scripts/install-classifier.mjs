#!/usr/bin/env node
/**
 * install-classifier.mjs — Install the on-device prompt-injection classifier.
 *
 *   node scripts/install-classifier.mjs [--data-dir <dir>] [--keep-fp32]
 *
 * 1. Downloads protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0) from
 *    its official Hugging Face repo — config, tokenizer and ONNX weights.
 * 2. Verifies the ONNX file's SHA-256 against the checksum Hugging Face
 *    publishes for it (refuses to install on mismatch).
 * 3. Quantizes to int8 (MatMul + embedding Gather, per-channel) with
 *    onnxruntime via `uv` when available: 739 MB → 244 MB, same accuracy
 *    (checked by benchmark/eval-public.mjs). Without `uv`, keeps fp32.
 *
 * Installs to <data-dir>/models/prompt-injection-v2 (default ~/.alvora-cyber,
 * which the desktop app also checks).
 */

import fs     from 'fs';
import os     from 'os';
import path   from 'path';
import crypto from 'crypto';
import { execFileSync } from 'child_process';

const REPO  = 'protectai/deberta-v3-base-prompt-injection-v2';
const FILES = ['config.json', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json'];
const ONNX  = 'onnx/model.onnx';

const args    = process.argv.slice(2);
const dataDir = args.includes('--data-dir') ? args[args.indexOf('--data-dir') + 1] : path.join(os.homedir(), '.alvora-cyber');
const keepFp32 = args.includes('--keep-fp32');
const target  = path.join(dataDir, 'models', 'prompt-injection-v2');
const tmp     = fs.mkdtempSync(path.join(os.tmpdir(), 'alvora-classifier-'));

async function download(file, dest) {
  const res = await fetch(`https://huggingface.co/${REPO}/resolve/main/${file}`);
  if (!res.ok) throw new Error(`${file}: HTTP ${res.status}`);
  fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
}

function sha256(file) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(8 * 1024 * 1024);
  let n;
  while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  fs.closeSync(fd);
  return h.digest('hex');
}

function hasUv() {
  try { execFileSync('uv', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; }
}

try {
  console.log(`Installing ${REPO} → ${target}`);
  const meta = await (await fetch(`https://huggingface.co/api/models/${REPO}?blobs=true`)).json();
  const expected = meta.siblings?.find(s => s.rfilename === ONNX)?.lfs?.sha256;
  if (!expected) throw new Error('could not read the published checksum');

  for (const f of FILES) await download(f, path.join(tmp, f));
  console.log('  downloading ONNX weights (~740 MB)…');
  const fp32 = path.join(tmp, 'model.onnx');
  await download(ONNX, fp32);
  const actual = sha256(fp32);
  if (actual !== expected) throw new Error(`checksum mismatch (expected ${expected}, got ${actual}) — refusing to install`);
  console.log('  checksum verified ✓');

  let weights = fp32, name = 'model.onnx';
  if (!keepFp32 && hasUv()) {
    console.log('  quantizing to int8 with onnxruntime (via uv)…');
    const script = path.join(tmp, 'quantize.py');
    fs.writeFileSync(script, [
      'import sys',
      'from onnxruntime.quantization import quantize_dynamic, QuantType',
      'quantize_dynamic(sys.argv[1], sys.argv[2], weight_type=QuantType.QInt8, op_types_to_quantize=["MatMul", "Gather"], per_channel=True)',
    ].join('\n'));
    const int8 = path.join(tmp, 'model.int8.onnx');
    execFileSync('uv', ['run', '--quiet', '--python', '3.12', '--with', 'onnxruntime==1.20.1', '--with', 'onnx', 'python', '-I', script, fp32, int8], { stdio: 'inherit' });
    weights = int8; name = 'model.int8.onnx';
  } else if (!keepFp32) {
    console.log('  (uv not found — keeping the fp32 model; install uv for a 3× smaller, faster model)');
  }

  fs.mkdirSync(target, { recursive: true });
  for (const f of FILES) fs.copyFileSync(path.join(tmp, f), path.join(target, f));
  for (const old of ['model.onnx', 'model.int8.onnx']) fs.rmSync(path.join(target, old), { force: true });
  fs.copyFileSync(weights, path.join(target, name));
  console.log(`Done: ${path.join(target, name)} (${(fs.statSync(path.join(target, name)).size / 1e6).toFixed(0)} MB)`);
} catch (err) {
  console.error(`Install failed: ${err.message}`);
  process.exitCode = 1;
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
