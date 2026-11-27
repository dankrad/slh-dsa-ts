#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const formal = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(formal);
const upstream = JSON.parse(fs.readFileSync(path.join(formal, 'upstream.json'), 'utf8'));
for (const [file, expected] of Object.entries(upstream.files)) {
  const actual = createHash('sha256').update(fs.readFileSync(path.join(formal, file))).digest('hex');
  if (actual !== expected) throw new Error(`Vendored specification changed: ${file}`);
}
console.log(`Pinned specification checksums passed (${upstream.revision})`);
function run(cmd, args, cwd = root) {
  const r = spawnSync(cmd, args, { cwd, stdio: 'inherit', env: process.env });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}`);
}
const version = spawnSync('lean', ['--version'], { cwd: formal, encoding: 'utf8' });
if (version.error) throw version.error;
if (version.status !== 0 || !/^Lean \(version 4\.36\.0[,)]/.test(version.stdout)) {
  throw new Error(`Expected pinned Lean 4.36.0, got ${version.stdout || version.stderr}`);
}
console.log(version.stdout.trim());
run(process.execPath, ['formal/extract/extract-to-int.mjs', '--check']);
run(process.execPath, ['formal/extract/extract-to-int.mjs', '--self-test']);
run('lake', ['build'], formal);
run(process.execPath, ['formal/extract/replay-negative.mjs']);
