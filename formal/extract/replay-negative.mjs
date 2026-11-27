#!/usr/bin/env node
/** Negative proof replay in isolated temporary directories; never edits src/. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const formal = path.join(root, 'formal');
const require = createRequire(import.meta.url);
const parserPackage = require.resolve('typescript/package.json');
const lake = 'lake';
const lean = 'lean';
const run = (cmd, args, cwd, env = process.env) => spawnSync(cmd, args, {cwd, env, encoding:'utf8', maxBuffer:16*1024*1024});
const checked = (r, what) => { if (r.error || r.status !== 0) throw new Error(`${what}: ${r.error ?? ''}\n${r.stdout}\n${r.stderr}`); };
checked(run(lake, ['build', 'Generated.ToIntCorrect'], formal, {...process.env, ELAN_NO_SELF_UPDATE:'1'}), 'baseline proof');
const source = fs.readFileSync(path.join(root, 'src/index.ts'), 'utf8');
const results = [];
for (const [name, from, to, counterexample] of [
  ['shift-7', 'value << 8n', 'value << 7n', '[1#8, 0#8]'],
  ['initial-1', 'let value = 0n;', 'let value = 1n;', '[]'],
]) {
  if (!source.includes(from)) throw new Error(`Absent mutation fixture: ${name}`);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'slhdsa-negative-'));
  try {
    for (const dir of ['src', 'formal/extract', 'formal/Generated', 'formal/Spec']) fs.mkdirSync(path.join(tmp, dir), {recursive:true});
    fs.writeFileSync(path.join(tmp, 'src/index.ts'), source.replace(from, to));
    for (const file of ['lean-toolchain', 'extract/extract-to-int.mjs', 'Generated/BigIntSubset.lean', 'Generated/ToIntCorrect.lean', 'Spec/SlhDsa.lean'])
      fs.copyFileSync(path.join(formal, file), path.join(tmp, 'formal', file));
    // Reuse only the immutable pinned specification dependencies, never any
    // baseline Generated object (which would mask a source mutation).
    fs.cpSync(path.join(formal, '.lake/build/lib/lean/Spec'), path.join(tmp, 'formal/Spec'), {recursive:true});
    const cwd = path.join(tmp, 'formal');
    const env = {...process.env, ELAN_NO_SELF_UPDATE:'1', NODE_PATH:path.dirname(path.dirname(parserPackage)), LEAN_PATH:[cwd, path.join(formal, '.lake/build/lib/lean')].join(path.delimiter)};
    checked(run(process.execPath, ['extract/extract-to-int.mjs'], cwd, env), `${name} extraction`);
    for (const module of ['BigIntSubset', 'ToInt']) checked(run(lean, ['-o', `Generated/${module}.olean`, `Generated/${module}.lean`], cwd, env), `${name} compile AST`);
    const replay = run(lean, ['Generated/ToIntCorrect.lean'], cwd, env);
    if (replay.error || replay.status === 0 || !/unsolved goals|Type mismatch/.test(replay.stdout) || /unknown module|object file|unknown constant/.test(replay.stdout + replay.stderr))
      throw new Error(`Expected genuine failed proof replay for ${name}:\n${replay.stdout}\n${replay.stderr}`);
    // Kernel-checked counterexample: this mutant is actually unequal to Spec,
    // rather than merely beyond the capabilities of the existing proof script.
    fs.writeFileSync(path.join(cwd, 'Counterexample.lean'), `import Generated.ToInt\nimport Spec.SlhDsa\ntheorem mutant_is_incorrect : TSExtracted.toIntProgram.denote ${counterexample} ≠ some (Spec.toInt ${counterexample}) := by decide\n#print axioms mutant_is_incorrect\n`);
    const counter = run(lean, ['Counterexample.lean'], cwd, env);
    checked(counter, `${name} counterexample`);
    results.push({name, changedAST:true, proofReplay:'rejected with unsolved goals or type mismatch', counterexample, counterexampleChecked:true, axioms:counter.stdout.trim()});
  } finally { fs.rmSync(tmp, {recursive:true, force:true}); }
}
console.log(JSON.stringify({baseline:'passed', mutants:results}, null, 2));
