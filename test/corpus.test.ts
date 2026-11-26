import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import { digest, loadVectors, sets } from './helpers.js';

test('all twelve copied ACVP files are byte-identical to the pinned reference manifest', () => {
  const root=new URL('../vectors/',import.meta.url);
  const manifest=JSON.parse(readFileSync(new URL('manifest.json',root),'utf8'));
  assert.equal(manifest.commit,'462724e2b5f8ffe63a2ce76c9b1ab07099c1807b');
  const files=readdirSync(root).filter(f=>/^slh-dsa-.*\.json$/.test(f)).sort();
  assert.deepEqual(files,Object.keys(manifest.files).sort()); assert.equal(files.length,12);
  for (const file of files) assert.equal(digest(readFileSync(new URL(file,root))),manifest.files[file],file);
});

test('ACVP corpus totals: 120 keyGen, 336 sigGen, 336 sigVer (48 valid, 288 invalid)', () => {
  const totals=[0,0,0,0,0];
  for (const set of sets) {
    const vectors=loadVectors(set);
    ['keyGen','sigGen','sigVer'].forEach((key,i)=> {totals[i]+=vectors[key as keyof typeof vectors].reduce((s,g)=>s+g.tests.length,0)});
    for (const group of vectors.sigVer) for (const c of group.tests) totals[c.testPassed?3:4]++;
  }
  assert.deepEqual(totals,[120,336,336,48,288]);
});
