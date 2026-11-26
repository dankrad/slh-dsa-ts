import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { keygenInternal, signInternal, verifyInternal, sign, verify } from '../src/index.js';

export type Name = Parameters<typeof keygenInternal>[0];
export type VectorCase = Record<string, string | number | boolean> & { tcId: number };
export type VectorGroup = { parameterSet: Name; tgId: number; deterministic?: boolean; signatureInterface?: string; tests: VectorCase[] };
export type Vectors = { keyGen: VectorGroup[]; sigGen: VectorGroup[]; sigVer: VectorGroup[] };
export const sets = ['sha2-128s','sha2-128f','sha2-192s','sha2-192f','sha2-256s','sha2-256f','shake-128s','shake-128f','shake-192s','shake-192f','shake-256s','shake-256f'] as const;
export const nameOf = (set: string) => ('SLH-DSA-' + set.replace(/^sha2/, 'SHA2').replace(/^shake/, 'SHAKE')) as Name;
export const nOf = (set: string) => Number(set.match(/(128|192|256)/)![0]) / 8;
export const sigBytesOf = (set: string) => ({ '128s': 7856, '128f': 17088, '192s': 16224, '192f': 35664, '256s': 29792, '256f': 49856 }[set.slice(-4)]!);
export const hex = (value: unknown): Uint8Array => {
  assert.equal(typeof value, 'string', 'vector byte field must be a hex string');
  assert.match(value as string, /^(?:[a-fA-F0-9]{2})*$/, 'invalid vector hexadecimal');
  return new Uint8Array(Buffer.from(value as string, 'hex'));
};
export const bytes = (size: number, salt = 0) => Uint8Array.from({length: size}, (_, i) => (i * 113 + salt) & 255);
export const mutate = (input: Uint8Array, position = 0) => { const copy = input.slice(); copy[position] ^= 1; return copy; };
export const concat = (...parts: Uint8Array[]) => new Uint8Array(Buffer.concat(parts));
export const toHex = (input: Uint8Array) => Buffer.from(input).toString('hex');
export const digest = (input: Uint8Array | string) => createHash('sha256').update(input).digest('hex');
export function equalBytes(actual: Uint8Array, expected: Uint8Array, label: string) {
  assert.ok(actual instanceof Uint8Array, `${label}: output must be Uint8Array`);
  assert.equal(actual.length, expected.length, `${label}: byte length`);
  // Do not dump tens of thousands of signature bytes on failure.
  const mismatch = actual.findIndex((value, index) => value !== expected[index]);
  assert.equal(mismatch, -1, `${label}: first mismatch at byte ${mismatch}; SHA256 actual=${digest(actual)}, expected=${digest(expected)}`);
}
export const loadVectors = (set: string): Vectors => JSON.parse(readFileSync(new URL(`../vectors/slh-dsa-${set}.json`, import.meta.url), 'utf8'));

export function registerAcvp(set: string) {
  const vectors = loadVectors(set);
  const name = nameOf(set), n = nOf(set);
  test(`${name}: vector coverage`, () => {
    assert.deepEqual(['keyGen','sigGen','sigVer'].map(k => (vectors[k as keyof Vectors]).reduce((s,g) => s + g.tests.length, 0)), [10,28,28]);
    assert.deepEqual(vectors.sigVer.flatMap(g => g.tests).reduce((a,t) => {a[t.testPassed ? 0 : 1]++; return a}, [0,0]), [4,24]);
  });
  for (const group of vectors.keyGen) for (const c of group.tests) {
    test(`${name}: ACVP keyGen tgId=${group.tgId} tcId=${c.tcId}`, () => {
      const seeds = [hex(c.skSeed), hex(c.skPrf), hex(c.pkSeed)];
      const copies = seeds.map(toHex);
      const keys = keygenInternal(name, seeds[0], seeds[1], seeds[2]);
      equalBytes(keys.publicKey, hex(c.pk), 'public key');
      equalBytes(keys.secretKey, hex(c.sk), 'secret key');
      assert.deepEqual(seeds.map(toHex), copies, 'keygen must not mutate seeds');
      equalBytes(keys.secretKey.subarray(2*n), keys.publicKey, 'secret key embeds public key');
    });
  }
  for (const group of vectors.sigGen) for (const c of group.tests) {
    test(`${name}: ACVP sigGen ${group.signatureInterface} ${group.deterministic ? 'deterministic' : 'hedged'} tgId=${group.tgId} tcId=${c.tcId}`, () => {
      const sk = hex(c.sk), msg = hex(c.message), ctx = hex(c.context ?? '');
      const rand = group.deterministic ? sk.slice(2*n, 3*n) : hex(c.additionalRandomness);
      const inputs = [sk, msg, ctx, rand], copies = inputs.map(toHex);
      const sig = group.signatureInterface === 'internal'
        ? signInternal(name, msg, sk, rand)
        : sign(name, msg, sk, { context: ctx, randomness: rand });
      assert.equal(sig.length, sigBytesOf(set));
      equalBytes(sig, hex(c.signature), 'signature');
      const pk = hex(c.pk);
      const verified = group.signatureInterface === 'internal'
        ? verifyInternal(name, msg, sig, pk)
        : verify(name, msg, sig, pk, ctx);
      assert.equal(verified, true, 'generated known-answer signature must verify');
      assert.deepEqual(inputs.map(toHex), copies, 'sign must not mutate caller inputs');
    });
  }
  for (const group of vectors.sigVer) for (const c of group.tests) {
    test(`${name}: ACVP sigVer ${group.signatureInterface} ${c.testPassed ? 'valid' : 'invalid'} tgId=${group.tgId} tcId=${c.tcId} ${c.reason ?? ''}`, () => {
      const pk = hex(c.pk), msg = hex(c.message), sig = hex(c.signature), ctx = hex(c.context ?? '');
      const inputs = [pk,msg,sig,ctx], copies = inputs.map(toHex);
      const verified = group.signatureInterface === 'internal'
        ? verifyInternal(name, msg, sig, pk)
        : verify(name, msg, sig, pk, ctx);
      assert.equal(verified, c.testPassed, String(c.reason));
      assert.deepEqual(inputs.map(toHex), copies, 'verify must not mutate caller inputs');
    });
  }
}
