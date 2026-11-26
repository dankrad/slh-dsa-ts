/** Read-only white-box checks derived from FIPS 205 and the pinned Lean spec. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import ts from 'typescript';

// Expose private helpers in a fresh in-memory module, without changing src or
// production exports. TypeScript is already a development dependency. tsx's
// loader resolves the absolute params.ts import from the generated data URL.
const paramsURL = new URL('../src/params.ts', import.meta.url).href;
const source = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')
  .replaceAll("from './params.js'", `from '${paramsURL}'`)
  + '\nexport { Address, Hashes, base2b, wotsDigits, digestIndices, withContext,'
  + ' forsSign, forsRecover, forsNode, wotsGenerate, wotsRecover };';
const code = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
}).outputText;
const m = await import('data:text/javascript;base64,' + Buffer.from(code).toString('base64'));
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

test('spec invariants: 4 exact full/compressed address and clearing assertions', () => {
  for (const shake of [false, true]) {
    const a = new m.Address(shake, 0x12, 0xfedcba9876543210n, 6, 0x12345678)
      .word2(0x90abcdef).word3(0xdeadbeef);
    assert.equal(hex(a.bytes), shake
      ? '0000001200000000fedcba9876543210000000061234567890abcdefdeadbeef'
      : '12fedcba9876543210061234567890abcdefdeadbeef');
    assert.equal(hex(a.typed(1, 2).bytes), shake
      ? '0000001200000000fedcba987654321000000001000000020000000000000000'
      : '12fedcba987654321001000000020000000000000000');
  }
});

test('spec invariants: 840 base2b assertions against an independent bitstring oracle', () => {
  // Deterministic xorshift32: reproducible varied bytes, not cryptographic RNG.
  let seed = 0x12345678;
  const next = () => {
    seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
    return seed >>> 0;
  };
  for (let b = 1; b <= 14; b++) for (let count = 1; count <= 60; count++) {
    const bytes = Uint8Array.from({ length: Math.ceil(b * count / 8) }, () => next() & 255);
    const bits = [...bytes].map(x => x.toString(2).padStart(8, '0')).join('');
    const expected = Array.from({ length: count }, (_, i) => parseInt(bits.slice(i * b, (i + 1) * b), 2));
    assert.deepEqual(m.base2b(bytes, b, count), expected, `b=${b}, count=${count}`);
  }
});

test('spec invariants: 108 all-set digest, checksum, hash and context rejection assertions', () => {
  for (const name of m.PARAMETER_NAMES) {
    const p = m.PARAMETERS[name];
    const indices = m.digestIndices(p, new Uint8Array(p.m).fill(255));
    assert.equal(indices.tree, (1n << BigInt(p.h - p.hp)) - 1n, `${name}: tree mask`);
    assert.equal(indices.leaf, 2 ** p.hp - 1, `${name}: leaf mask`);

    for (const fill of [0, 255, 0x5a]) {
      const message = new Uint8Array(p.n).fill(fill);
      const digits = [...message].flatMap(x => [x >> 4, x & 15]);
      const checksum = digits.reduce((sum, x) => sum + 15 - x, 0);
      assert.deepEqual(m.wotsDigits(message), [
        ...digits, (checksum >> 8) & 15, (checksum >> 4) & 15, checksum & 15,
      ], `${name}: checksum fill=${fill}`);
    }

    assert.throws(() => m.sign(name, new Uint8Array(), new Uint8Array(p.secretKeyBytes), {
      context: new Uint8Array(256),
    }), RangeError, `${name}: reject signing context 256`);
    assert.equal(m.verify(name, new Uint8Array(), new Uint8Array(p.signatureBytes),
      new Uint8Array(p.publicKeyBytes), new Uint8Array(256)), false, `${name}: reject verification context 256`);

    const seed = Uint8Array.from({ length: p.n }, (_, i) => i + 9);
    const hash = new m.Hashes(p, seed);
    const address = hash.address(13, 0xfedcba9876543210n, 3, 511).word2(14).word3(360447);
    const short = new Uint8Array(p.n).fill(0xa7);
    const long = new Uint8Array(p.n * 2).fill(0x3c);
    // Direct complete hash calls independently check the pre-seeded Hash.copy
    // optimization. This is not an independent SHA implementation/provider.
    const digest = (algorithm: string, ...parts: Uint8Array[]) => {
      const h = createHash(algorithm, p.family === 'SHAKE' ? { outputLength: p.n } : undefined);
      for (const part of parts) h.update(part);
      return h.digest().subarray(0, p.n);
    };
    assert.equal(hex(hash.f(address, short)), p.family === 'SHAKE'
      ? hex(digest('shake256', seed, address.bytes, short))
      : hex(digest('sha256', seed, new Uint8Array(64 - p.n), address.bytes, short)), `${name}: F/PRF`);
    assert.equal(hex(hash.t(address, long)), p.family === 'SHAKE'
      ? hex(digest('shake256', seed, address.bytes, long))
      : hex(digest(p.n === 16 ? 'sha256' : 'sha512', seed,
        new Uint8Array((p.n === 16 ? 64 : 128) - p.n), address.bytes, long)), `${name}: H/T`);
  }
});

test('spec invariants: 3 exact empty, one-byte and 255-byte context framing assertions', () => {
  for (const length of [0, 1, 255]) {
    const context = new Uint8Array(length).fill(7), message = Uint8Array.of(255, 0);
    assert.equal(hex(m.withContext(message, context)),
      hex(Uint8Array.from([0, length, ...context, ...message])));
  }
});

test('spec invariants: 72 WOTS reconstruction and reduced-height FORS root assertions', () => {
  for (const name of m.PARAMETER_NAMES) {
    const p = m.PARAMETERS[name];
    const secret = Uint8Array.from({ length: p.n }, (_, i) => (i * 37 + 9) & 255);
    const seed = new Uint8Array(p.n).fill(0x43), hash = new m.Hashes(p, seed);
    const address = hash.address(16, 0xffffffffffffffffn);
    const publicKey = m.wotsGenerate(hash, secret, address, 511);
    for (const fill of [0, 255, 90]) {
      const message = new Uint8Array(p.n).fill(fill);
      const signature = m.wotsGenerate(hash, secret, address, 511, message);
      assert.equal(hex(m.wotsRecover(hash, signature, message, address, 511)), hex(publicKey),
        `${name}: WOTS fill=${fill}`);
    }

    // Internal-only custom parameters exercise FORS recurrence and global tree
    // offsets cheaply. They are NOT an allowed public FIPS 205 parameter set,
    // and these cases do not replace full-parameter ACVP/Rust conformance.
    const reduced = { ...p, a: 3, k: 3, mdBytes: 2, forsSignatureBytes: 3 * 4 * p.n };
    const forsHash = new m.Hashes(reduced, seed);
    const forsAddress = forsHash.address(0, 0xffffffffffffffffn, 3, 511);
    const roots = Array.from({ length: reduced.k }, (_, i) =>
      m.forsNode(forsHash, secret, i, reduced.a, forsAddress, 511));
    const expected = forsHash.t(forsAddress.typed(4, 511), ...roots);
    for (const md of [Uint8Array.of(255, 255), Uint8Array.of(0, 0), Uint8Array.of(0xe7, 0x80)]) {
      const signature = m.forsSign(forsHash, md, secret, forsAddress, 511);
      assert.equal(hex(m.forsRecover(forsHash, signature, md, forsAddress, 511)), hex(expected),
        `${name}: reduced FORS digest=${hex(md)}`);
    }
  }
});
