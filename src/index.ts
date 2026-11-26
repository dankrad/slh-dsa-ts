/**
 * Pure SLH-DSA (FIPS 205), all SHA2 and SHAKE parameter sets.
 *
 * Transcribed against the Rust and Lean specifications at reference commit
 * 462724e2b5f8ffe63a2ce76c9b1ab07099c1807b. This TypeScript implementation
 * is tested software, NOT covered by that repository's formal proofs.
 * Uses only Node's crypto primitives; no runtime package dependencies.
 *
 * Security: JavaScript/JIT execution is not constant-time. Secret-bearing
 * allocations are garbage-collected and cannot be reliably erased. This is
 * a readable reference implementation, not an audited key custody backend.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual, type Hash } from 'node:crypto';
import { getParameters, type ParameterName, type Parameters } from './params.js';
export { PARAMETER_NAMES, PARAMETERS, getParameters } from './params.js';
export type { ParameterName, Parameters } from './params.js';

export interface KeyPair {
  /** SK.seed || SK.prf || PK.seed || PK.root (4n bytes). */
  secretKey: Uint8Array;
  /** PK.seed || PK.root (2n bytes). */
  publicKey: Uint8Array;
}

export interface SignOptions {
  /** Arbitrary bytes, at most 255. Empty by default. */
  context?: Uint8Array;
  /**
   * Omitted: fresh randomBytes(n), i.e. hedged signing.
   * 'deterministic': use PK.seed as opt_rand (FIPS 205 deterministic mode).
   * Uint8Array: caller-supplied n-byte opt_rand; never a PRNG seed.
   */
  randomness?: Uint8Array | 'deterministic';
}

const EMPTY = new Uint8Array(0);
const WOTS_HASH = 0, WOTS_PK = 1, TREE = 2, FORS_TREE = 3;
const FORS_ROOTS = 4, WOTS_PRF = 5, FORS_PRF = 6;

function assertBytes(value: Uint8Array, label: string, length?: number): void {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${label} must be a Uint8Array`);
  if (length !== undefined && value.length !== length) {
    throw new RangeError(`${label} must be exactly ${length} bytes`);
  }
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

/** Algorithm 2. BigInt is essential: some tree indices use all 64 bits. */
function toInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** Algorithm 4, most significant bits first (not the old SPHINCS+ bit order). */
function base2b(bytes: Uint8Array, b: number, count: number): number[] {
  const out = new Array<number>(count);
  let input = 0, bits = 0, total = 0;
  for (let i = 0; i < count; i++) {
    while (bits < b) { total = (total << 8) | bytes[input++]!; bits += 8; }
    bits -= b;
    out[i] = (total >>> bits) & ((1 << b) - 1);
  }
  return out;
}

/** §4.2 address, encoded directly as full SHAKE ADRS or SHA2 ADRSc (§11.2). */
class Address {
  readonly bytes: Uint8Array;
  private readonly view: DataView;
  private readonly keyOffset: number;
  constructor(readonly shake: boolean, layer = 0, tree = 0n, type = 0, keypair = 0) {
    this.bytes = new Uint8Array(shake ? 32 : 22);
    this.view = new DataView(this.bytes.buffer);
    this.keyOffset = shake ? 20 : 10;
    if (shake) this.view.setUint32(0, layer);
    else this.bytes[0] = layer;
    this.view.setBigUint64(shake ? 8 : 1, tree);
    if (shake) this.view.setUint32(16, type);
    else this.bytes[9] = type;
    this.keypair(keypair);
  }
  /** setTypeAndClear, preserving only layer/tree; optionally restore keypair. */
  typed(type: number, keypair = 0): Address {
    const result = new Address(this.shake);
    const prefix = this.shake ? 16 : 9;
    result.bytes.set(this.bytes.subarray(0, prefix));
    if (this.shake) result.view.setUint32(16, type);
    else result.bytes[9] = type;
    result.keypair(keypair);
    return result;
  }
  keypair(value: number): this { this.view.setUint32(this.keyOffset, value); return this; }
  word2(value: number): this { this.view.setUint32(this.keyOffset + 4, value); return this; }
  word3(value: number): this { this.view.setUint32(this.keyOffset + 8, value); return this; }
}

/** §11: copy pre-seeded Node hash contexts to avoid rehashing the seed block. */
class Hashes {
  readonly shake: boolean;
  private readonly shortPrefix: Hash;
  private readonly longPrefix: Hash;
  readonly messageHash: 'sha256' | 'sha512';
  constructor(readonly p: Parameters, readonly pkSeed: Uint8Array) {
    this.shake = p.family === 'SHAKE';
    this.messageHash = p.n === 16 ? 'sha256' : 'sha512';
    if (this.shake) {
      this.shortPrefix = createHash('shake256', { outputLength: p.n }).update(pkSeed);
      this.longPrefix = this.shortPrefix;
    } else {
      this.shortPrefix = createHash('sha256').update(pkSeed).update(new Uint8Array(64 - p.n));
      this.longPrefix = p.n === 16 ? this.shortPrefix :
        createHash('sha512').update(pkSeed).update(new Uint8Array(128 - p.n));
    }
  }
  address(layer = 0, tree = 0n, type = 0, keypair = 0): Address {
    return new Address(this.shake, layer, tree, type, keypair);
  }
  /** F/PRF always SHA256 for SHA2, even when n is 24 or 32. */
  f(address: Address, value: Uint8Array): Uint8Array {
    return this.shortPrefix.copy(this.shake ? { outputLength: this.p.n } : undefined).update(address.bytes).update(value).digest().subarray(0, this.p.n);
  }
  /** H and T_l use SHA512 for SHA2 category 3/5; SHA256 for category 1. */
  t(address: Address, ...parts: Uint8Array[]): Uint8Array {
    const hash = this.longPrefix.copy(this.shake ? { outputLength: this.p.n } : undefined).update(address.bytes);
    for (const part of parts) hash.update(part);
    return hash.digest().subarray(0, this.p.n);
  }
  prfMessage(skPrf: Uint8Array, optRand: Uint8Array, message: Uint8Array): Uint8Array {
    if (this.shake) return createHash('shake256', { outputLength: this.p.n })
      .update(skPrf).update(optRand).update(message).digest();
    return createHmac(this.messageHash, skPrf).update(optRand).update(message).digest().subarray(0, this.p.n);
  }
  hMessage(r: Uint8Array, pkRoot: Uint8Array, message: Uint8Array): Uint8Array {
    if (this.shake) return createHash('shake256', { outputLength: this.p.m })
      .update(r).update(this.pkSeed).update(pkRoot).update(message).digest();
    const inner = createHash(this.messageHash).update(r).update(this.pkSeed).update(pkRoot).update(message).digest();
    const mgfSeed = createHash(this.messageHash).update(r).update(this.pkSeed).update(inner);
    const out = new Uint8Array(this.p.m);
    const counter = new Uint8Array(4);
    const cv = new DataView(counter.buffer);
    let offset = 0;
    for (let i = 0; offset < out.length; i++) {
      cv.setUint32(0, i);
      const block = mgfSeed.copy().update(counter).digest();
      const take = Math.min(block.length, out.length - offset);
      out.set(block.subarray(0, take), offset);
      offset += take;
    }
    return out;
  }
}

/** Algorithm 5: chain steps i,...,i+s-1. */
function chain(hash: Hashes, value: Uint8Array, start: number, steps: number, adrs: Address): Uint8Array {
  let node = value;
  for (let j = start; j < start + steps; j++) node = hash.f(adrs.word3(j), node);
  return node;
}

function wotsDigits(message: Uint8Array): number[] {
  const digits = base2b(message, 4, 2 * message.length);
  let checksum = 0;
  for (const digit of digits) checksum += 15 - digit;
  checksum <<= 4;
  digits.push(checksum >>> 12, (checksum >>> 8) & 15, (checksum >>> 4) & 15);
  return digits;
}

/** Algorithms 6 and 7 share secret generation; signing returns partial chains. */
function wotsGenerate(hash: Hashes, skSeed: Uint8Array, adrs: Address, keypair: number,
  message?: Uint8Array): Uint8Array {
  const { p } = hash;
  const digits = message === undefined ? undefined : wotsDigits(message);
  const secretAddress = adrs.typed(WOTS_PRF, keypair);
  const chainAddress = adrs.typed(WOTS_HASH, keypair);
  const values = new Uint8Array(p.len * p.n);
  for (let i = 0; i < p.len; i++) {
    const secret = hash.f(secretAddress.word2(i), skSeed);
    values.set(chain(hash, secret, 0, digits?.[i] ?? 15, chainAddress.word2(i)), i * p.n);
  }
  return message === undefined ? hash.t(adrs.typed(WOTS_PK, keypair), values) : values;
}

/** Algorithm 8. */
function wotsRecover(hash: Hashes, signature: Uint8Array, message: Uint8Array,
  adrs: Address, keypair: number): Uint8Array {
  const { p } = hash;
  const digits = wotsDigits(message);
  const chainAddress = adrs.typed(WOTS_HASH, keypair);
  const values = new Uint8Array(p.len * p.n);
  for (let i = 0; i < p.len; i++) {
    const digit = digits[i]!;
    values.set(chain(hash, signature.subarray(i * p.n, (i + 1) * p.n), digit,
      15 - digit, chainAddress.word2(i)), i * p.n);
  }
  return hash.t(adrs.typed(WOTS_PK, keypair), values);
}

/** Algorithm 9. Depth is at most 9. */
function xmssNode(hash: Hashes, skSeed: Uint8Array, index: number, height: number, adrs: Address): Uint8Array {
  if (height === 0) return wotsGenerate(hash, skSeed, adrs, index);
  const left = xmssNode(hash, skSeed, 2 * index, height - 1, adrs);
  const right = xmssNode(hash, skSeed, 2 * index + 1, height - 1, adrs);
  return hash.t(adrs.typed(TREE).word2(height).word3(index), left, right);
}

/** Shared authentication path climb, Algorithms 11 and 17. */
function climb(hash: Hashes, node: Uint8Array, index: number, auth: Uint8Array,
  height: number, adrs: Address): Uint8Array {
  for (let level = 0; level < height; level++) {
    const sibling = auth.subarray(level * hash.p.n, (level + 1) * hash.p.n);
    adrs.word2(level + 1).word3(Math.floor(index / 2));
    node = index % 2 === 0 ? hash.t(adrs, node, sibling) : hash.t(adrs, sibling, node);
    index = Math.floor(index / 2);
  }
  return node;
}

/** Algorithm 10. */
function xmssSign(hash: Hashes, message: Uint8Array, skSeed: Uint8Array, leaf: number, adrs: Address): Uint8Array {
  const { p } = hash;
  const out = new Uint8Array(p.xmssSignatureBytes);
  out.set(wotsGenerate(hash, skSeed, adrs, leaf, message));
  for (let j = 0; j < p.hp; j++) {
    out.set(xmssNode(hash, skSeed, (leaf >>> j) ^ 1, j, adrs), (p.len + j) * p.n);
  }
  return out;
}

/** Algorithm 11. */
function xmssRecover(hash: Hashes, signature: Uint8Array, message: Uint8Array, leaf: number,
  adrs: Address): Uint8Array {
  const node = wotsRecover(hash, signature, message, adrs, leaf);
  return climb(hash, node, leaf, signature.subarray(hash.p.len * hash.p.n), hash.p.hp, adrs.typed(TREE));
}

/** Algorithm 14. */
function forsSecret(hash: Hashes, skSeed: Uint8Array, index: number, adrs: Address, keypair: number): Uint8Array {
  return hash.f(adrs.typed(FORS_PRF, keypair).word3(index), skSeed);
}

/** Algorithm 15. Depth is at most 14, with only O(a*n) live node storage. */
function forsNode(hash: Hashes, skSeed: Uint8Array, index: number, height: number,
  adrs: Address, keypair: number): Uint8Array {
  if (height === 0) {
    const secret = forsSecret(hash, skSeed, index, adrs, keypair);
    return hash.f(adrs.word2(0).word3(index), secret);
  }
  const left = forsNode(hash, skSeed, 2 * index, height - 1, adrs, keypair);
  const right = forsNode(hash, skSeed, 2 * index + 1, height - 1, adrs, keypair);
  return hash.t(adrs.word2(height).word3(index), left, right);
}

/** Algorithm 16. */
function forsSign(hash: Hashes, md: Uint8Array, skSeed: Uint8Array, adrs: Address, keypair: number): Uint8Array {
  const { p } = hash;
  const indices = base2b(md, p.a, p.k);
  const out = new Uint8Array(p.forsSignatureBytes);
  let offset = 0;
  for (let i = 0; i < p.k; i++) {
    const index = indices[i]!;
    out.set(forsSecret(hash, skSeed, i * 2 ** p.a + index, adrs, keypair), offset);
    offset += p.n;
    for (let j = 0; j < p.a; j++) {
      out.set(forsNode(hash, skSeed, i * 2 ** (p.a - j) + ((index >>> j) ^ 1),
        j, adrs, keypair), offset);
      offset += p.n;
    }
  }
  return out;
}

/** Algorithm 17. */
function forsRecover(hash: Hashes, signature: Uint8Array, md: Uint8Array,
  adrs: Address, keypair: number): Uint8Array {
  const { p } = hash;
  const indices = base2b(md, p.a, p.k);
  const roots = new Uint8Array(p.k * p.n);
  for (let i = 0; i < p.k; i++) {
    const offset = i * (p.a + 1) * p.n;
    const index = i * 2 ** p.a + indices[i]!;
    const node = hash.f(adrs.word2(0).word3(index), signature.subarray(offset, offset + p.n));
    roots.set(climb(hash, node, index, signature.subarray(offset + p.n, offset + (p.a + 1) * p.n),
      p.a, adrs), i * p.n);
  }
  return hash.t(adrs.typed(FORS_ROOTS, keypair), roots);
}

function digestIndices(p: Parameters, digest: Uint8Array): { md: Uint8Array; tree: bigint; leaf: number } {
  const end = p.mdBytes + p.treeBytes;
  return {
    md: digest.subarray(0, p.mdBytes),
    tree: toInt(digest.subarray(p.mdBytes, end)) & ((1n << BigInt(p.h - p.hp)) - 1n),
    leaf: Number(toInt(digest.subarray(end, end + p.leafBytes)) & ((1n << BigInt(p.hp)) - 1n)),
  };
}

/** Algorithm 18. Seeds are each n bytes; outputs are fresh non-aliasing arrays. */
export function keygenInternal(name: ParameterName, skSeed: Uint8Array, skPrf: Uint8Array,
  pkSeed: Uint8Array): KeyPair {
  const p = getParameters(name);
  assertBytes(skSeed, 'skSeed', p.n); assertBytes(skPrf, 'skPrf', p.n); assertBytes(pkSeed, 'pkSeed', p.n);
  const hash = new Hashes(p, pkSeed);
  const root = xmssNode(hash, skSeed, 0, p.hp, hash.address(p.d - 1));
  return { secretKey: concat(skSeed, skPrf, pkSeed, root), publicKey: concat(pkSeed, root) };
}

/**
 * Algorithm 19, unframed internal message. Omitted optRand means PK.seed,
 * the deterministic variant. Do not confuse this with external sign(),
 * which frames the message/context and defaults to fresh randomness.
 */
export function signInternal(name: ParameterName, message: Uint8Array, secretKey: Uint8Array,
  optRand?: Uint8Array): Uint8Array {
  const p = getParameters(name);
  assertBytes(message, 'message'); assertBytes(secretKey, 'secretKey', p.secretKeyBytes);
  const skSeed = secretKey.subarray(0, p.n), skPrf = secretKey.subarray(p.n, 2 * p.n);
  const pkSeed = secretKey.subarray(2 * p.n, 3 * p.n), pkRoot = secretKey.subarray(3 * p.n);
  const randomness = optRand === undefined ? pkSeed : optRand;
  assertBytes(randomness, 'optRand', p.n);
  const hash = new Hashes(p, pkSeed);
  const r = hash.prfMessage(skPrf, randomness, message);
  const indices = digestIndices(p, hash.hMessage(r, pkRoot, message));
  let { tree, leaf } = indices;
  const adrs = hash.address(0, tree, FORS_TREE, leaf);
  const fsig = forsSign(hash, indices.md, skSeed, adrs, leaf);
  let root = forsRecover(hash, fsig, indices.md, adrs, leaf);
  const out = new Uint8Array(p.signatureBytes);
  out.set(r); out.set(fsig, p.n);
  let offset = p.n + p.forsSignatureBytes;
  const leafMask = (1n << BigInt(p.hp)) - 1n;
  for (let layer = 0; layer < p.d; layer++) {
    const address = hash.address(layer, tree);
    const xsig = xmssSign(hash, root, skSeed, leaf, address);
    out.set(xsig, offset); offset += xsig.length;
    if (layer + 1 < p.d) root = xmssRecover(hash, xsig, root, leaf, address);
    leaf = Number(tree & leafMask); tree >>= BigInt(p.hp);
  }
  return out;
}

/** Algorithm 20. Invalid byte inputs, malformed keys/signatures return false. */
export function verifyInternal(name: ParameterName, message: Uint8Array, signature: Uint8Array,
  publicKey: Uint8Array): boolean {
  const p = getParameters(name);
  if (!(message instanceof Uint8Array) || !(signature instanceof Uint8Array) ||
    !(publicKey instanceof Uint8Array) || signature.length !== p.signatureBytes ||
    publicKey.length !== p.publicKeyBytes) return false;
  const hash = new Hashes(p, publicKey.subarray(0, p.n));
  const pkRoot = publicKey.subarray(p.n);
  const indices = digestIndices(p, hash.hMessage(signature.subarray(0, p.n), pkRoot, message));
  let { tree, leaf } = indices;
  const end = p.n + p.forsSignatureBytes;
  let root = forsRecover(hash, signature.subarray(p.n, end), indices.md,
    hash.address(0, tree, FORS_TREE, leaf), leaf);
  const mask = (1n << BigInt(p.hp)) - 1n;
  let offset = end;
  for (let layer = 0; layer < p.d; layer++) {
    root = xmssRecover(hash, signature.subarray(offset, offset + p.xmssSignatureBytes),
      root, leaf, hash.address(layer, tree));
    offset += p.xmssSignatureBytes;
    leaf = Number(tree & mask); tree >>= BigInt(p.hp);
  }
  return timingSafeEqual(root, pkRoot);
}

/** Algorithm 21: three independent n-byte seeds from Node's operating-system RNG. */
export function keygen(name: ParameterName): KeyPair {
  const { n } = getParameters(name);
  return keygenInternal(name, randomBytes(n), randomBytes(n), randomBytes(n));
}

/** Algorithms 22/24 pure message framing, NOT HashSLH-DSA prehash framing. */
function withContext(message: Uint8Array, context: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(0, context.length), context, message);
}

/** Algorithm 22. Default randomness is fresh; choose 'deterministic' explicitly. */
export function sign(name: ParameterName, message: Uint8Array, secretKey: Uint8Array,
  options: SignOptions = {}): Uint8Array {
  const p = getParameters(name);
  assertBytes(message, 'message'); assertBytes(secretKey, 'secretKey', p.secretKeyBytes);
  const context = options.context === undefined ? EMPTY : options.context;
  assertBytes(context, 'context');
  if (context.length > 255) throw new RangeError('context must contain at most 255 bytes');
  const randomness = options.randomness === 'deterministic' ? secretKey.subarray(2 * p.n, 3 * p.n) :
    options.randomness === undefined ? randomBytes(p.n) : options.randomness;
  assertBytes(randomness, 'randomness', p.n);
  return signInternal(name, withContext(message, context), secretKey, randomness);
}

/** Algorithm 24. A context longer than 255 bytes is rejected, never truncated. */
export function verify(name: ParameterName, message: Uint8Array, signature: Uint8Array,
  publicKey: Uint8Array, context: Uint8Array = EMPTY): boolean {
  getParameters(name);
  if (!(message instanceof Uint8Array) || !(context instanceof Uint8Array) || context.length > 255) return false;
  return verifyInternal(name, withContext(message, context), signature, publicKey);
}
