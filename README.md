# SLH-DSA in TypeScript

Independent Node.js/TypeScript implementation of the twelve **pure SLH-DSA** parameter sets in FIPS 205: SHA2 and SHAKE, each with 128s, 128f, 192s, 192f, 256s and 256f. Includes key generation, signing and verification. HashSLH-DSA (the mode that hashes a message before signing) and ASN.1 key encodings are not implemented.

## Verification status

**This TypeScript implementation is not formally verified.** It is designed for byte-for-byte conformance testing against NIST vectors and the Rust implementation at [`danrobinson/rust-pq`, commit `462724e`](https://github.com/danrobinson/rust-pq/tree/462724e2b5f8ffe63a2ce76c9b1ab07099c1807b). That repository contains a Lean specification and proofs of its Rust implementation. Those proofs do not apply to this independent TypeScript port. Tests establish agreement only on the tested inputs, not for all inputs.

The port follows [`lean/Spec/SlhDsa.lean`](https://github.com/danrobinson/rust-pq/blob/462724e2b5f8ffe63a2ce76c9b1ab07099c1807b/lean/Spec/SlhDsa.lean). Hash primitives use Node's `node:crypto`, adding Node/OpenSSL to the trusted runtime. No claim of constant-time JavaScript execution or reliable secret erasure is made. Treat this as research code, not an audited production signer.

## Development

Requires Node.js 22 or later.

```sh
npm ci --ignore-scripts
npm run build
npm run typecheck
npm test
```

The twelve `vectors/slh-dsa-*.json` files are copied unchanged from the pinned Rust reference, whose `vectors/README.md` identifies their NIST Automated Cryptographic Validation Protocol (ACVP) origin. The suite tests raw internal functions separately from pure-mode context framing.

## Formats and scope

Keys and signatures are raw byte strings. A public key is `PK.seed || PK.root`; a secret key is `SK.seed || SK.prf || PK.seed || PK.root`. Here `||` denotes concatenation; each field is `n` bytes (16, 24 or 32 for security levels 128, 192 or 256). `PK.seed` is the public hash seed, `PK.root` the hypertree root, `SK.seed` the secret key-generation seed, and `SK.prf` the secret message-randomizer key. The pure-mode signing input is `0x00 || context.length || context || message`; the length is encoded as one byte. A context is an application-provided domain-separation byte string, at most 255 bytes. Internal functions accept already-framed bytes and are exposed for conformance testing, not ordinary application signing.

MIT licensed; the Rust reference repository’s license is retained in `LICENSE`.

## API example

After building, run this as an ES module in the repository root:

```js
import { keygen, sign, verify } from './dist/index.js';
const set = 'SLH-DSA-SHA2-128f';
const { secretKey, publicKey } = keygen(set);
const message = new TextEncoder().encode('hello');
const context = new TextEncoder().encode('example/v1');
const signature = sign(set, message, secretKey, { context });
console.log(verify(set, message, signature, publicKey, context)); // true
```

`sign` defaults to fresh operating-system randomness. For reproducible signatures, pass `{ context, randomness: 'deterministic' }` to `sign`; this uses `PK.seed` instead of fresh randomness. An explicit `n`-byte `Uint8Array` supplies the signing randomness directly. `verify` returns `false` for malformed byte inputs, key/signature lengths, or contexts longer than 255 bytes. Unsupported parameter-set names throw `RangeError`.

Every seed argument is an `n`-byte `Uint8Array`. The lower-level `keygenInternal(set, skSeed, skPrf, pkSeed)`, `signInternal(set, message, secretKey, optRand?)` and `verifyInternal(set, message, signature, publicKey)` omit context framing. Omitted `optRand` uses `PK.seed` (deterministic mode), unlike the randomized external `sign` default. Prefer the external API above for applications.

`PARAMETER_NAMES` exports the twelve accepted strings (for example `SLH-DSA-SHAKE-256s`); `getParameters(set)` provides key/signature lengths and other Table 2 parameters.
