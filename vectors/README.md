# Test vector provenance

These fixtures test this package's TypeScript implementation of SLH-DSA, the
hash-based signature scheme standardized in FIPS 205. Paths below are relative
to the package root. The twelve parameter sets combine SHA2/SHAKE hash families,
128/192/256-bit security levels, and small-signature (s) or fast-signing (f) variants.

The twelve `slh-dsa-{sha2,shake}-{128,192,256}{s,f}.json` files are byte-for-byte
copies of [`danrobinson/rust-pq` vectors](https://github.com/danrobinson/rust-pq/tree/462724e2b5f8ffe63a2ce76c9b1ab07099c1807b/vectors)
at commit `462724e2b5f8ffe63a2ce76c9b1ab07099c1807b` (the Rust reference implementation is in that repository's `rust/` directory).
SHA-256 checksums are in `vectors/manifest.json` and checked by `test/corpus.test.ts`.

That repository attributes these to [NIST's ACVP-Server](https://github.com/usnistgov/ACVP-Server):
`gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/internalProjection.json`,
extracted with its [`scripts/extract_vectors.py`](https://github.com/danrobinson/rust-pq/blob/462724e2b5f8ffe63a2ce76c9b1ab07099c1807b/scripts/extract_vectors.py).
The upstream extraction excludes HashSLH-DSA groups, which sign a prehashed
message rather than using the pure message interface. The upstream vector
README does not record the original ACVP-Server commit; we pin the exact copied
corpus, not an independently identified NIST revision.

Each parameter set has 10 keyGen (key generation), 28 sigGen (signing), and
28 sigVer (verification) test cases. Total: 120 keyGen, 336 sigGen,
336 sigVer (48 valid signatures accepted and 288 invalid signatures rejected). Both internal and pure external
interfaces, deterministic and hedged signing, and external contexts are exercised. The
external interface frames the message with a context string; the internal
interface signs its input without that framing. Deterministic signing uses
the public key's seed component (PK.seed) as per-signature randomness; hedged signing supplies fresh random bytes.

`rust-differential.json` contains twelve additional reproducible fixtures generated
from the same pinned Rust reference using its default public API, with no optional
hardware/platform features. Each has one keypair and two signatures (internal and
pure external); the generator verifies both before writing them. Inputs include
empty messages, message lengths around hash-block boundaries, and 255-byte contexts.
Regenerate with `scripts/regenerate-rust-fixtures.sh` while the unmodified pinned
reference repository is checked out at the stated commit as `../reference`,
a sibling of this package directory. This requires Rust/Cargo.
The Cargo lockfile under `scripts/rust-fixtures` pins the helper's dependencies.

These are conformance and differential tests, not formal verification of the
TypeScript code, cryptographic validation, an audit, constant-time evidence, or
secret-erasure evidence. Ordinary `npm test` needs only Node and the checked-in
fixtures, not a Rust toolchain or a network connection.
