# Independent specification review

This package implements the twelve pure SHA2/SHAKE parameter sets of
SLH-DSA (FIPS 205) in TypeScript. Its `src/index.ts` and `src/params.ts`
were reviewed against
[danrobinson/rust-pq at 462724e2b5f8ffe63a2ce76c9b1ab07099c1807b](https://github.com/danrobinson/rust-pq/tree/462724e2b5f8ffe63a2ce76c9b1ab07099c1807b),
especially the mathematical transcription in `lean/Spec/SlhDsa.lean` and
the Rust implementation in `rust/src/`. No blocking correctness
mismatch was found. Production source was not changed by this review.

A hash address selects a domain-separated hash instance. Its fields encode
the layer, tree, operation type, key pair, chain or height, and hash or node
index. Changing operation type clears the lower fields to prevent stale values.
Checked hash-address serialization and reset of fields on address-type changes;
SHA2/SHAKE hash inputs and SHA2 mask-generation counters; BigInt tree indices;
WOTS one-time-signature checksums and chain endpoints; FORS few-time-signature
tree offsets, authentication paths and mutable address reuse; context framing
and rejection; and exact key/signature lengths.
The SHA2-256f and SHAKE-256f parameter sets use a 64-bit tree index, so converting it to a JavaScript Number
would lose information. The reviewed implementation keeps it as BigInt.

## Reproduction

`npx tsx --test test/spec-invariants.test.ts` runs **1027 assertions** in
five Node tests, one per scope below. `npm test` includes the same file automatically.

| Scope | Assertions |
| --- | ---: |
| Exact full/compressed address bytes and field clearing | 4 |
| Base-2^b digit extraction versus binary-string slicing | 840 |
| All twelve sets: maximum digest indices, checksum, hashes, context rejection | 108 |
| Exact context framing at lengths 0, 1 and 255 | 3 |
| WOTS reconstruction and reduced-height FORS roots | 72 |

The tests expose private helpers only in a fresh in-memory module using the
existing TypeScript development dependency; they do not alter production
files or exports. Hash checks use direct Node hash calls backed by OpenSSL,
not an independent hash provider. FORS component cases use custom tree height
`a=3` and tree count `k=3`
to check recurrence and offsets; they are not supported public parameter sets
or substitutes for the separate full-parameter NIST Automated Cryptographic
Validation Protocol (ACVP) vectors and Rust comparison tests described in
[`test/README.md`](README.md).

## Proof boundary

Proofs in the referenced Rust repository, such as `lean/Slhdsa/Theorems.lean` and
`lean/Slhdsa/Proofs/ShakeSlh.lean` relate a translation of the Rust program
automatically extracted into Lean by Aeneas to the mathematical specification.
Proof sources were inspected, but Lean builds were **not
replayed** during this review. Neither those proofs nor the 1027 passing
assertions formally prove this TypeScript program or Node/OpenSSL. JavaScript
execution has no constant-time or reliable secret-erasure guarantee. This
review is not a cryptographic audit or an unconditional security proof.
