# Running the harness

This harness tests the TypeScript implementation of SLH-DSA, the FIPS 205
hash-based signature scheme. Paths below are relative to the package root.
The TypeScript implementation is compared against the Rust implementation in [`danrobinson/rust-pq`](https://github.com/danrobinson/rust-pq) at
commit `462724e2b5f8ffe63a2ce76c9b1ab07099c1807b`.

Run `npm test` at the package root. `tsx --test test/*.test.ts` runs Node's test
runner, with separate files per parameter set to permit process parallelism.
No cases are sampled or skipped. Each NIST Automated Cryptographic Validation
Protocol (ACVP) case is independently named with its
parameter set, interface, group ID, case ID, and rejection reason where supplied.

Coverage includes all 792 cases copied from the pinned reference; exact key and signature bytes; input
non-mutation; twelve Rust-reference keypairs, each with one internal and one external
signature (24 signatures total); valid/invalid
verification; domain/context separation; signature/public-key truncation and
extension; seed/private-key/randomness lengths; Buffer/view byte offsets; 255-byte
and rejected 256-byte contexts; empty messages; hash-block-boundary message lengths;
and 1 MB messages for SHA2-128f and SHAKE-128f; explicit deterministic and default
hedged API modes (fixed PK.seed versus fresh per-signature randomness); unknown parameter names; and malformed JavaScript input types. Verification failures must return
false, while malformed keygen/signing input must throw.

For live cross-language verification run `npx tsx scripts/rust-differential.ts`.
It generates TypeScript keypairs and signatures, compares them byte-for-byte to
the checked-in Rust fixtures, and then asks a separately compiled Rust executable
to verify all 24 TypeScript signatures. An unmodified checkout of that Rust repository at the pinned commit, located at
`../reference` (a sibling of this package), and Rust/Cargo are needed only for this optional command.

The fixture provenance and scope are documented in `vectors/README.md`. Passing
this harness is not a formal proof of TypeScript correctness.
