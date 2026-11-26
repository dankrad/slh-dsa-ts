# Conformance results and proof boundary

This TypeScript library implements all twelve pure SLH-DSA parameter sets (signing messages directly, rather than the separate HashSLH-DSA prehash mode). The Rust reference implementation is pinned to [danrobinson/rust-pq commit 462724e](https://github.com/danrobinson/rust-pq/tree/462724e2b5f8ffe63a2ce76c9b1ab07099c1807b).

## Executed checks

- Build and strict source typecheck passed. Strict explicit checking of tests/scripts also passed.
- All 792 NIST Automated Cryptographic Validation Protocol (ACVP) cases passed: 120 key generation, 336 signing, 336 verification. Verification accepted all 48 valid signatures and rejected all 288 invalid signatures. All twelve vector files copied from the Rust reference were independently compared byte-for-byte to the pinned reference; hashes are in `vectors/manifest.json`.
- All 36 fixture differential tests passed: twelve Rust keypairs and 24 Rust signatures match TypeScript byte-for-byte.
- A separately compiled Rust executable accepted all 24 TypeScript-generated signatures (internal and external interfaces, all twelve sets).
- 951 final tests passed across split invocations: 926 initial tests, 20 additional API-mode tests, and five specification-invariant tests. The five invariant tests contain 1027 assertions; the 792 ACVP cases are included in the initial 926 tests. No cases were sampled or skipped. The initial modes run had a harness-only expectation error about the documented deterministic internal default; it was corrected before the final passing run.
- Specification review found no blocking mismatch in parameters, hashing domains, address bytes/reset, WOTS, FORS, BigInt tree indices or pure context framing. See `test/SPEC_REVIEW.md`.
- npm audit reported zero vulnerabilities. actionlint and zizmor passed. Gitleaks found only twelve synthetic, reproducible test-secret-key false positives; exact fingerprints are documented in `.gitleaksignore`. The rescan passed.
- README example executed successfully. Tests ran on Node 24.22.3; Node 22 is declared compatible but was not directly exercised.

Reproduce ordinary conformance checks with `npm ci --ignore-scripts && npm run build && npm run typecheck && npm test`. The optional `npm run test:rust` needs Cargo and the unmodified pinned reference as sibling directory `../reference`. See `test/README.md` and `vectors/README.md` for scope and fixture regeneration.

## What is not proved

This TypeScript implementation is **not formally verified**. The reference's Lean proofs concern its Rust/Aeneas program, not this TypeScript program. No TypeScript-to-Lean refinement proof, proof of Node/OpenSSL, Lean build replay, constant-time guarantee, reliable secret erasure, audit or NIST validation is supplied. HashSLH-DSA and ASN.1 encodings are not implemented. Passing tests establishes agreement on tested inputs only.
