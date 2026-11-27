# Development
Node.js 22 or later. Install using `npm ci --ignore-scripts`.
Run `npm run build`, `npm run typecheck`, and `npm test`.
All twelve pure FIPS 205 parameter sets are in scope; HashSLH-DSA is not.
The upstream reference is danrobinson/rust-pq at 462724e2b5f8ffe63a2ce76c9b1ab07099c1807b.
Do not describe testing or Rust's Lean proofs as a formal proof of this TypeScript implementation.
JavaScript execution has no constant-time or reliable secret-erasure guarantee.

Partial formal proofs: install the pinned Lean toolchain in `formal/lean-toolchain`, then run `npm run proof:check`. Read `formal/README.md` for the precise source-extraction and model-only boundaries. Do not change vendored `formal/Spec` files or describe partial proofs as full keygen/sign/verify verification.
