# Reference and vector provenance

Reference: https://github.com/danrobinson/rust-pq
Commit: 462724e2b5f8ffe63a2ce76c9b1ab07099c1807b

The implementation is an independent TypeScript transcription informed by the upstream Lean specification and Rust implementation. The upstream MIT license and attribution are retained in LICENSE.

The twelve vectors/slh-dsa-*.json files are copied unchanged from that commit. Upstream identifies these as NIST ACVP pure-mode vectors extracted from https://github.com/usnistgov/ACVP-Server at gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/internalProjection.json. The upstream extraction script is scripts/extract_vectors.py. No direct independent retrieval from NIST is claimed here.
