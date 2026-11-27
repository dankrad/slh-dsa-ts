# Partial Lean refinement proofs

**The TypeScript SLH-DSA library is not formally verified end to end.** SLH-DSA
is the hash-based signature scheme standardized in FIPS 205; this library
implements its twelve pure-mode parameter sets. This directory, `formal/`,
contains one source-extracted byte-to-integer helper proof and separate mathematical model
proofs against the Lean specification from
[`danrobinson/rust-pq` at `462724e`](https://github.com/danrobinson/rust-pq/tree/462724e2b5f8ffe63a2ce76c9b1ab07099c1807b).
No theorem here proves the library's key-generation, signing or verification
entry points correct for all inputs. The production TypeScript is unchanged.

## What is proved

### Extracted byte-to-integer helper

`extract/extract-to-int.mjs` uses the TypeScript parser to extract the actual
`toInt` function from `src/index.ts`. It accepts a narrow function-body grammar:
accumulator initialization, a synchronous `for-of` over the input bytes with
one accumulator assignment, and a return expression. Expression operators,
literals and variable bindings become a structural syntax tree in
`Generated/ToInt.lean`; they are not replaced by a predefined arithmetic model.
Unsupported syntax is rejected. `Generated/BigIntSubset.lean` is the
**handwritten interpreter**, not generated code; its filename groups it with
the extraction-related modules.

The interpreter models bytes as 8-bit values and nonnegative JavaScript BigInt
as unbounded natural numbers. BigInt shifts and bitwise OR do not have the
32-bit truncation of JavaScript Number bitwise operators.

The kernel-checked theorem `TSExtracted.toInt_source_correct`, in
`Generated/ToIntCorrect.lean`, states, for **every finite byte list** `bytes`:

```text
toIntProgram.denote bytes = some (Spec.toInt bytes)
```

`toIntProgram` is the extracted syntax tree, `.denote` runs its interpreter,
and `Spec.toInt` is the upstream byte-to-integer function.

It proves successful termination and exact big-endian decoding under this
interpreter, including empty input and values above 64 bits. The proof consumes
the generated syntax tree. A source hash records provenance only; it is not
the argument for semantic equivalence. The extractor tests source mutations for changed syntax trees or rejection.
A separate negative-replay test changes the shift from 8 to 7 and the initial
accumulator from 0 to 1 in isolated copies: the original proof must fail, and
Lean checks concrete counterexamples to both mutated programs.

### Independent mathematical models

These proofs do **not** consume extracted TypeScript syntax:

- `Proofs/Parameters.lean`: all twelve independently stated parameter rows and
  derived lengths equal the upstream definitions; bounds cover digest
  partitions, 64-bit tree indices and nine-bit leaf indices.
- `Proofs/Framing.lean`: pure mode frames a message as
  `[0, context.length] ++ context ++ message`, with a one-byte length. This
  assembly equals the specification,
  is injective for contexts shorter than 256 bytes, and rejects oversized
  contexts in mathematical models of the API. `externalSign_refines` and
  `externalVerify_refines` prove that adding this framing around an internal
  signer or verifier preserves correctness **if every call to that internal
  operation already agrees with the spec**. That premise has not been proved
  for the TypeScript internal signer or verifier.
- `Proofs/Loops.lean`: indexed/while-shaped loop models, Winternitz one-time
  signature (WOTS) hash-chain composition,
  binary-tree recursion and omission of the signer's unused final recovered
  root preserve their corresponding specification results. The last recovered
  root is scratch state, unused after the last signature segment is emitted. Hashes and
  addresses in these models are the specification's operations, not Node
  calls or mutable TypeScript objects.

These are reusable lemmas, not evidence that the corresponding source
functions have already been verified. `formal/coverage.json` lists each proof category and the remaining unproved
source-level obligations.

## Trust boundary and remaining work

The helper result trusts the TypeScript parser, the structural extractor,
and the adequacy of the small interpreter to ECMAScript. Those components are
not themselves verified. It assumes ordinary, stable, non-shared Uint8Arrays,
pristine builtins and iterators, no detached buffers or concurrent mutation,
and sufficient resources. It does not cover arbitrary JavaScript subclasses,
prototype replacement or hostile execution environments.

Lean's kernel and standard logical foundations are trusted. The build-time axiom audit in `Proofs/AxiomAudit.lean`
allows only `propext`, `Classical.choice` and `Quot.sound`; it rejects `sorryAx`
and custom axioms reachable from any public theorem in this suite. The
upstream specification is the target, not a proved equivalence to the FIPS
205 English document. The four specification files copied into `formal/Spec/`
(`SlhDsa`, `Sha256`, `Sha512`, `Shake256`) are byte-for-byte copies; `upstream.json` pins their hashes and revision. The upstream MIT license
is retained in the repository root `LICENSE`.

Missing source-level obligations include the `base2b` function's
Number/Int32 bit-buffer arithmetic,
mutable buffers and aliasing, DataView address serialization, Node hashing and
hash-state cloning, assembly of WOTS and the XMSS/FORS signature-tree components, and the public API's validation and
randomness behavior. The internal keygen/sign/verify refinement theorems do
not exist yet. Completing them requires a source-to-semantics bridge for those
operations and compositional proofs; testing cannot discharge them.

No cryptographic security, constant-time execution, secret-erasure, runtime
resource bound or Node/V8/OpenSSL correctness claim is made.

## Reproduce

Use Node.js 22 or later and Lean **4.36.0**, matching `lean-toolchain`.
Install Lean with your normal Lean installation method and put its `lean` and
`lake` commands on `PATH`. No mathlib, Rust build or external Lean packages are
needed. From the repository root:

```sh
npm ci --ignore-scripts
npm run proof:check
```

The command checks pinned specification hashes, the Lean version, regenerated
AST freshness and extractor mutation tests, then builds every proof and runs
the axiom audit. For a clean replay, remove the ignored `formal/.lake` build
cache first. CI also runs the proof check, using a checksum-pinned official
Lean release, alongside the unchanged NIST-vector and Rust-reference conformance tests in
`test/`.
