import Spec.SlhDsa

/-!
# Independent parameter arithmetic model (partial refinement only)

The row literals and arithmetic below model `src/params.ts` independently of
`Spec.Params`. These proofs compare mathematical definitions, not JavaScript
execution: parsing/extracting the actual TypeScript and IEEE-754 semantics are
outside this file. In particular, the tree index requires BigInt, not Number.
-/

namespace TSModel

inductive ParameterSet where
  | sha2_128s | sha2_128f | sha2_192s | sha2_192f | sha2_256s | sha2_256f
  | shake_128s | shake_128f | shake_192s | shake_192f | shake_256s | shake_256f
  deriving DecidableEq, Repr

inductive Family where
  | sha2 | shake
  deriving DecidableEq, Repr

structure ParameterRow where
  n : Nat
  h : Nat
  d : Nat
  hp : Nat
  a : Nat
  k : Nat
  m : Nat
  family : Family
  deriving DecidableEq, Repr

/-- Literal Table 2 rows, independently written, not projections of Spec. -/
def row : ParameterSet → ParameterRow
  | .sha2_128s => ⟨16, 63, 7, 9, 12, 14, 30, .sha2⟩
  | .sha2_128f => ⟨16, 66, 22, 3, 6, 33, 34, .sha2⟩
  | .sha2_192s => ⟨24, 63, 7, 9, 14, 17, 39, .sha2⟩
  | .sha2_192f => ⟨24, 66, 22, 3, 8, 33, 42, .sha2⟩
  | .sha2_256s => ⟨32, 64, 8, 8, 14, 22, 47, .sha2⟩
  | .sha2_256f => ⟨32, 68, 17, 4, 9, 35, 49, .sha2⟩
  | .shake_128s => ⟨16, 63, 7, 9, 12, 14, 30, .shake⟩
  | .shake_128f => ⟨16, 66, 22, 3, 6, 33, 34, .shake⟩
  | .shake_192s => ⟨24, 63, 7, 9, 14, 17, 39, .shake⟩
  | .shake_192f => ⟨24, 66, 22, 3, 8, 33, 42, .shake⟩
  | .shake_256s => ⟨32, 64, 8, 8, 14, 22, 47, .shake⟩
  | .shake_256f => ⟨32, 68, 17, 4, 9, 35, 49, .shake⟩

def upstream : ParameterSet → Spec.Params
  | .sha2_128s => Spec.sha2_128s
  | .sha2_128f => Spec.sha2_128f
  | .sha2_192s => Spec.sha2_192s
  | .sha2_192f => Spec.sha2_192f
  | .sha2_256s => Spec.sha2_256s
  | .sha2_256f => Spec.sha2_256f
  | .shake_128s => Spec.shake_128s
  | .shake_128f => Spec.shake_128f
  | .shake_192s => Spec.shake_192s
  | .shake_192f => Spec.shake_192f
  | .shake_256s => Spec.shake_256s
  | .shake_256f => Spec.shake_256f

def asSpec (r : ParameterRow) : Spec.Params :=
  { n := r.n, h := r.h, d := r.d, hp := r.hp, a := r.a, k := r.k,
    m := r.m, lgw := 4,
    family := match r.family with | .sha2 => .sha2 | .shake => .shake }

namespace ParameterRow

def len (r : ParameterRow) : Nat := 2 * r.n + 3
def mdBytes (r : ParameterRow) : Nat := (r.k * r.a + 7) / 8
def treeBytes (r : ParameterRow) : Nat := (r.h - r.hp + 7) / 8
def leafBytes (r : ParameterRow) : Nat := (r.hp + 7) / 8
def xmssSignatureBytes (r : ParameterRow) : Nat := (r.len + r.hp) * r.n
def forsSignatureBytes (r : ParameterRow) : Nat := r.k * (r.a + 1) * r.n
def signatureBytes (r : ParameterRow) : Nat :=
  r.n + r.forsSignatureBytes + r.d * r.xmssSignatureBytes
def publicKeyBytes (r : ParameterRow) : Nat := 2 * r.n
def secretKeyBytes (r : ParameterRow) : Nat := 4 * r.n

end ParameterRow

/-- Every field of every one of the twelve independent rows agrees with Spec. -/
theorem all_twelve_rows (s : ParameterSet) : asSpec (row s) = upstream s := by
  cases s <;> decide

/-- All machine-bound and digest-partition obligations of upstream Valid hold. -/
theorem all_twelve_valid (s : ParameterSet) : (asSpec (row s)).Valid := by
  cases s <;> constructor <;> decide

/-- Specialized `2*n+3` agrees with upstream's logarithmic WOTS formula. -/
theorem all_twelve_lengths (s : ParameterSet) :
    let r := row s
    let p := upstream s
    r.len = p.len ∧ r.mdBytes = p.mdBytes ∧
    r.treeBytes = p.treeBytes ∧ r.leafBytes = p.leafBytes ∧
    r.xmssSignatureBytes = p.xmssSigBytes ∧
    r.forsSignatureBytes = p.forsSigBytes ∧
    r.signatureBytes = p.sigBytes ∧
    r.publicKeyBytes = 2 * p.n ∧ r.secretKeyBytes = 4 * p.n := by
  cases s <;> decide

/-- Concrete signature sizes provide an additional independently stated oracle. -/
def expectedSignatureBytes : ParameterSet → Nat
  | .sha2_128s | .shake_128s => 7856
  | .sha2_128f | .shake_128f => 17088
  | .sha2_192s | .shake_192s => 16224
  | .sha2_192f | .shake_192f => 35664
  | .sha2_256s | .shake_256s => 29792
  | .sha2_256f | .shake_256f => 49856

theorem all_twelve_signature_sizes (s : ParameterSet) :
    (row s).signatureBytes = expectedSignatureBytes s := by
  cases s <;> decide

/-- Structural and precision bounds; these do not claim JavaScript semantics. -/
theorem all_twelve_bounds (s : ParameterSet) :
    let r := row s
    r.h = r.d * r.hp ∧ r.hp = r.h / r.d ∧
    0 < r.n ∧ 0 < r.d ∧ 0 < r.hp ∧
    r.hp ≤ 9 ∧ r.a ≤ 14 ∧ r.k ≤ 35 ∧
    r.h - r.hp ≤ 64 ∧
    r.k * 2 ^ r.a < 2 ^ 32 ∧
    r.signatureBytes < 2 ^ 53 ∧
    r.mdBytes + r.treeBytes + r.leafBytes = r.m := by
  cases s <;> decide

/-- Every tree-index domain exceeds the safe-integer domain of binary64.
This is why a Number-only tree-index implementation would be unsound. -/
theorem all_twelve_tree_indices_need_more_than_53_bits (s : ParameterSet) :
    53 < (row s).h - (row s).hp := by
  cases s <;> decide

/-- The mathematical digest reduction really yields a 64-bit tree index,
for arbitrary digest bytes, not just test vectors. -/
theorem digestTree_fits_64_bits (s : ParameterSet) (digest : Spec.Bytes) :
    Spec.digestTree (upstream s) digest < 2 ^ 64 := by
  cases s <;> unfold Spec.digestTree <;>
    exact Nat.lt_of_lt_of_le (Nat.mod_lt _ (by decide)) (by decide)

/-- The leaf index is at most nine bits, hence precisely representable as Number. -/
theorem digestLeaf_fits_9_bits (s : ParameterSet) (digest : Spec.Bytes) :
    Spec.digestLeaf (upstream s) digest < 2 ^ 9 := by
  cases s <;> unfold Spec.digestLeaf <;>
    exact Nat.lt_of_lt_of_le (Nat.mod_lt _ (by decide)) (by decide)

#print axioms all_twelve_rows
#print axioms all_twelve_valid
#print axioms all_twelve_lengths
#print axioms all_twelve_signature_sizes
#print axioms all_twelve_bounds
#print axioms all_twelve_tree_indices_need_more_than_53_bits
#print axioms digestTree_fits_64_bits
#print axioms digestLeaf_fits_9_bits

end TSModel
