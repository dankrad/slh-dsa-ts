import Spec.SlhDsa

/-!
# Loop refinements for the SLH-DSA mathematical model

These are kernel-checked equalities between executable Lean models and the
vendored `Spec.SlhDsa` (upstream rust-pq commit
462724e2b5f8ffe63a2ce76c9b1ab07099c1807b). They are NOT an extraction of
`src/index.ts`, nor a theorem about JavaScript/TypeScript execution.

The control flow corresponds to the source's chain loop, recursive XMSS/FORS
nodes, and hypertree signer's omission of its unused last recovered root.
Byte arrays, address mutation, hash APIs, buffer writes and JavaScript number
bounds are not modeled here: bytes are lists and indices are natural numbers.
-/

namespace Proofs.Loops

/-- Tail-recursive loop: process `count` successive indices starting at `start`.
The state is updated before the recursive call, as in an imperative for-loop. -/
def indexedLoop {α : Type} (step : α → Nat → α) (start : Nat) : Nat → α → α
  | 0, st => st
  | count + 1, st => indexedLoop step (start + 1) count (step st start)

private theorem range_succ_front (n : Nat) :
    List.range (n + 1) = 0 :: (List.range n).map Nat.succ := by
  induction n with
  | zero => rfl
  | succ n ih =>
    calc
      List.range (n + 1 + 1) = List.range (n + 1) ++ [n + 1] := List.range_succ
      _ = (0 :: (List.range n).map Nat.succ) ++ [n + 1] := by rw [ih]
      _ = 0 :: (List.range (n + 1)).map Nat.succ := by
        simp only [List.range_succ, List.map_append, List.map_cons, List.map_nil,
          List.cons_append, Nat.succ_eq_add_one]

/-- Refinement holds for every step function, state, starting index and count;
it has no hypothesis assuming the desired loop equality. -/
theorem indexedLoop_eq_fold {α : Type} (step : α → Nat → α)
    (start count : Nat) (st : α) :
    indexedLoop step start count st =
      (List.range count).foldl (fun acc j => step acc (start + j)) st := by
  induction count generalizing start st with
  | zero => rfl
  | succ count ih =>
    rw [indexedLoop, ih, range_succ_front]
    simp only [List.foldl_cons, List.foldl_map, Nat.add_zero]
    simp only [Nat.succ_eq_add_one, Nat.add_left_comm, Nat.add_comm]

/-- The common zero-based specialization used in upstream folds. -/
theorem indexedLoop_zero_eq_fold {α : Type} (step : α → Nat → α)
    (count : Nat) (st : α) :
    indexedLoop step 0 count st = (List.range count).foldl step st := by
  simpa only [Nat.zero_add] using indexedLoop_eq_fold step 0 count st

/-- Splitting an indexed loop at any iteration preserves its result. -/
theorem indexedLoop_add {α : Type} (step : α → Nat → α)
    (start first second : Nat) (st : α) :
    indexedLoop step start (first + second) st =
      indexedLoop step (start + first) second (indexedLoop step start first st) := by
  induction first generalizing start st with
  | zero => simp only [Nat.zero_add, Nat.add_zero, indexedLoop]
  | succ first ih =>
    rw [Nat.succ_add]
    change indexedLoop step (start + 1) (first + second) (step st start) =
      indexedLoop step (start + (first + 1)) second
        (indexedLoop step (start + 1) first (step st start))
    rw [show start + (first + 1) = (start + 1) + first by omega]
    exact ih (start + 1) (step st start)

/-- A terminating while-shaped model with an exclusive upper bound. -/
def boundedLoop {α : Type} (step : α → Nat → α) (stop index : Nat) (st : α) : α :=
  if index < stop then boundedLoop step stop (index + 1) (step st index) else st
termination_by stop - index
decreasing_by omega

/-- The while-shaped and count-based models coincide, including zero iterations. -/
theorem boundedLoop_eq_indexedLoop {α : Type} (step : α → Nat → α)
    (start count : Nat) (st : α) :
    boundedLoop step (start + count) start st = indexedLoop step start count st := by
  induction count generalizing start st with
  | zero => rw [boundedLoop]; simp [indexedLoop]
  | succ count ih =>
    rw [boundedLoop, ite_eq_left (by omega), indexedLoop]
    have hs : start + (count + 1) = (start + 1) + count := by omega
    rw [hs, ih]

/-- WOTS+ chain with the same loop shape as `src/index.ts`'s `chain`.
The hash and address are the *specification* operations, not extracted TS. -/
def chainLoop (p : Spec.Params) (x : Spec.Bytes) (start count : Nat)
    (pkSeed : Spec.Bytes) (adrs : Spec.Adrs) : Spec.Bytes :=
  boundedLoop (fun node j => Spec.F p pkSeed { adrs with word3 := j } node)
    (start + count) start x

/-- Algorithm 5 refinement for arbitrary parameters, bytes, address, start/count.
No length, parameter validity, or hash assumptions are required at this level. -/
theorem chainLoop_eq_spec (p : Spec.Params) (x : Spec.Bytes) (start count : Nat)
    (pkSeed : Spec.Bytes) (adrs : Spec.Adrs) :
    chainLoop p x start count pkSeed adrs = Spec.chain p x start count pkSeed adrs := by
  unfold chainLoop Spec.chain
  rw [boundedLoop_eq_indexedLoop, indexedLoop_eq_fold]

/-- Splitting a chain into successive segments is exact (including empty segments). -/
theorem chain_append (p : Spec.Params) (x : Spec.Bytes) (start first second : Nat)
    (pkSeed : Spec.Bytes) (adrs : Spec.Adrs) :
    Spec.chain p (Spec.chain p x start first pkSeed adrs) (start + first) second pkSeed adrs =
      Spec.chain p x start (first + second) pkSeed adrs := by
  simp only [← chainLoop_eq_spec, chainLoop, boundedLoop_eq_indexedLoop]
  exact (indexedLoop_add _ start first second x).symm

/-- A shared recursive binary-tree model, with index and height explicit.
This captures call structure, not aliasing of mutable TypeScript addresses. -/
def treeNode {α : Type} (leaf : Nat → α) (parent : Nat → Nat → α → α → α)
    (index : Nat) : Nat → α
  | 0 => leaf index
  | height + 1 =>
    let left := treeNode leaf parent (2 * index) height
    let right := treeNode leaf parent (2 * index + 1) height
    parent (height + 1) index left right

/-- The generic binary recursion specializes exactly to Algorithm 9. -/
theorem treeNode_xmss (p : Spec.Params) (skSeed pkSeed : Spec.Bytes)
    (adrs : Spec.Adrs) (index height : Nat) :
    treeNode
      (fun i => Spec.wotsPkGen p skSeed pkSeed
        { adrs.setTypeAndClear Spec.WOTS_HASH with keypair := i })
      (fun h i l r => Spec.H p pkSeed
        { adrs.setTypeAndClear Spec.TREE with word2 := h, word3 := i } (l ++ r))
      index height = Spec.xmssNode p skSeed index height pkSeed adrs := by
  induction height generalizing index with
  | zero => rfl
  | succ height ih => simp only [treeNode, Spec.xmssNode, ih]

/-- The generic binary recursion specializes exactly to Algorithm 15. -/
theorem treeNode_fors (p : Spec.Params) (skSeed pkSeed : Spec.Bytes)
    (adrs : Spec.Adrs) (index height : Nat) :
    treeNode
      (fun i => Spec.F p pkSeed { adrs with word2 := 0, word3 := i }
        (Spec.forsSkGen p skSeed pkSeed adrs i))
      (fun h i l r => Spec.H p pkSeed { adrs with word2 := h, word3 := i } (l ++ r))
      index height = Spec.forsNode p skSeed index height pkSeed adrs := by
  induction height generalizing index with
  | zero => rfl
  | succ height ih => simp only [treeNode, Spec.forsNode, ih]

/-- Suppress a scratch-state update at the last iteration. The first component
is observable output, the second component is all scratch state. -/
def skipLast {α β : Type} (count : Nat) (step : α × β → Nat → α × β)
    (st : α × β) (j : Nat) : α × β :=
  let next := step st j
  (next.1, if j + 1 < count then next.2 else st.2)

/-- Before the last iteration, even the entire scratch state is identical. -/
theorem skipLast_prefix {α β : Type} (step : α × β → Nat → α × β)
    (st : α × β) {k count : Nat} (h : k < count) :
    (List.range k).foldl (skipLast count step) st =
      (List.range k).foldl step st := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      ih (by omega), skipLast, ite_eq_left h]

/-- The final scratch-state update cannot affect the returned output. -/
theorem skipLast_output {α β : Type} (step : α × β → Nat → α × β)
    (st : α × β) (count : Nat) :
    ((List.range count).foldl (skipLast count step) st).1 =
      ((List.range count).foldl step st).1 := by
  cases count with
  | zero => rfl
  | succ k =>
    rw [List.range_succ, List.foldl_append, List.foldl_append,
      skipLast_prefix step st (by omega)]
    rfl

/-- Hypertree state: emitted signature, current root, tree index, leaf index. -/
abbrev HtState := Spec.Bytes × (Spec.Bytes × Nat × Nat)

/-- One full specification layer. -/
def htStep (p : Spec.Params) (skSeed pkSeed : Spec.Bytes) (st : HtState) (j : Nat) : HtState :=
  let adrs := { Spec.Adrs.zero with layer := j, tree := st.2.2.1 }
  let sig := Spec.xmssSign p st.2.1 skSeed st.2.2.2 pkSeed adrs
  (st.1 ++ sig,
    Spec.xmssPkFromSig p st.2.2.2 sig st.2.1 pkSeed adrs,
    st.2.2.1 >>> p.hp, st.2.2.1 % 2 ^ p.hp)

/-- Signer-shaped layer: the final recovered root is genuinely under the branch
and is not needed to produce signature output. Indices are still advanced. -/
def htStepSkipRoot (p : Spec.Params) (skSeed pkSeed : Spec.Bytes) (st : HtState)
    (j : Nat) : HtState :=
  let adrs := { Spec.Adrs.zero with layer := j, tree := st.2.2.1 }
  let sig := Spec.xmssSign p st.2.1 skSeed st.2.2.2 pkSeed adrs
  let root := if j + 1 < p.d then
    Spec.xmssPkFromSig p st.2.2.2 sig st.2.1 pkSeed adrs else st.2.1
  (st.1 ++ sig, root, st.2.2.1 >>> p.hp, st.2.2.1 % 2 ^ p.hp)

private theorem htStepSkipRoot_prefix (p : Spec.Params) (skSeed pkSeed : Spec.Bytes)
    (st : HtState) {k : Nat} (h : k < p.d) :
    (List.range k).foldl (htStepSkipRoot p skSeed pkSeed) st =
      (List.range k).foldl (htStep p skSeed pkSeed) st := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      ih (by omega), htStepSkipRoot, htStep, ite_eq_left h]

/-- A tail-recursive mathematical model of the TS hypertree signing loop. -/
def htSignLoop (p : Spec.Params) (msg skSeed pkSeed : Spec.Bytes)
    (idxTree idxLeaf : Nat) : Spec.Bytes :=
  (indexedLoop (htStepSkipRoot p skSeed pkSeed) 0 p.d ([], msg, idxTree, idxLeaf)).1

/-- For every parameter record (even zero layers), skipping the last recovery
preserves the entire hypertree signature. This is not a TypeScript theorem. -/
theorem htSignLoop_eq_spec (p : Spec.Params) (msg skSeed pkSeed : Spec.Bytes)
    (idxTree idxLeaf : Nat) :
    htSignLoop p msg skSeed pkSeed idxTree idxLeaf =
      Spec.htSign p msg skSeed pkSeed idxTree idxLeaf := by
  unfold htSignLoop
  rw [indexedLoop_zero_eq_fold]
  change ((List.range p.d).foldl (htStepSkipRoot p skSeed pkSeed)
    ([], msg, idxTree, idxLeaf)).1 =
      ((List.range p.d).foldl (htStep p skSeed pkSeed) ([], msg, idxTree, idxLeaf)).1
  generalize hd : p.d = count
  cases count with
  | zero => rfl
  | succ k =>
    rw [List.range_succ, List.foldl_append, List.foldl_append,
      htStepSkipRoot_prefix p skSeed pkSeed _ (by omega)]
    rfl

#print axioms indexedLoop_eq_fold
#print axioms indexedLoop_zero_eq_fold
#print axioms indexedLoop_add
#print axioms boundedLoop_eq_indexedLoop
#print axioms chainLoop_eq_spec
#print axioms chain_append
#print axioms treeNode_xmss
#print axioms treeNode_fors
#print axioms skipLast_prefix
#print axioms skipLast_output
#print axioms htSignLoop_eq_spec

end Proofs.Loops
