import Generated.ToInt
import Spec.SlhDsa

/-!
Correctness of evaluation of the actual structurally extracted `toInt` program.
This theorem does not assume that a separately hand-coded toInt implements the
source: its left side is an interpreter applied to the generated source AST.
Frontend correctness and ECMAScript adequacy remain explicit trust boundaries.
-/
namespace TSExtracted

/-- The source's BigInt shift and OR equal one base-256 accumulation step. -/
theorem toInt_step_correct (acc : Nat) (byte : BitVec 8) :
    toIntProgram.evalStep acc byte = some (256 * acc + byte.toNat) := by
  simp [TSBigInt.Program.evalStep, toIntProgram, TSBigInt.evalBigInt,
    TSBigInt.Expr.eval, TSBigInt.bind, TSBigInt.shift_or_byte acc byte.toNat byte.isLt]

private theorem toInt_loop_correct (bytes : Spec.Bytes) (acc : Nat) :
    toIntProgram.evalLoop bytes acc =
      some (bytes.foldl (fun t b => 256 * t + b.toNat) acc) := by
  induction bytes generalizing acc with
  | nil => rfl
  | cons byte rest ih =>
    simp [TSBigInt.Program.evalLoop, toInt_step_correct, ih]

/-- For every byte string, the extracted function terminates successfully and
returns FIPS 205 Algorithm 2's exact mathematical integer. Includes empty and
arbitrarily long inputs; no 32-bit, 64-bit or 53-bit Number bound is imposed. -/
theorem toInt_source_correct (bytes : Spec.Bytes) :
    toIntProgram.denote bytes = some (Spec.toInt bytes) := by
  have init : TSBigInt.evalBigInt toIntProgram.initial TSBigInt.emptyEnv = some 0 := rfl
  have ret (n : Nat) : TSBigInt.evalBigInt toIntProgram.result
      (TSBigInt.bind TSBigInt.emptyEnv toIntProgram.accumulatorName (.bigint n)) = some n := by
    simp [toIntProgram, TSBigInt.evalBigInt, TSBigInt.Expr.eval, TSBigInt.bind]
  simp only [TSBigInt.Program.denote, init, ret]
  simp [toInt_loop_correct, Spec.toInt]

#print axioms toInt_source_correct

end TSExtracted
