import Generated.ToIntCorrect
import Proofs.Parameters
import Proofs.Framing
import Proofs.Loops
import Lean

/-! Reject nonstandard axiom dependencies of every public theorem in our three
proof namespaces. This is a build check, not a proof of runtime adequacy. -/
open Lean Elab Command in
run_elab do
  let env ← getEnv
  let allowed : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]
  let mut count : Nat := 0
  for (name, info) in env.constants.toList do
    if name.toString.startsWith "TSModel." || name.toString.startsWith "TSExtracted." ||
        name.toString.startsWith "Proofs.Loops." then
      if let .thmInfo _ := info then
        count := count + 1
        let axioms ← Lean.collectAxioms name
        for ax in axioms do
          unless allowed.contains ax do
            throwError "{name} depends on forbidden axiom {ax}"
  unless count ≥ 30 do
    throwError "Expected at least 30 public theorems, found {count}"
  logInfo m!"Axiom audit passed: {count} public theorems; only propext, Classical.choice, Quot.sound allowed"
