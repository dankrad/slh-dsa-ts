import Spec.SlhDsa

/-!
# Pure-mode context framing (partial mathematical refinement)

`frame` models the byte assembly in `src/index.ts`: a zero domain byte,
one context-length byte, the context, then the message. `externalSign` and
`externalVerify` model the typed, already validated API path. They do NOT
model JavaScript type checks, exceptions, random generation, mutation,
resource bounds, or the internal cryptographic implementation. The generic
assembly theorems require pointwise correctness of the INTERNAL operation;
they do not assume correctness of the external operation being proved.
-/

namespace TSModel
namespace Framing

abbrev Bytes := Spec.Bytes

/-- Independent pure-mode assembly; BitVec.ofNat models byte conversion. -/
def frame (message context : Bytes) : Bytes :=
  [0#8, BitVec.ofNat 8 context.length] ++ context ++ message

/-- A one-byte big-endian encoding reduces to the low byte. -/
theorem toByte_one (n : Nat) : Spec.toByte n 1 = [BitVec.ofNat 8 n] := by
  rfl

/-- All byte strings, not merely concrete vectors. In valid APIs context <256. -/
theorem frame_eq_spec (message context : Bytes) :
    frame message context = Spec.withContext message context := by
  rw [Spec.withContext, toByte_one, toByte_one]
  rfl

theorem frame_length (message context : Bytes) :
    (frame message context).length = 2 + context.length + message.length := by
  simp [frame]
  omega

/-- The two-byte header and length bound make pure-mode framing injective. -/
theorem frame_injective (message₁ context₁ message₂ context₂ : Bytes)
    (h₁ : context₁.length < 256) (h₂ : context₂.length < 256)
    (heq : frame message₁ context₁ = frame message₂ context₂) :
    context₁ = context₂ ∧ message₁ = message₂ := by
  have hbyte : BitVec.ofNat 8 context₁.length = BitVec.ofNat 8 context₂.length := by
    have hx := congrArg (fun bs : Bytes => bs[1]?) heq
    simpa [frame] using hx
  have hnat := congrArg BitVec.toNat hbyte
  have hlen : context₁.length = context₂.length := by
    simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt h₁, Nat.mod_eq_of_lt h₂] using hnat
  have hrest : context₁ ++ message₁ = context₂ ++ message₂ := by
    exact (List.cons.inj (List.cons.inj heq).2).2
  have hctx : context₁ = context₂ := by
    have ht := congrArg (List.take context₁.length) hrest
    simpa [List.take_append, hlen] using ht
  constructor
  · exact hctx
  · subst context₂
    exact List.append_cancel_left hrest

/-- The typed sign model represents rejected context as none, not an exception. -/
def externalSign (internal : Bytes → Bytes → Bytes → Bytes)
    (message context secretKey randomness : Bytes) : Option Bytes :=
  if context.length < 256 then
    some (internal (frame message context) secretKey randomness)
  else none

/-- The typed verify model rejects oversized context before the internal call. -/
def externalVerify (internal : Bytes → Bytes → Bytes → Bool)
    (message signature context publicKey : Bytes) : Bool :=
  if context.length < 256 then
    internal (frame message context) signature publicKey
  else false

theorem externalSign_accept (internal : Bytes → Bytes → Bytes → Bytes)
    (message context secretKey randomness : Bytes) (h : context.length < 256) :
    externalSign internal message context secretKey randomness =
      some (internal (Spec.withContext message context) secretKey randomness) := by
  simp [externalSign, h, frame_eq_spec]

theorem externalSign_reject (internal : Bytes → Bytes → Bytes → Bytes)
    (message context secretKey randomness : Bytes) (h : 255 < context.length) :
    externalSign internal message context secretKey randomness = none := by
  have hn : ¬ context.length < 256 := by omega
  simp [externalSign, hn]

theorem externalVerify_accept (internal : Bytes → Bytes → Bytes → Bool)
    (message signature context publicKey : Bytes) (h : context.length < 256) :
    externalVerify internal message signature context publicKey =
      internal (Spec.withContext message context) signature publicKey := by
  simp [externalVerify, h, frame_eq_spec]

theorem externalVerify_reject (internal : Bytes → Bytes → Bytes → Bool)
    (message signature context publicKey : Bytes) (h : 255 < context.length) :
    externalVerify internal message signature context publicKey = false := by
  have hn : ¬ context.length < 256 := by omega
  simp [externalVerify, hn]

/-- Composition, not circular external correctness: only the INTERNAL
operation is required to refine the upstream internal operation pointwise. -/
theorem externalSign_refines (p : Spec.Params)
    (internal : Bytes → Bytes → Bytes → Bytes)
    (hInternal : ∀ msg sk rnd, internal msg sk rnd = Spec.slhSignInternal p msg sk rnd)
    (message context secretKey randomness : Bytes) :
    externalSign internal message context secretKey randomness =
      Spec.slhSign p message context secretKey randomness := by
  by_cases h : context.length < 256
  · have hn : ¬ context.length > 255 := by omega
    simp only [externalSign, ite_eq_left h, Spec.slhSign, ite_eq_right hn]
    rw [frame_eq_spec, hInternal]
  · have hn : context.length > 255 := by omega
    simp only [externalSign, ite_eq_right h, Spec.slhSign, ite_eq_left hn]

/-- Verification API assembly follows from pointwise INTERNAL refinement. -/
theorem externalVerify_refines (p : Spec.Params)
    (internal : Bytes → Bytes → Bytes → Bool)
    (hInternal : ∀ msg sig pk, internal msg sig pk = Spec.slhVerifyInternal p msg sig pk)
    (message signature context publicKey : Bytes) :
    externalVerify internal message signature context publicKey =
      Spec.slhVerify p message signature context publicKey := by
  by_cases h : context.length < 256
  · have hn : ¬ context.length > 255 := by omega
    simp only [externalVerify, ite_eq_left h, Spec.slhVerify, ite_eq_right hn]
    rw [frame_eq_spec, hInternal]
  · have hn : context.length > 255 := by omega
    simp only [externalVerify, ite_eq_right h, Spec.slhVerify, ite_eq_left hn]

#print axioms toByte_one
#print axioms frame_eq_spec
#print axioms frame_length
#print axioms frame_injective
#print axioms externalSign_accept
#print axioms externalSign_reject
#print axioms externalVerify_accept
#print axioms externalVerify_reject
#print axioms externalSign_refines
#print axioms externalVerify_refines

end Framing
end TSModel
