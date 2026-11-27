/-!
A deliberately narrow, explicit source-language semantics. `numberByte` is the
exact JavaScript Number yielded by an ordinary Uint8Array iterator. `bigint`
models only the nonnegative part of JavaScript BigInt, which is closed under
all operations accepted here. In particular, neither operation below is a
JavaScript Number bitwise operation: there is NO Int32/Uint32 truncation and
NO reduction of the shift count modulo 32.

The TypeScript parser/extractor and this fragment's adequacy to ECMAScript are
reviewed trust assumptions, NOT theorems of this module. No claim about Node,
V8, resource exhaustion, monkeypatched iterators/BigInt, detached buffers,
concurrent mutation, or other TypeScript functions follows from this model.
-/
namespace TSBigInt

inductive Value where
  | numberByte (value : BitVec 8)
  | bigint (value : Nat)
  deriving Repr, DecidableEq

inductive Expr where
  | var (name : String)
  | bigintLiteral (value : Nat)
  | toBigInt (argument : Expr)
  | shiftLeft (left right : Expr)
  | bitOr (left right : Expr)
  deriving Repr, DecidableEq

abbrev Env := String → Option Value

def emptyEnv : Env := fun _ => none

def bind (env : Env) (name : String) (value : Value) : Env :=
  fun query => if query = name then some value else env query

/-- Exact, unbounded operations on the accepted nonnegative BigInt fragment. -/
def Expr.eval (env : Env) : Expr → Option Value
  | .var name => env name
  | .bigintLiteral n => some (.bigint n)
  | .toBigInt arg => do
    match ← arg.eval env with
    | .numberByte b => pure (.bigint b.toNat)
    | .bigint n => pure (.bigint n)
  | .shiftLeft left right => do
    let .bigint l ← left.eval env | none
    let .bigint r ← right.eval env | none
    pure (.bigint (l <<< r))
  | .bitOr left right => do
    let .bigint l ← left.eval env | none
    let .bigint r ← right.eval env | none
    pure (.bigint (l ||| r))

def evalBigInt (expr : Expr) (env : Env) : Option Nat := do
  let .bigint n ← expr.eval env | none
  pure n

/-- The complete accepted function-body grammar, not an arithmetic template:
`let accumulator = initial; for (const byte of input) accumulator = step;
return result;`. Every expression is extracted from the source AST. -/
structure Program where
  functionName : String
  inputName : String
  accumulatorName : String
  byteName : String
  initial : Expr
  step : Expr
  result : Expr
  deriving Repr, DecidableEq

def Program.evalStep (p : Program) (acc : Nat) (byte : BitVec 8) : Option Nat :=
  evalBigInt p.step (bind (bind emptyEnv p.accumulatorName (.bigint acc)) p.byteName (.numberByte byte))

def Program.evalLoop (p : Program) : List (BitVec 8) → Nat → Option Nat
  | [], acc => some acc
  | byte :: rest, acc => do
    let next ← p.evalStep acc byte
    p.evalLoop rest next

/-- Structural evaluation of the extracted initialization, loop and return. -/
def Program.denote (p : Program) (bytes : List (BitVec 8)) : Option Nat := do
  let initial ← evalBigInt p.initial emptyEnv
  let final ← p.evalLoop bytes initial
  evalBigInt p.result (bind emptyEnv p.accumulatorName (.bigint final))

/-- No carry overlap: the low eight bits of a shifted natural are zero. -/
theorem shift_or_byte (acc byte : Nat) (bound : byte < 256) :
    (acc <<< 8) ||| byte = 256 * acc + byte := by
  have h : byte < 2 ^ 8 := bound
  rw [← Nat.shiftLeft_add_eq_or_of_lt h acc]
  simp [Nat.shiftLeft_eq, Nat.mul_comm]

end TSBigInt
