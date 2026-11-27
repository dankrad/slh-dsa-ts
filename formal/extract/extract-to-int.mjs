#!/usr/bin/env node
/** Trusted, fail-closed structural frontend; see README.md. No semantic hashes. */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(import.meta.url);
let ts;
try { ts = require('typescript'); }
catch { throw new Error('Install repository dependencies with npm ci --ignore-scripts (or set NODE_PATH to a compatible TypeScript installation)'); }
const fail = message => { throw new Error(`Extraction rejected: ${message}`); };
const assert = (condition, message) => { if (!condition) fail(message); };
const ident = (node, label) => { assert(node && ts.isIdentifier(node), `${label} must be identifier`); return node.text; };
const no = (items, label) => assert(!items || items.length === 0, `${label} unsupported`);
function extract(sourceText, sourcePath) {
  const sf = ts.createSourceFile(sourcePath, sourceText, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  assert(sf.parseDiagnostics.length === 0, 'TypeScript parse diagnostics');
  // Conservative whole-file binding check: the call below must name the
  // ambient BigInt builtin, not a lexical/import binding. This is NOT an
  // effect analysis: pristine builtin/iterator behavior is still trusted.
  function bindingNames(name) {
    if (!name) return [];
    if (ts.isIdentifier(name)) return [name.text];
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name))
      return name.elements.flatMap(e => ts.isBindingElement(e) ? bindingNames(e.name) : []);
    return [];
  }
  function checkBindings(node) {
    if (ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isBindingElement(node) ||
        ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) ||
        ts.isClassDeclaration(node) || ts.isClassExpression(node) ||
        ts.isImportClause(node) || ts.isImportSpecifier(node) ||
        ts.isNamespaceImport(node) || ts.isImportEqualsDeclaration(node) ||
        ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node))
      assert(!bindingNames(node.name).includes('BigInt'), 'lexical/import binding shadows BigInt');
    ts.forEachChild(node, checkBindings);
  }
  checkBindings(sf);
  const candidates = sf.statements.filter(s => s.name && ts.isIdentifier(s.name) && s.name.text === 'toInt');
  assert(candidates.length === 1 && ts.isFunctionDeclaration(candidates[0]), 'need exactly one top-level function toInt');
  const fn = candidates[0];
  no(fn.modifiers, 'function modifiers'); no(fn.typeParameters, 'type parameters');
  assert(!fn.asteriskToken && fn.body && fn.parameters.length === 1, 'expected non-generator function with one parameter and body');
  const param = fn.parameters[0];
  no(param.modifiers, 'parameter modifiers');
  assert(!param.initializer && !param.dotDotDotToken && !param.questionToken, 'parameter default/optional/rest unsupported');
  const inputName = ident(param.name, 'parameter');
  assert(param.type && ts.isTypeReferenceNode(param.type) && ts.isIdentifier(param.type.typeName) && param.type.typeName.text === 'Uint8Array' && !param.type.typeArguments, 'parameter must be Uint8Array');
  assert(fn.type && fn.type.kind === ts.SyntaxKind.BigIntKeyword, 'return type must be bigint');
  const stmts = fn.body.statements;
  assert(stmts.length === 3, 'body must have initialization, for-of, return only');
  const init = stmts[0];
  assert(ts.isVariableStatement(init), 'expected accumulator declaration'); no(init.modifiers, 'declaration modifiers');
  assert(init.declarationList.flags === ts.NodeFlags.Let && init.declarationList.declarations.length === 1, 'expected one let accumulator');
  const declaration = init.declarationList.declarations[0];
  assert(!declaration.type && !declaration.exclamationToken && declaration.initializer, 'accumulator initializer required, annotations unsupported');
  const accumulatorName = ident(declaration.name, 'accumulator');
  const loop = stmts[1];
  assert(ts.isForOfStatement(loop) && !loop.awaitModifier, 'expected synchronous for-of');
  assert(ident(loop.expression, 'iterable') === inputName, 'loop must iterate function input');
  assert(ts.isVariableDeclarationList(loop.initializer) && loop.initializer.flags === ts.NodeFlags.Const && loop.initializer.declarations.length === 1, 'expected one const byte binder');
  const byteDecl = loop.initializer.declarations[0];
  assert(!byteDecl.type && !byteDecl.initializer && !byteDecl.exclamationToken, 'byte declaration annotation/initializer unsupported');
  const byteName = ident(byteDecl.name, 'byte');
  assert(new Set([inputName, accumulatorName, byteName, 'BigInt']).size === 4, 'bindings must be distinct and not shadow BigInt');
  // No block is silently flattened: this frontend accepts precisely this grammar.
  assert(ts.isExpressionStatement(loop.statement), 'loop body must be a single assignment expression statement');
  const assignment = loop.statement.expression;
  assert(ts.isBinaryExpression(assignment) && assignment.operatorToken.kind === ts.SyntaxKind.EqualsToken && ident(assignment.left, 'assignment target') === accumulatorName, 'loop must assign accumulator');
  const ret = stmts[2];
  assert(ts.isReturnStatement(ret) && ret.expression, 'return expression required');
  function expr(node, inLoop) {
    if (ts.isParenthesizedExpression(node)) return expr(node.expression, inLoop);
    if (ts.isIdentifier(node)) {
      assert(node.text === accumulatorName || (inLoop && node.text === byteName), `unbound identifier ${node.text}`);
      return { kind: 'var', name: node.text };
    }
    if (ts.isBigIntLiteral(node)) {
      // Decimal nonnegative literals only; reject separators, alternate bases, unary minus.
      const raw = node.getText(sf); assert(/^(0|[1-9][0-9]*)n$/.test(raw), 'only decimal nonnegative BigInt literals');
      return { kind: 'bigintLiteral', value: raw.slice(0, -1) };
    }
    if (ts.isCallExpression(node)) {
      assert(ts.isIdentifier(node.expression) && node.expression.text === 'BigInt' && node.arguments.length === 1 && !node.typeArguments && !node.questionDotToken, 'only BigInt(singleArgument) calls accepted');
      return { kind: 'toBigInt', argument: expr(node.arguments[0], inLoop) };
    }
    if (ts.isBinaryExpression(node)) {
      const kind = new Map([[ts.SyntaxKind.LessThanLessThanToken, 'shiftLeft'], [ts.SyntaxKind.BarToken, 'bitOr']]).get(node.operatorToken.kind);
      assert(kind, `unsupported operator ${node.operatorToken.getText(sf)}`);
      return { kind, left: expr(node.left, inLoop), right: expr(node.right, inLoop) };
    }
    fail(`unsupported expression ${ts.SyntaxKind[node.kind]}`);
  }
  const initial = expr(declaration.initializer, false);
  assert(initial.kind === 'bigintLiteral', 'initial value must be closed BigInt literal');
  return {
    program: { functionName: 'toInt', inputName, accumulatorName, byteName, initial, step: expr(assignment.right, true), result: expr(ret.expression, false) },
    location: { start: fn.getStart(sf), end: fn.end, startLine: sf.getLineAndCharacterOfPosition(fn.getStart(sf)).line + 1, endLine: sf.getLineAndCharacterOfPosition(fn.end).line + 1 },
    sourceSlice: sourceText.slice(fn.getStart(sf), fn.end),
  };
}
const str = x => JSON.stringify(x);
function leanExpr(e) {
  switch (e.kind) {
    case 'var': return `(.var ${str(e.name)})`;
    case 'bigintLiteral': return `(.bigintLiteral ${e.value})`;
    case 'toBigInt': return `(.toBigInt ${leanExpr(e.argument)})`;
    case 'shiftLeft': case 'bitOr': return `(.${e.kind} ${leanExpr(e.left)} ${leanExpr(e.right)})`;
    default: fail(`internal unknown IR kind ${e.kind}`);
  }
}
function outputs(sourceText, sourcePath) {
  const r = extract(sourceText, sourcePath), p = r.program;
  const lean = `-- GENERATED by formal/extract/extract-to-int.mjs; do not edit.\n-- This is structural source extraction, not a proof of frontend correctness.\nimport Generated.BigIntSubset\n\nnamespace TSExtracted\n\ndef toIntProgram : TSBigInt.Program := {\n  functionName := ${str(p.functionName)}\n  inputName := ${str(p.inputName)}\n  accumulatorName := ${str(p.accumulatorName)}\n  byteName := ${str(p.byteName)}\n  initial := ${leanExpr(p.initial)}\n  step := ${leanExpr(p.step)}\n  result := ${leanExpr(p.result)}\n}\n\nend TSExtracted\n`;
  const manifest = JSON.stringify({schemaVersion:2, typescriptVersion:ts.version, upstreamSpecification:{repository:'danrobinson/rust-pq',commit:'462724e2b5f8ffe63a2ce76c9b1ab07099c1807b',file:'formal/Spec/SlhDsa.lean',sha256:createHash('sha256').update(fs.readFileSync(path.join(root,'formal/Spec/SlhDsa.lean'))).digest('hex')}, extractorSha256:createHash('sha256').update(fs.readFileSync(fileURLToPath(import.meta.url))).digest('hex'), functionSourceSha256:createHash('sha256').update(r.sourceSlice).digest('hex'), source:'src/index.ts', ...r.location, functionSource:r.sourceSlice, program:p, sourceSha256:createHash('sha256').update(sourceText).digest('hex'), trust:'Parser/extractor and ECMAScript adequacy are unproved; hash is provenance/freshness only.'}, null, 2) + '\n';
  return { lean, manifest };
}
assert(process.argv.slice(2).every(x => x === '--check' || x === '--self-test'), 'only --check or --self-test accepted');
assert(!(process.argv.includes('--check') && process.argv.includes('--self-test')), 'choose --check or --self-test, not both');
if (process.argv.includes('--self-test')) {
  const source = fs.readFileSync(path.join(root, 'src/index.ts'), 'utf8');
  const base = outputs(source, 'src/index.ts');
  const mutations = [
    ['literal', 'value << 8n', 'value << 7n', 'change'],
    ['operator', '(value << 8n) | BigInt(byte)', '(value << 8n) & BigInt(byte)', 'reject'],
    ['accepted operator change', '(value << 8n) | BigInt(byte)', '(value << 8n) << BigInt(byte)', 'change'],
    ['nested literal', 'BigInt(byte)', '(BigInt(byte) | 1n)', 'change'],
    ['negative literal', 'value << 8n', 'value << -8n', 'reject'],
    ['number initial', 'let value = 0n;', 'let value = 0;', 'reject'],
    ['self initial', 'let value = 0n;', 'let value = value;', 'reject'],
    ['wrong assignment', 'value = (value << 8n)', 'byte = (value << 8n)', 'reject'],
    ['compound assignment', 'value = (value << 8n)', 'value |= (value << 8n)', 'reject'],
    ['extra loop call', 'BigInt(byte);', 'BigInt(byte), sideEffect();', 'reject'],
    ['for await', 'for (const byte of bytes)', 'for await (const byte of bytes)', 'reject'],
    ['initial', 'let value = 0n;', 'let value = 1n;', 'change'],
    ['binding', 'BigInt(byte)', 'BigInt(value)', 'change'],
    ['return', 'return value;\n}', 'return 0n;\n}', 'change'],
    ['extra statement', 'let value = 0n;', 'let value = 0n; value = 2n;', 'reject'],
    ['numeric shift', 'value << 8n', 'value << 8', 'reject'],
    ['module BigInt binding', 'function toInt(bytes:', 'const BigInt = (x: unknown) => 0n;\nfunction toInt(bytes:', 'reject'],
    ['import BigInt binding', 'function toInt(bytes:', 'import { fake as BigInt } from "fake";\nfunction toInt(bytes:', 'reject'],
    ['destructured BigInt binding', 'function toInt(bytes:', 'const { builtin: BigInt } = whatever;\nfunction toInt(bytes:', 'reject'],
    ['shadowed BigInt', 'const byte of bytes', 'const BigInt of bytes', 'reject'],
    ['input iterable', 'const byte of bytes', 'const byte of other', 'reject'],
    ['missing bigint type', 'function toInt(bytes: Uint8Array): bigint', 'function toInt(bytes: Uint8Array): number', 'reject'],
    ['duplicate', '\nclass Address {', '\nfunction toInt(bytes: Uint8Array): bigint { return 0n; }\nclass Address {', 'reject'],
    ['loop block', 'for (const byte of bytes) value = (value << 8n) | BigInt(byte);', 'for (const byte of bytes) { value = (value << 8n) | BigInt(byte); }', 'reject'],
  ];
  for (const [label, from, to, expected] of mutations) {
    assert(source.includes(from), `self-test fixture absent: ${label}`);
    let changed;
    try { changed = outputs(source.replace(from, to), 'mutated.ts'); }
    catch (e) { if (expected === 'reject' && String(e.message).startsWith('Extraction rejected:')) continue; throw e; }
    assert(expected === 'change' && changed.lean !== base.lean, `mutation ${label} silently accepted without changed semantic term`);
  }
  console.log(`Extraction mutation tests passed: ${mutations.length}`);
} else {
  assert(process.argv.slice(2).every(x => x === '--check'), 'only --check or --self-test accepted');
  const out = outputs(fs.readFileSync(path.join(root, 'src/index.ts'), 'utf8'), 'src/index.ts');
  const targets = [[path.join(root, 'formal/Generated/ToInt.lean'),out.lean],[path.join(root, 'formal/Generated/to-int.manifest.json'),out.manifest]];
  for (const [file, value] of targets) {
    if (process.argv.includes('--check')) assert(fs.existsSync(file) && fs.readFileSync(file,'utf8') === value, `${path.relative(root,file)} stale; regenerate`);
    else { fs.mkdirSync(path.dirname(file), {recursive:true}); fs.writeFileSync(file,value); }
  }
  console.log(process.argv.includes('--check') ? 'Extracted toInt AST is fresh' : 'Extracted toInt AST generated');
}
