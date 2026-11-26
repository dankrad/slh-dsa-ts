/** Optional live cross-language check; fixture-based coverage also runs in npm test. */
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { keygenInternal, signInternal, sign, type ParameterName } from '../src/index.js';
import { equalBytes, hex, toHex } from '../test/helpers.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const fixtures = JSON.parse(readFileSync(new URL('../vectors/rust-differential.json',import.meta.url),'utf8'));
assert.equal(execFileSync('git',['-C',join(root,'../reference'),'rev-parse','HEAD'],{encoding:'utf8'}).trim(),fixtures.commit,'Rust reference pin');
assert.equal(execFileSync('git',['-C',join(root,'../reference'),'status','--porcelain','--untracked-files=no'],{encoding:'utf8'}).trim(),'','Rust reference must be unmodified');
const cases=fixtures.cases.map((c:Record<string,string>) => {
  const name=c.name as ParameterName;
  const keys=keygenInternal(name,hex(c.skSeed),hex(c.skPrf),hex(c.pkSeed));
  equalBytes(keys.secretKey,hex(c.secretKey),'Rust secret key'); equalBytes(keys.publicKey,hex(c.publicKey),'Rust public key');
  const message=hex(c.message),context=hex(c.context),randomness=hex(c.randomness);
  const internal=signInternal(name,message,keys.secretKey,randomness);
  const external=sign(name,message,keys.secretKey,{context,randomness});
  equalBytes(internal,hex(c.internalSignature),'Rust internal signature');
  equalBytes(external,hex(c.externalSignature),'Rust external signature');
  return {...c, publicKey:toHex(keys.publicKey), internalSignature:toHex(internal),externalSignature:toHex(external)};
});
const directory=mkdtempSync(join(tmpdir(),'slh-dsa-ts-rust-'));
try {
  const path=join(directory,'typescript-signatures.json'); writeFileSync(path,JSON.stringify({cases}));
  const result=execFileSync('cargo',['run','--locked','--release','--manifest-path',join(root,'scripts/rust-fixtures/Cargo.toml'),'--','verify',path],{cwd:root,encoding:'utf8',stdio:['ignore','pipe','inherit']});
  process.stdout.write(result);
} finally {rmSync(directory,{recursive:true,force:true});}
