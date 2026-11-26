import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { keygenInternal, signInternal, verifyInternal, sign, verify } from '../src/index.js';
import { equalBytes, hex, mutate, nameOf } from './helpers.js';

type Fixture = Record<string,string>;
const fixtures = JSON.parse(readFileSync(new URL('../vectors/rust-differential.json',import.meta.url),'utf8')) as { commit:string; cases: Fixture[] };
export function registerRustDifferential(set: string) {
  const name = nameOf(set);
  const c = fixtures.cases.find(c=>c.name===name)!;
  assert.equal(fixtures.commit,'462724e2b5f8ffe63a2ce76c9b1ab07099c1807b');
  assert.ok(c,`missing Rust fixture ${name}`);
  test(`${name}: differential keypair equals pinned Rust`, () => {
    const keys=keygenInternal(name,hex(c.skSeed),hex(c.skPrf),hex(c.pkSeed));
    equalBytes(keys.secretKey,hex(c.secretKey),'Rust secret key');
    equalBytes(keys.publicKey,hex(c.publicKey),'Rust public key');
  });
  test(`${name}: internal signature equals pinned Rust and verifies`, () => {
    const msg=hex(c.message),sk=hex(c.secretKey),pk=hex(c.publicKey),rand=hex(c.randomness);
    const sig=signInternal(name,msg,sk,rand);
    equalBytes(sig,hex(c.internalSignature),'Rust internal signature');
    assert.equal(verifyInternal(name,msg,hex(c.internalSignature),pk),true,'TS verifies Rust');
    assert.equal(verifyInternal(name,msg,mutate(sig),pk),false);
  });
  test(`${name}: external signature equals pinned Rust and verifies`, () => {
    const msg=hex(c.message),ctx=hex(c.context),sk=hex(c.secretKey),pk=hex(c.publicKey),rand=hex(c.randomness);
    const sig=sign(name,msg,sk,{context:ctx,randomness:rand});
    equalBytes(sig,hex(c.externalSignature),'Rust external signature');
    assert.equal(verify(name,msg,hex(c.externalSignature),pk,ctx),true,'TS verifies Rust');
    assert.equal(verify(name,msg,mutate(sig),pk,ctx),false);
  });
}
