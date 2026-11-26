import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PARAMETER_NAMES, PARAMETERS, getParameters, keygen, keygenInternal, sign, signInternal, verify, verifyInternal, type ParameterName } from '../src/index.js';
import { bytes, equalBytes, hex, loadVectors, nameOf, nOf, sets, sigBytesOf, toHex } from './helpers.js';

for (const set of sets) {
  const name=nameOf(set),n=nOf(set),v=loadVectors(set);
  test(`${name}: explicit deterministic API matches ACVP`, () => {
    const c=v.sigGen.find(g=>g.signatureInterface==='external'&&g.deterministic)!.tests[0];
    const msg=hex(c.message),sk=hex(c.sk),ctx=hex(c.context);
    const actual=sign(name,msg,sk,{context:ctx,randomness:'deterministic'});
    equalBytes(actual,hex(c.signature),'deterministic ACVP signature');
    equalBytes(actual,sign(name,msg,sk,{context:ctx,randomness:sk.slice(2*n,3*n)}),'deterministic means PK.seed');
  });
}

test('parameter table independently agrees with FIPS 205 key/signature lengths', () => {
  assert.deepEqual([...PARAMETER_NAMES].sort(),sets.map(nameOf).sort());
  for (const set of sets) {
    const p=getParameters(nameOf(set)),n=nOf(set);
    assert.equal(p.n,n);assert.equal(p.publicKeyBytes,2*n);assert.equal(p.secretKeyBytes,4*n);
    assert.equal(p.signatureBytes,sigBytesOf(set));
    assert.equal(p.h,p.d*p.hp);
    assert.equal(p.m,p.mdBytes+p.treeBytes+p.leafBytes);
    assert.equal(p.signatureBytes,n+p.forsSignatureBytes+p.d*p.xmssSignatureBytes);
    assert.ok(Object.isFrozen(p));
  }
  assert.ok(Object.isFrozen(PARAMETER_NAMES)); assert.ok(Object.isFrozen(PARAMETERS));
});

test('unsupported parameter names are rejected rather than falling back or using inherited properties', () => {
  for (const value of ['', '128f', 'SLH-DSA-SHA2-128F', 'SLH-DSA-SHAKE-512f', '__proto__', 'constructor', 'toString', undefined, null]) {
    const name=value as unknown as ParameterName;
    assert.throws(()=>getParameters(name));assert.throws(()=>keygen(name));
    assert.throws(()=>keygenInternal(name,bytes(16),bytes(16),bytes(16)));
    assert.throws(()=>signInternal(name,bytes(0),bytes(64),bytes(16)));
    assert.throws(()=>sign(name,bytes(0),bytes(64)));
    assert.throws(()=>verifyInternal(name,bytes(0),bytes(0),bytes(32)));
    assert.throws(()=>verify(name,bytes(0),bytes(0),bytes(32)));
  }
});

for (const set of ['sha2-128f','shake-128f']) {
  const name=nameOf(set),v=loadVectors(set);
  const c=v.sigGen.find(g=>g.signatureInterface==='internal'&&!g.deterministic)!.tests[0];
  const msg=hex(c.message),sk=hex(c.sk),pk=hex(c.pk),rand=hex(c.additionalRandomness);
  test(`${name}: default hedged signing, omitted context, explicit empty context`, () => {
    const a=sign(name,msg,sk),b=sign(name,msg,sk);
    assert.notEqual(toHex(a),toHex(b),'independent fresh randomness');
    assert.equal(verify(name,msg,a,pk),true);assert.equal(verify(name,msg,b,pk),true);
    equalBytes(signInternal(name,msg,sk),signInternal(name,msg,sk,sk.slice(2*nOf(set),3*nOf(set))),'internal omitted optRand means PK.seed');
    const d=sign(name,msg,sk,{randomness:'deterministic'});
    equalBytes(d,sign(name,msg,sk,{context:bytes(0),randomness:'deterministic'}),'empty-context default');
  });
  test(`${name}: signing sliced Buffer inputs honors offsets and preserves the backing buffer`, () => {
    const view=(input:Uint8Array)=>Buffer.concat([Buffer.alloc(11,197),Buffer.from(input),Buffer.alloc(9,211)]).subarray(11,11+input.length);
    const a=view(msg),b=view(sk),r=view(rand),saved=[a,b,r].map(x=>toHex(new Uint8Array(x.buffer)));
    equalBytes(signInternal(name,a,b,r),hex(c.signature),'sliced Buffer internal signature');
    assert.deepEqual([a,b,r].map(x=>toHex(new Uint8Array(x.buffer))),saved);
  });
  test(`${name}: non-byte cryptographic inputs are rejected`, () => {
    const bad=[null,undefined,'00',[0,1],new Uint16Array(16),new DataView(new ArrayBuffer(16))];
    for (const value of bad) {
      const input=value as unknown as Uint8Array;
      assert.throws(()=>keygenInternal(name,input,rand,rand));
      assert.throws(()=>signInternal(name,input,sk,rand));
      assert.throws(()=>signInternal(name,msg,input,rand));
      if (value !== undefined) assert.throws(()=>signInternal(name,msg,sk,input));
      assert.equal(verifyInternal(name,input,hex(c.signature),pk),false);
      assert.equal(verifyInternal(name,msg,input,pk),false);
      assert.equal(verifyInternal(name,msg,hex(c.signature),input),false);
      assert.equal(verify(name,input,hex(c.signature),pk),false);
    }
  });
}
