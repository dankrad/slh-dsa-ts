import assert from 'node:assert/strict';
import { test } from 'node:test';
import { keygen, keygenInternal, sign, signInternal, verify, verifyInternal } from '../src/index.js';
import { bytes, concat, equalBytes, hex, loadVectors, mutate, nameOf, nOf, sets, sigBytesOf, toHex } from './helpers.js';

for (const set of sets) {
  const name = nameOf(set), n = nOf(set), v = loadVectors(set);
  const external = v.sigGen.find(g => g.signatureInterface === 'external')!.tests[0];
  const internal = v.sigGen.find(g => g.signatureInterface === 'internal')!.tests[0];
  const msg = hex(external.message), ctx = hex(external.context), sk = hex(external.sk);
  const pk = hex(external.pk), sig = hex(external.signature);
  test(`${name}: reject message/context/key/signature tampering and domain confusion`, () => {
    assert.equal(verify(name, msg, sig, pk, ctx), true);
    const positions = [...new Set([0, n-1, n, 2*n, Math.floor(sig.length/2), sig.length-n, sig.length-1])];
    for (const at of positions) assert.equal(verify(name,msg,mutate(sig,at),pk,ctx),false,`signature bit ${at}`);
    for (const at of [0,n,pk.length-1]) assert.equal(verify(name,msg,sig,mutate(pk,at),ctx),false,`public-key bit ${at}`);
    assert.equal(verify(name,concat(msg,bytes(1)),sig,pk,ctx),false,'changed message');
    assert.equal(verify(name,msg,sig,pk,concat(ctx,bytes(1))),false,'changed context');
    assert.equal(verifyInternal(name,msg,sig,pk),false,'external cannot be treated as internal');
    assert.equal(verify(name,hex(internal.message),hex(internal.signature),hex(internal.pk)),false,'internal cannot be treated as external');
    const otherFamily = set.startsWith('sha2') ? set.replace('sha2','shake') : set.replace('shake','sha2');
    assert.equal(verify(nameOf(otherFamily),msg,sig,pk,ctx),false,'same-sized different-family set');
  });
  test(`${name}: verification rejects malformed lengths without throwing`, () => {
    for (const length of [0,1,n-1,n,sig.length-1,sig.length+1]) {
      const wrong = new Uint8Array(length); wrong.set(sig.subarray(0,length));
      assert.equal(verify(name,msg,wrong,pk,ctx),false,`signature length ${length}`);
      assert.equal(verifyInternal(name,msg,wrong,pk),false,`internal signature length ${length}`);
    }
    for (const length of [0,1,pk.length-1,pk.length+1]) {
      const wrong = new Uint8Array(length); wrong.set(pk.subarray(0,length));
      assert.equal(verify(name,msg,sig,wrong,ctx),false,`public key length ${length}`);
      assert.equal(verifyInternal(name,msg,sig,wrong),false,`internal public key length ${length}`);
    }
    assert.equal(verify(name,msg,sig,pk,bytes(256)),false,'context exceeds one byte');
  });
  test(`${name}: keygen/sign reject invalid lengths`, () => {
    for (const length of [0,n-1,n+1]) {
      for (let i=0;i<3;i++) {
        const seeds = [bytes(n),bytes(n),bytes(n)]; seeds[i]=bytes(length);
        assert.throws(() => keygenInternal(name,seeds[0],seeds[1],seeds[2]),`seed ${i}, length ${length}`);
      }
      assert.throws(() => signInternal(name,msg,sk,bytes(length)),`internal randomness ${length}`);
      assert.throws(() => sign(name,msg,sk,{randomness:bytes(length)}),`external randomness ${length}`);
    }
    for (const length of [0,sk.length-1,sk.length+1]) {
      assert.throws(() => signInternal(name,msg,bytes(length),bytes(n)),`secret key ${length}`);
      assert.throws(() => sign(name,msg,bytes(length),{randomness:bytes(n)}),`external secret key ${length}`);
    }
    assert.throws(() => sign(name,msg,sk,{context:bytes(256),randomness:bytes(n)}),'sign rejects oversized context');
  });
  test(`${name}: Buffer and Uint8Array views honor byte offsets`, () => {
    const view = (a:Uint8Array) => Buffer.concat([Buffer.alloc(13,0xff),Buffer.from(a),Buffer.alloc(7,0xff)]).subarray(13,13+a.length);
    assert.equal(verify(name,view(msg),view(sig),view(pk),view(ctx)),true);
    assert.equal(verifyInternal(name,view(hex(internal.message)),view(hex(internal.signature)),view(hex(internal.pk))),true);
  });
}

for (const set of ['sha2-128f','shake-128f']) {
  const name = nameOf(set), n=nOf(set);
  const c = loadVectors(set).keyGen[0].tests[0], sk=hex(c.sk), pk=hex(c.pk);
  for (const length of [0,1,55,56,63,64,111,112,127,128,135,136,137,255,256,1025,1048576]) {
    test(`${name}: external round trip message length ${length}, context ${length%2 ? 255 : 0}`, () => {
      const message=bytes(length,17), context=bytes(length%2 ? 255 : 0,23), randomness=bytes(n,29);
      const inputDigests=[message,context,sk,randomness].map(toHex);
      const signature=sign(name,message,sk,{context,randomness});
      assert.equal(signature.length,sigBytesOf(set));
      assert.equal(verify(name,message,signature,pk,context),true);
      equalBytes(signature,signInternal(name,concat(bytes(1,0),bytes(1,context.length),context,message),sk,randomness),'external prefix = 00 || ctx.length || ctx || message');
      assert.deepEqual([message,context,sk,randomness].map(toHex),inputDigests,'inputs unchanged');
      if (context.length===0) assert.equal(verify(name,message,signature,pk),true,'omitted context means empty');
    });
  }
  test(`${name}: external random key generation and supplied randomness`, () => {
    const first=keygen(name), second=keygen(name);
    assert.equal(first.publicKey.length,2*n); assert.equal(first.secretKey.length,4*n);
    assert.notEqual(toHex(first.secretKey),toHex(second.secretKey));
    equalBytes(first.secretKey.subarray(2*n),first.publicKey,'generated keypair consistency');
    const msg=bytes(73,37), context=bytes(255,19), randomness=bytes(n,91);
    const a=sign(name,msg,first.secretKey,{context,randomness});
    equalBytes(a,sign(name,msg,first.secretKey,{context,randomness}),'fixed randomness reproducible');
    const b=sign(name,msg,first.secretKey,{context,randomness:mutate(randomness)});
    assert.notEqual(toHex(a),toHex(b),'different randomness changes signature');
    assert.equal(verify(name,msg,a,first.publicKey,context),true);
    assert.equal(verify(name,msg,b,first.publicKey,context),true);
    assert.equal(verify(name,msg,a,second.publicKey,context),false);
  });
}
