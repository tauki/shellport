import test from 'node:test';
import assert from 'node:assert/strict';
import {decodeBase64URL,encodeBase64URL,registrationOptions,loginOptions,credentialJSON} from '../web/src/passkeys.ts';

test('WebAuthn options decode URL-safe binary and preserve policy',()=>{
  const bytes=Uint8Array.from([0,255,254,253,128,1]).buffer;
  const encoded=encodeBase64URL(bytes);assert.equal(encoded,'AP_-_YAB');assert.deepEqual(decodeBase64URL(encoded),bytes);
  const created=registrationOptions({challenge:encoded,rp:{name:'Shellport',id:'shellport.example.test'},user:{id:encoded,name:'Owner',displayName:'Shellport'},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'},excludeCredentials:[{id:encoded,type:'public-key',transports:['internal']}],extensions:{credProps:true}});
  assert.deepEqual(created.challenge,bytes);assert.deepEqual(created.user.id,bytes);assert.deepEqual(created.excludeCredentials?.[0].id,bytes);assert.equal(created.authenticatorSelection?.userVerification,'required');assert.deepEqual(created.extensions,{credProps:true});
  const requested=loginOptions({challenge:encoded,rpId:'shellport.example.test',userVerification:'required',allowCredentials:[{id:encoded,type:'public-key'}]});assert.deepEqual(requested.challenge,bytes);assert.deepEqual(requested.allowCredentials?.[0].id,bytes);assert.equal(requested.rpId,'shellport.example.test');assert.equal(requested.userVerification,'required');
});

test('WebAuthn responses retain signed bytes, extensions, transports and absent user handle',()=>{
  const bytes=Uint8Array.from([255,1]).buffer;
  const common={id:'_wE',rawId:bytes,type:'public-key',authenticatorAttachment:'platform',getClientExtensionResults:()=>({credProps:{rk:true}})};
  const creation=credentialJSON({...common,response:{clientDataJSON:bytes,attestationObject:bytes,getTransports:()=>['internal']}} as unknown as PublicKeyCredential) as any;
  assert.equal(creation.rawId,'_wE');assert.equal(creation.response.attestationObject,'_wE');assert.deepEqual(creation.response.transports,['internal']);assert.deepEqual(creation.clientExtensionResults,{credProps:{rk:true}});
  const assertion=credentialJSON({...common,response:{clientDataJSON:bytes,authenticatorData:bytes,signature:bytes,userHandle:null}} as unknown as PublicKeyCredential) as any;
  assert.equal(assertion.response.signature,'_wE');assert.equal(assertion.response.authenticatorData,'_wE');assert.equal(assertion.response.userHandle,null);
  const identified=credentialJSON({...common,response:{clientDataJSON:bytes,authenticatorData:bytes,signature:bytes,userHandle:bytes}} as unknown as PublicKeyCredential) as any;assert.equal(identified.response.userHandle,'_wE');
});
