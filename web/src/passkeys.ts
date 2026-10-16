type EncodedDescriptor=Omit<PublicKeyCredentialDescriptor,'id'> & {id:string};
export type CreationJSON=Omit<PublicKeyCredentialCreationOptions,'challenge'|'user'|'excludeCredentials'> & {challenge:string;user:Omit<PublicKeyCredentialUserEntity,'id'> & {id:string};excludeCredentials?:EncodedDescriptor[]};
export type RequestJSON=Omit<PublicKeyCredentialRequestOptions,'challenge'|'allowCredentials'> & {challenge:string;allowCredentials?:EncodedDescriptor[]};
export type PasskeyLoginOptions={needsPassword?:boolean;options?:{publicKey:RequestJSON};expiresAt?:string};
export type PasskeyRegistrationOptions={options:{publicKey:CreationJSON};expiresAt:string};
export type PasskeyRecord={id:string;name:string;address:string;createdAt:string;lastUsedAt?:string;availableHere:boolean};
export type PasskeyDirectory={passkeys:PasskeyRecord[];address:string;canAdd:boolean};

export function decodeBase64URL(value:string):ArrayBuffer {
  const binary=atob(value.replace(/-/g,'+').replace(/_/g,'/'));
  const bytes=new Uint8Array(binary.length);for(let i=0;i<binary.length;i++) bytes[i]=binary.charCodeAt(i);
  return bytes.buffer;
}
export function encodeBase64URL(buffer:ArrayBuffer):string {
  let binary='';for(const byte of new Uint8Array(buffer)) binary+=String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
export function registrationOptions(options:CreationJSON):PublicKeyCredentialCreationOptions {
  return {...options,challenge:decodeBase64URL(options.challenge),user:{...options.user,id:decodeBase64URL(options.user.id)},excludeCredentials:options.excludeCredentials?.map(item=>({...item,id:decodeBase64URL(item.id)}))};
}
export function loginOptions(options:RequestJSON):PublicKeyCredentialRequestOptions {
  return {...options,challenge:decodeBase64URL(options.challenge),allowCredentials:options.allowCredentials?.map(item=>({...item,id:decodeBase64URL(item.id)}))};
}
export function credentialJSON(credential:PublicKeyCredential):unknown {
  const response=credential.response;
  const common={id:credential.id,rawId:encodeBase64URL(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults()};
  if ('attestationObject' in response) {
    const creation=response as AuthenticatorAttestationResponse;
    return {...common,response:{clientDataJSON:encodeBase64URL(creation.clientDataJSON),attestationObject:encodeBase64URL(creation.attestationObject),transports:creation.getTransports?.() || []}};
  }
  const assertion=response as AuthenticatorAssertionResponse;
  return {...common,response:{clientDataJSON:encodeBase64URL(assertion.clientDataJSON),authenticatorData:encodeBase64URL(assertion.authenticatorData),signature:encodeBase64URL(assertion.signature),userHandle:assertion.userHandle ? encodeBase64URL(assertion.userHandle) : null}};
}
export function canUsePasskeys():boolean {
  return !!globalThis.isSecureContext && typeof PublicKeyCredential!=='undefined' && !!navigator.credentials?.create && !!navigator.credentials?.get;
}
