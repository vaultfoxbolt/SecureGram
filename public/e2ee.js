// Shared E2EE helpers (browser + Node 20 WebCrypto)
(function(root){
const subtle=(globalThis.crypto).subtle,enc=new TextEncoder(),dec=new TextDecoder();
const b64=buf=>{const b=new Uint8Array(buf);let s='';for(let i=0;i<b.length;i+=0x8000)s+=String.fromCharCode.apply(null,b.subarray(i,i+0x8000));return btoa(s)};
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const E={b64,unb64,
 genKeyPair:()=>subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveKey','deriveBits']),
 exportPub:k=>subtle.exportKey('jwk',k),
 importPub:jwk=>subtle.importKey('jwk',{kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y,ext:true},{name:'ECDH',namedCurve:'P-256'},true,[]),
 async deriveChatKey(priv,peerJwk){const bits=await subtle.deriveBits({name:'ECDH',public:await E.importPub(peerJwk)},priv,256);
  const hk=await subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);
  return subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:enc.encode('tg-e2ee-v1'),info:enc.encode('chat-key')},hk,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])},
 async encryptJSON(key,obj){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(obj)));return{iv:b64(iv),ct:b64(ct)}},
 async decryptJSON(key,iv,ct){return JSON.parse(dec.decode(await subtle.decrypt({name:'AES-GCM',iv:unb64(iv)},key,unb64(ct))))},
 async encryptFile(buf){const k=await subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await subtle.encrypt({name:'AES-GCM',iv},k,buf);return{ct,key:b64(await subtle.exportKey('raw',k)),iv:b64(iv)}},
 async decryptFile(buf,key,iv){const k=await subtle.importKey('raw',unb64(key),'AES-GCM',false,['decrypt']);return subtle.decrypt({name:'AES-GCM',iv:unb64(iv)},k,buf)}
};
if(typeof module!=='undefined')module.exports=E;else root.E2EE=E;
})(this);
