// Simulates 2 users (alice, bob) using the same e2ee.js as the browser.
const E=require('../public/e2ee.js'),WebSocket=require('ws'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const BASE=process.env.BASE||'http://localhost:3000',sfx=Date.now().toString(36);
const ok=(c,m)=>{if(!c)throw new Error('FAIL: '+m);console.log('✔',m)};
async function user(name){const u=name+sfx;const r=await(await fetch(BASE+'/api/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:'secret123'})})).json();
 const kp=await E.genKeyPair();const h={'Content-Type':'application/json',Authorization:'Bearer '+r.token};
 await fetch(BASE+'/api/publickey',{method:'PUT',headers:h,body:JSON.stringify({publicKey:await E.exportPub(kp.publicKey)})});
 const ws=new WebSocket(BASE.replace('http','ws')+'/ws?token='+r.token);await new Promise(x=>ws.on('open',x));return{u,token:r.token,kp,h,ws}}
const next=ws=>new Promise(x=>ws.once('message',d=>x(JSON.parse(d))));
(async()=>{const A=await user('alice'),B=await user('bob');ok(A.token&&B.token,'signup alice & bob');
 const peer=async(me,o)=>E.deriveChatKey(me.kp.privateKey,(await(await fetch(BASE+'/api/users/'+o.u,{headers:me.h})).json()).publicKey);
 const kA=await peer(A,B),kB=await peer(B,A);
 const secret='Namaste Bob, top secret 🔐 '+sfx;const em=await E.encryptJSON(kA,{text:secret});const pB=next(B.ws);
 A.ws.send(JSON.stringify({type:'msg',to:B.u,...em,kind:'text'}));const got=await pB;
 ok((await E.decryptJSON(kB,got.msg.iv,got.msg.ct)).text===secret,'bob received & decrypted text in real time');
 // image
 const img=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==','base64');
 const ef=await E.encryptFile(img);const up=await(await fetch(BASE+'/api/media',{method:'POST',headers:{...A.h,'Content-Type':'application/octet-stream'},body:Buffer.from(ef.ct)})).json();
 ok(up.id,'alice uploaded encrypted image '+up.id);const em2=await E.encryptJSON(kA,{media:{id:up.id,key:ef.key,iv:ef.iv,mime:'image/png',name:'x.png',size:img.length}});
 const pB2=next(B.ws);A.ws.send(JSON.stringify({type:'msg',to:B.u,...em2,kind:'media'}));const g2=await pB2;const meta=(await E.decryptJSON(kB,g2.msg.iv,g2.msg.ct)).media;
 const blob=Buffer.from(await(await fetch(BASE+'/api/media/'+meta.id,{headers:B.h})).arrayBuffer());
 ok(Buffer.from(await E.decryptFile(blob,meta.key,meta.iv)).equals(img),'bob downloaded & decrypted image (bytes identical)');
 // server-side ciphertext checks
 await new Promise(x=>setTimeout(x,400));const raw=fs.readFileSync(path.join(__dirname,'../data/db.json'),'utf8');
 ok(!raw.includes(secret)&&!raw.includes('top secret'),'db.json does not contain plaintext');ok(!raw.includes(ef.key),'db.json does not contain media key');
 const stored=fs.readFileSync(path.join(__dirname,'../data/media',up.id+'.bin'));ok(!stored.equals(img)&&stored.indexOf(img.subarray(0,8))<0,'stored media file is ciphertext (no PNG header)');
 const msgs=await(await fetch(BASE+'/api/messages/'+A.u,{headers:B.h})).json();ok(msgs.length===2&&msgs.every(m=>!('text'in m)),'history has 2 ciphertext-only messages');
 const C=await user('eve');const kE=await peer(C,A);let fail=false;try{await E.decryptJSON(kE,got.msg.iv,got.msg.ct)}catch{fail=true}ok(fail,'third user (eve) cannot decrypt alice→bob message');
 console.log('\nALL TESTS PASSED');process.exit(0)})().catch(e=>{console.error(e);process.exit(1)});
