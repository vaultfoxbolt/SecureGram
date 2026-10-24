const $=id=>document.getElementById(id);let S={token:localStorage.token,me:localStorage.me,priv:null,chats:[],peer:null,keys:{},ws:null};
const api=async(p,o={})=>{const r=await fetch(p,{...o,headers:{'Content-Type':'application/json',Authorization:'Bearer '+S.token,...(o.headers||{})}});const j=r.headers.get('content-type')?.includes('json')?await r.json():r;if(!r.ok)throw new Error(j.error||r.status);return j};
const esc=s=>s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const color=u=>`hsl(${[...u].reduce((a,c)=>a+c.charCodeAt(0),0)*47%360},55%,50%)`;
const fmt=ts=>new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
// IndexedDB: private key stays in this browser (non-extractable CryptoKey)
const idb=()=>new Promise((res,rej)=>{const r=indexedDB.open('securegram',1);r.onupgradeneeded=()=>r.result.createObjectStore('keys');r.onsuccess=()=>res(r.result);r.onerror=rej});
const idbGet=async k=>{const d=await idb();return new Promise(r=>{const q=d.transaction('keys').objectStore('keys').get(k);q.onsuccess=()=>r(q.result)})};
const idbPut=async(k,v)=>{const d=await idb();return new Promise(r=>{const t=d.transaction('keys','readwrite');t.objectStore('keys').put(v,k);t.oncomplete=r})};
async function ensureKeys(){let kp=await idbGet('kp:'+S.me);if(!kp){kp=await E2EE.genKeyPair();await idbPut('kp:'+S.me,kp)}
 S.priv=kp.privateKey;await api('/api/publickey',{method:'PUT',body:JSON.stringify({publicKey:await E2EE.exportPub(kp.publicKey)})})}
async function chatKey(u){if(S.keys[u])return S.keys[u];const{publicKey}=await api('/api/users/'+u);if(!publicKey)throw new Error(u+' has no key yet (never logged in)');
 return S.keys[u]=await E2EE.deriveChatKey(S.priv,publicKey)}
async function doAuth(kind){$('aerr').textContent='';try{const r=await fetch('/api/'+kind,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('au').value.trim(),password:$('ap').value})});
 const j=await r.json();if(!r.ok)throw new Error(j.error);localStorage.token=S.token=j.token;localStorage.me=S.me=j.username;await start()}catch(e){$('aerr').textContent=e.message}}
$('loginBtn').onclick=()=>doAuth('login');$('signupBtn').onclick=()=>doAuth('signup');$('ap').onkeydown=e=>e.key==='Enter'&&doAuth('login');
$('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST'})}catch{}localStorage.clear();location.reload()};
async function start(){try{await ensureKeys()}catch(e){localStorage.clear();$('auth').classList.remove('hidden');return}
 $('auth').classList.add('hidden');$('app').classList.remove('hidden');$('me').textContent='@'+S.me;connect();loadChats()}
function connect(){const ws=S.ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws?token='+S.token);
 ws.onmessage=async e=>{const d=JSON.parse(e.data);if(d.type!=='msg')return;const m=d.msg,o=m.from===S.me?m.to:m.from;if(o===S.peer)await renderMsg(m,true);loadChats()};
 ws.onclose=()=>setTimeout(connect,2000)}
async function preview(c){if(!c.last)return'No messages yet';try{const p=await E2EE.decryptJSON(await chatKey(c.username),c.last.iv,c.last.ct);return p.text||(p.media?.mime.startsWith('video')?'🎬 Video':'🖼 Photo')}catch{return'🔒 Encrypted message'}}
async function loadChats(){S.chats=await api('/api/chats');const ul=$('chats');const items=await Promise.all(S.chats.map(async c=>`<li data-u="${c.username}" class="${c.username===S.peer?'active':''}"><div class="av" style="background:${color(c.username)}">${c.username[0].toUpperCase()}</div><div class="ci"><div class="row"><b>${c.username}</b><small>${c.last?fmt(c.last.ts):''}</small></div><div class="prev">${esc(await preview(c))}</div></div></li>`));
 ul.innerHTML=items.join('');ul.querySelectorAll('li').forEach(li=>li.onclick=()=>openChat(li.dataset.u))}
$('addBtn').onclick=async()=>{const u=$('newu').value.trim().toLowerCase();if(!u)return;try{await api('/api/contacts',{method:'POST',body:JSON.stringify({username:u})});$('newu').value='';await loadChats();openChat(u)}catch(e){alert(e.message)}};
$('newu').onkeydown=e=>e.key==='Enter'&&$('addBtn').onclick();
$('back').onclick=()=>{$('app').classList.remove('inchat');S.peer=null};
let lastDay;async function openChat(u){S.peer=u;lastDay=null;$('app').classList.add('inchat');$('empty').classList.add('hidden');$('chat').classList.remove('hidden');$('peer').textContent=u;
 document.querySelectorAll('#chats li').forEach(li=>li.classList.toggle('active',li.dataset.u===u));$('msgs').innerHTML='';
 for(const m of await api('/api/messages/'+u))await renderMsg(m,false);$('msgs').scrollTop=1e9}
async function renderMsg(m,scroll){const box=$('msgs'),day=new Date(m.ts).toDateString();if(day!==lastDay){lastDay=day;box.insertAdjacentHTML('beforeend',`<div class="day">${day}</div>`)}
 const el=document.createElement('div');el.className='b'+(m.from===S.me?' mine':'');box.appendChild(el);let p;
 try{p=await E2EE.decryptJSON(await chatKey(m.from===S.me?m.to:m.from),m.iv,m.ct)}catch{el.innerHTML=`<i>🔒 Cannot decrypt (key changed / other device)</i><span class="t">${fmt(m.ts)}</span>`;return}
 if(p.media){el.innerHTML='<i>Decrypting media…</i>';try{const r=await api('/api/media/'+p.media.id);const plain=await E2EE.decryptFile(await r.arrayBuffer(),p.media.key,p.media.iv);
  const url=URL.createObjectURL(new Blob([plain],{type:p.media.mime}));const v=p.media.mime.startsWith('video');
  el.innerHTML=(v?`<video src="${url}" controls playsinline></video>`:`<img src="${url}">`)+(p.text?`<div>${esc(p.text)}</div>`:'');
  if(!v)el.querySelector('img').onclick=()=>{$('viewer').innerHTML=`<img src="${url}">`;$('viewer').classList.remove('hidden')};if(scroll)box.scrollTop=1e9}catch{el.innerHTML='<i>Media unavailable</i>'}}
 else el.innerHTML=esc(p.text||'');el.insertAdjacentHTML('beforeend',`<span class="t">${fmt(m.ts)}</span>`);if(scroll)box.scrollTop=1e9}
$('viewer').onclick=()=>$('viewer').classList.add('hidden');
async function send(payload,kind){const{iv,ct}=await E2EE.encryptJSON(await chatKey(S.peer),payload);S.ws.send(JSON.stringify({type:'msg',to:S.peer,iv,ct,kind}))}
$('composer').onsubmit=async e=>{e.preventDefault();const t=$('text').value.trim();if(!t||!S.peer)return;$('text').value='';try{await send({text:t},'text')}catch(err){alert(err.message)}};
$('file').onchange=async e=>{const f=e.target.files[0];e.target.value='';if(!f||!S.peer)return;if(f.size>50e6)return alert('Max 50MB');
 try{const{ct,key,iv}=await E2EE.encryptFile(await f.arrayBuffer());const{id}=await api('/api/media',{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:ct});
  await send({media:{id,key,iv,mime:f.type||'application/octet-stream',name:f.name,size:f.size},text:$('text').value.trim()},'media');$('text').value=''}catch(err){alert(err.message)}};
if(S.token&&S.me)start();
