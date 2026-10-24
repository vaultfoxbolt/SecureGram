const express=require('express'),http=require('http'),{WebSocketServer}=require('ws'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const PORT=process.env.PORT||3000,DATA=path.join(__dirname,'data'),MEDIA=path.join(DATA,'media'),DBF=path.join(DATA,'db.json');
fs.mkdirSync(MEDIA,{recursive:true});
let db=fs.existsSync(DBF)?JSON.parse(fs.readFileSync(DBF)):{users:{},tokens:{},messages:[]};
let saveT;const save=()=>{clearTimeout(saveT);saveT=setTimeout(()=>fs.writeFileSync(DBF,JSON.stringify(db)),100)};
const hash=(p,s)=>crypto.scryptSync(p,s,64).toString('hex');
const app=express();app.use(express.json({limit:'1mb'}));app.use(express.static(path.join(__dirname,'public')));
const auth=(req,res,next)=>{const t=(req.headers.authorization||'').replace('Bearer ','');const u=db.tokens[t];if(!u)return res.status(401).json({error:'unauthorized'});req.user=u;next()};
const valid=u=>/^[a-zA-Z0-9_]{3,20}$/.test(u||'');
app.post('/api/signup',(req,res)=>{const{username,password}=req.body;if(!valid(username)||!password||password.length<6)return res.status(400).json({error:'username 3-20 chars (a-z0-9_), password min 6'});
 const u=username.toLowerCase();if(db.users[u])return res.status(409).json({error:'username taken'});const salt=crypto.randomBytes(16).toString('hex');
 db.users[u]={username:u,salt,hash:hash(password,salt),publicKey:null,contacts:[]};const token=crypto.randomBytes(32).toString('hex');db.tokens[token]=u;save();res.json({token,username:u})});
app.post('/api/login',(req,res)=>{const{username,password}=req.body;const u=db.users[(username||'').toLowerCase()];
 if(!u||!crypto.timingSafeEqual(Buffer.from(hash(password||'',u.salt),'hex'),Buffer.from(u.hash,'hex')))return res.status(401).json({error:'invalid credentials'});
 const token=crypto.randomBytes(32).toString('hex');db.tokens[token]=u.username;save();res.json({token,username:u.username})});
app.post('/api/logout',auth,(req,res)=>{delete db.tokens[(req.headers.authorization||'').replace('Bearer ','')];save();res.json({ok:true})});
app.put('/api/publickey',auth,(req,res)=>{const{publicKey}=req.body;if(!publicKey||!publicKey.kty)return res.status(400).json({error:'jwk required'});db.users[req.user].publicKey={kty:publicKey.kty,crv:publicKey.crv,x:publicKey.x,y:publicKey.y};save();res.json({ok:true})});
app.get('/api/users/:u',auth,(req,res)=>{const u=db.users[req.params.u.toLowerCase()];if(!u)return res.status(404).json({error:'user not found'});res.json({username:u.username,publicKey:u.publicKey})});
app.post('/api/contacts',auth,(req,res)=>{const c=(req.body.username||'').toLowerCase();if(!db.users[c]||c===req.user)return res.status(404).json({error:'user not found'});
 const me=db.users[req.user];if(!me.contacts.includes(c))me.contacts.push(c);save();res.json({ok:true})});
app.get('/api/chats',auth,(req,res)=>{const me=req.user,map={};db.users[me].contacts.forEach(c=>map[c]={username:c,last:null});
 for(const m of db.messages){if(m.from===me||m.to===me){const o=m.from===me?m.to:m.from;map[o]={username:o,last:m}}}
 res.json(Object.values(map).map(c=>({...c,publicKey:db.users[c.username]?.publicKey})).sort((a,b)=>(b.last?.ts||0)-(a.last?.ts||0)))});
app.get('/api/messages/:u',auth,(req,res)=>{const o=req.params.u.toLowerCase(),me=req.user;res.json(db.messages.filter(m=>(m.from===me&&m.to===o)||(m.from===o&&m.to===me)))});
// encrypted media: raw binary ciphertext only
app.post('/api/media',auth,express.raw({type:'application/octet-stream',limit:'60mb'}),(req,res)=>{if(!req.body?.length)return res.status(400).json({error:'empty'});
 const id=crypto.randomBytes(16).toString('hex');fs.writeFileSync(path.join(MEDIA,id+'.bin'),req.body);res.json({id})});
app.get('/api/media/:id',auth,(req,res)=>{const id=req.params.id;if(!/^[a-f0-9]{32}$/.test(id))return res.sendStatus(400);const f=path.join(MEDIA,id+'.bin');if(!fs.existsSync(f))return res.sendStatus(404);res.type('application/octet-stream').sendFile(f)});
const server=http.createServer(app),wss=new WebSocketServer({server,path:'/ws'}),sockets={};
wss.on('connection',(ws,req)=>{const t=new URL(req.url,'http://x').searchParams.get('token'),u=db.tokens[t];if(!u)return ws.close(4001,'unauthorized');
 (sockets[u]=sockets[u]||new Set()).add(ws);
 ws.on('message',raw=>{let d;try{d=JSON.parse(raw)}catch{return}
  if(d.type==='msg'){const to=(d.to||'').toLowerCase();if(!db.users[to]||typeof d.iv!=='string'||typeof d.ct!=='string')return;
   const m={id:crypto.randomBytes(8).toString('hex'),from:u,to,iv:d.iv,ct:d.ct,kind:d.kind==='media'?'media':'text',ts:Date.now()};
   db.messages.push(m);const me=db.users[u],them=db.users[to];if(!me.contacts.includes(to))me.contacts.push(to);if(!them.contacts.includes(u))them.contacts.push(u);save();
   for(const n of[u,to])sockets[n]?.forEach(s=>s.readyState===1&&s.send(JSON.stringify({type:'msg',msg:m,clientId:n===u?d.clientId:undefined})))}});
 ws.on('close',()=>sockets[u].delete(ws))});
server.listen(PORT,()=>console.log('Messenger running on http://localhost:'+PORT));
