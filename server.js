const express=require('express');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');
const multer=require('multer');

const app=express();
const port=process.env.PORT||3000;
const PUBLIC_DIR=path.join(__dirname,'public');
const DATA_DIR=process.env.DATA_DIR||path.join(__dirname,'data');
const UPLOAD_DIR=path.join(DATA_DIR,'evidence');
const SUBMISSIONS_FILE=path.join(DATA_DIR,'submissions.json');
const BLACKLIST_FILE=path.join(DATA_DIR,'blacklist.json');
const OFFENSES_FILE=path.join(DATA_DIR,'offenses.json');
const ORDER_FILE=path.join(DATA_DIR,'order-content.json');
const STAFF_PASSWORD=process.env.STAFF_PASSWORD||'';
const sessions=new Map(),attempts=new Map();

const DEFAULT_OFFENSES={
 blacklistTitle:'Blacklistable Offenses',
 blacklistIntro:'These offenses may be grounds for an Order of the Hammer blacklist after staff review of the evidence and context.',
 blacklistRules:[
 '1.1.- Proven to be a pedophile or to have engaged in such behavior.',
 '1.2.- Give safe heaven to someone proven of sin 1.1 even after being informed of the sin and receive the evidence to prove it.',
 '1.3.- Engage in non-consensual sexual behavior that goes beyond the VR like sending unsolicited nudes.',
 '1.4.- The use of child pornography in any way shape or form.',
 '1.5.- The use of suicide or self harm as a way of manipulating or gaining attention.',
 '1.6.- For a minor to actively seek a romantic relation with a known pedophile, even knowing for that individual to be one.*',
 '1.7.- For a someone to actively seek a relation with a known pedophile, even knowing for that individual to be one.',
 '1.8.- For a minor to lie about their age in order to be in a relationship with an adult.',
 '1.9.- For an adult to engage in romantic speaking or attempt to have a relationship with a known minor. or grooming.',
 '1.10.- proven to be a zoophile or engage in such behavior.',
 '1.11.- for a minor to seek a relationship with an adult.',
 '1.12.- For anyone— adult or minor, to do anything unholy to animals.'
 ],
 infoTitle:'Info Offenses',
 infoIntro:'These are lower-level community offenses that may be published for awareness after staff review.',
 infoRules:[
 '2.1.- Attempt of a takeover without the consent of the greater group.',
 '2.2.- Use of drama to manipulate or ruin the fun of other to an extreme extent.',
 '2.3.- Spread of rumors without any evidence. With or without ill intent, it makes no difference as the damage is the same.',
 '2.4.- to make claims or accusations without evidence or with knowingly false evidence'
 ]
};
const DEFAULT_ORDER={title:'THE ORDER OF THE HAMMER',description:"The Grimdark Imperium's blacklist and exile designation for serious community violations.",motto:'Judgment Falls. The Hammer Remembers.'};

fs.mkdirSync(UPLOAD_DIR,{recursive:true});
function ensure(file,value){if(!fs.existsSync(file))fs.writeFileSync(file,JSON.stringify(value,null,2),'utf8')}
ensure(SUBMISSIONS_FILE,[]);ensure(BLACKLIST_FILE,[]);ensure(OFFENSES_FILE,DEFAULT_OFFENSES);ensure(ORDER_FILE,DEFAULT_ORDER);
function read(file,fallback){try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch{return fallback}}
function write(file,value){const tmp=file+'.tmp';fs.writeFileSync(tmp,JSON.stringify(value,null,2));fs.renameSync(tmp,file)}
function clean(v,max=8000){return String(v??'').replace(/[\u0000-\u001f<>]/g,' ').trim().slice(0,max)}
function newId(prefix='TGI'){return prefix+'-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase()}
function cookies(req){const o={};String(req.headers.cookie||'').split(';').forEach(p=>{const i=p.indexOf('=');if(i>0)o[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())});return o}
function isStaff(req){const t=cookies(req).tgi_staff,s=t&&sessions.get(t);if(!s||s.expires<Date.now()){if(t)sessions.delete(t);return false}return true}
function requireStaff(req,res,next){if(!isStaff(req))return res.status(401).json({error:'Staff sign-in required'});next()}
function safeEqual(a,b){const A=Buffer.from(String(a)),B=Buffer.from(String(b));return A.length===B.length&&crypto.timingSafeEqual(A,B)}

app.set('trust proxy',1);
app.use(express.json({limit:'2mb'}));
app.use(express.urlencoded({extended:true,limit:'2mb'}));
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');next()});

const allowed=new Set(['image/jpeg','image/png','image/webp','image/gif','application/pdf','text/plain']);
const upload=multer({storage:multer.diskStorage({destination:(req,f,cb)=>cb(null,UPLOAD_DIR),filename:(req,f,cb)=>cb(null,newId('EV')+path.extname(f.originalname).toLowerCase().slice(0,10))}),limits:{files:6,fileSize:10*1024*1024},fileFilter:(req,f,cb)=>allowed.has(f.mimetype)?cb(null,true):cb(new Error('Unsupported file type'))});

app.get('/health',(req,res)=>res.json({ok:true}));
app.get('/api/offenses',(req,res)=>res.json(read(OFFENSES_FILE,DEFAULT_OFFENSES)));
app.get('/api/order-content',(req,res)=>res.json(read(ORDER_FILE,DEFAULT_ORDER)));
app.get('/api/blacklist',(req,res)=>{
 const scope=req.query.scope||'active',rows=read(BLACKLIST_FILE,[]);
 const visible=rows.filter(x=>scope==='past'?['Revoked','Expired','Archived'].includes(x.status):x.status==='Active');
 res.json(visible.map(({privateNotes,...x})=>x));
});

app.post('/api/report',upload.array('attachments',6),(req,res)=>{
 const reportedUser=clean(req.body.reportedUser,120),reporter=clean(req.body.reporter,120),reason=clean(req.body.reason,500),details=clean(req.body.details,10000),incidentDate=clean(req.body.incidentDate,40),evidenceLinks=clean(req.body.evidenceLinks,3000);
 if(!reportedUser||!reason||!details)return res.status(400).json({error:'Reported user, reason, and details are required.'});
 const row={id:newId('CASE'),createdAt:new Date().toISOString(),status:'Pending Review',reportedUser,reporter:reporter||'Anonymous',reason,details,incidentDate,evidenceLinks,files:(req.files||[]).map(f=>({stored:f.filename,original:clean(f.originalname,180),type:f.mimetype,size:f.size}))};
 const rows=read(SUBMISSIONS_FILE,[]);rows.unshift(row);write(SUBMISSIONS_FILE,rows);res.status(201).json({ok:true,id:row.id});
});

app.post('/api/staff/login',(req,res)=>{
 if(!STAFF_PASSWORD)return res.status(503).json({error:'Staff login is not configured.'});
 const ip=req.ip||'unknown',now=Date.now();let a=attempts.get(ip)||{count:0,start:now};if(now-a.start>15*60*1000)a={count:0,start:now};if(a.count>=8)return res.status(429).json({error:'Too many attempts. Try again later.'});
 if(!safeEqual(req.body.password||'',STAFF_PASSWORD)){a.count++;attempts.set(ip,a);return res.status(401).json({error:'Incorrect password.'})}
 attempts.delete(ip);const token=crypto.randomBytes(32).toString('hex');sessions.set(token,{expires:now+12*60*60*1000});const secure=req.secure||req.get('x-forwarded-proto')==='https';res.setHeader('Set-Cookie',`tgi_staff=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${secure?'; Secure':''}`);res.json({ok:true});
});
app.post('/api/staff/logout',requireStaff,(req,res)=>{const t=cookies(req).tgi_staff;if(t)sessions.delete(t);res.setHeader('Set-Cookie','tgi_staff=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');res.json({ok:true})});
app.get('/api/staff/session',(req,res)=>res.json({authenticated:isStaff(req)}));

app.get('/api/staff/submissions',requireStaff,(req,res)=>res.json(read(SUBMISSIONS_FILE,[])));
app.put('/api/staff/submissions/:id',requireStaff,(req,res)=>{
 const rows=read(SUBMISSIONS_FILE,[]),row=rows.find(x=>x.id===req.params.id);if(!row)return res.status(404).json({error:'Submission not found'});
 for(const k of ['reportedUser','reporter','reason','details','incidentDate','evidenceLinks','status'])if(k in req.body)row[k]=clean(req.body[k],k==='details'?10000:3000);
 row.updatedAt=new Date().toISOString();write(SUBMISSIONS_FILE,rows);res.json({ok:true,row});
});
app.delete('/api/staff/submissions/:id',requireStaff,(req,res)=>{let rows=read(SUBMISSIONS_FILE,[]);const before=rows.length;rows=rows.filter(x=>x.id!==req.params.id);write(SUBMISSIONS_FILE,rows);res.status(rows.length===before?404:200).json({ok:rows.length<before})});
app.get('/api/staff/files/:submission/:file',requireStaff,(req,res)=>{const row=read(SUBMISSIONS_FILE,[]).find(x=>x.id===req.params.submission),f=row&&(row.files||[]).find(x=>x.stored===req.params.file);if(!f)return res.sendStatus(404);res.download(path.join(UPLOAD_DIR,f.stored),f.original)});

app.get('/api/staff/blacklist',requireStaff,(req,res)=>res.json(read(BLACKLIST_FILE,[])));
app.post('/api/staff/blacklist',requireStaff,(req,res)=>{
 const now=new Date().toISOString(),row={id:newId('BL'),name:clean(req.body.name,150),reason:clean(req.body.reason,1000),offense:clean(req.body.offense,1000),status:clean(req.body.status||'Active',40),publicSummary:clean(req.body.publicSummary,5000),privateNotes:clean(req.body.privateNotes,8000),createdAt:now,updatedAt:now};
 if(!row.name||!row.reason)return res.status(400).json({error:'Name and reason are required'});
 const rows=read(BLACKLIST_FILE,[]);rows.unshift(row);write(BLACKLIST_FILE,rows);res.status(201).json({ok:true,row});
});
app.put('/api/staff/blacklist/:id',requireStaff,(req,res)=>{
 const rows=read(BLACKLIST_FILE,[]),row=rows.find(x=>x.id===req.params.id);if(!row)return res.status(404).json({error:'Blacklist record not found'});
 for(const k of ['name','reason','offense','status','publicSummary','privateNotes'])if(k in req.body)row[k]=clean(req.body[k],k.includes('Summary')||k==='privateNotes'?8000:1500);
 row.updatedAt=new Date().toISOString();write(BLACKLIST_FILE,rows);res.json({ok:true,row});
});
app.delete('/api/staff/blacklist/:id',requireStaff,(req,res)=>{let rows=read(BLACKLIST_FILE,[]);const before=rows.length;rows=rows.filter(x=>x.id!==req.params.id);write(BLACKLIST_FILE,rows);res.status(rows.length===before?404:200).json({ok:rows.length<before})});

app.put('/api/staff/offenses',requireStaff,(req,res)=>{
 const data={blacklistTitle:clean(req.body.blacklistTitle,200)||'Blacklistable Offenses',blacklistIntro:clean(req.body.blacklistIntro,2000),blacklistRules:Array.isArray(req.body.blacklistRules)?req.body.blacklistRules.map(x=>clean(x,3000)).filter(Boolean).slice(0,200):[],infoTitle:clean(req.body.infoTitle,200)||'Info Offenses',infoIntro:clean(req.body.infoIntro,2000),infoRules:Array.isArray(req.body.infoRules)?req.body.infoRules.map(x=>clean(x,3000)).filter(Boolean).slice(0,200):[]};
 write(OFFENSES_FILE,data);res.json({ok:true,data});
});
app.put('/api/staff/order-content',requireStaff,(req,res)=>{const data={title:clean(req.body.title,200)||DEFAULT_ORDER.title,description:clean(req.body.description,3000),motto:clean(req.body.motto,500)};write(ORDER_FILE,data);res.json({ok:true,data})});

app.use(express.static(PUBLIC_DIR));
app.get('*',(req,res)=>res.sendFile(path.join(PUBLIC_DIR,'index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(400).json({error:err.message||'Request failed'})});
app.listen(port,'0.0.0.0',()=>console.log('TGI listening on '+port));