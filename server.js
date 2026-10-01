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
const DB_FILE=path.join(DATA_DIR,'submissions.json');
const STAFF_PASSWORD=process.env.STAFF_PASSWORD||'';
const sessions=new Map();
const attempts=new Map();

fs.mkdirSync(UPLOAD_DIR,{recursive:true});
if(!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE,'[]','utf8');

app.set('trust proxy',1);
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:true,limit:'1mb'}));
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','same-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  next();
});

function readDB(){try{return JSON.parse(fs.readFileSync(DB_FILE,'utf8'))}catch{return []}}
function writeDB(rows){const tmp=DB_FILE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(rows,null,2));fs.renameSync(tmp,DB_FILE)}
function cookieMap(req){const out={};String(req.headers.cookie||'').split(';').forEach(p=>{const i=p.indexOf('=');if(i>0)out[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())});return out}
function isStaff(req){const token=cookieMap(req).tgi_staff;if(!token)return false;const s=sessions.get(token);if(!s||s.expires<Date.now()){if(token)sessions.delete(token);return false}return true}
function requireStaff(req,res,next){if(!isStaff(req))return res.status(401).json({error:'Staff sign-in required'});next()}
function safeEqual(a,b){const A=Buffer.from(String(a));const B=Buffer.from(String(b));return A.length===B.length&&crypto.timingSafeEqual(A,B)}
function cleanText(v,max=4000){return String(v||'').replace(/[\u0000-\u001f<>]/g,' ').trim().slice(0,max)}
function id(){return Date.now().toString(36)+'-'+crypto.randomBytes(5).toString('hex')}

const allowed=new Set(['image/jpeg','image/png','image/webp','image/gif','application/pdf','text/plain']);
const storage=multer.diskStorage({
  destination:(req,file,cb)=>cb(null,UPLOAD_DIR),
  filename:(req,file,cb)=>cb(null,id()+path.extname(file.originalname).toLowerCase().slice(0,10))
});
const upload=multer({
  storage,
  limits:{files:6,fileSize:10*1024*1024},
  fileFilter:(req,file,cb)=>allowed.has(file.mimetype)?cb(null,true):cb(new Error('Unsupported file type'))
});

app.get('/health',(req,res)=>res.json({ok:true}));

app.post('/api/report',upload.array('attachments',6),(req,res)=>{
  const reportedUser=cleanText(req.body.reportedUser,120);
  const reporter=cleanText(req.body.reporter,120);
  const reason=cleanText(req.body.reason,300);
  const details=cleanText(req.body.details,8000);
  const incidentDate=cleanText(req.body.incidentDate,40);
  const evidenceLinks=cleanText(req.body.evidenceLinks,2500);
  if(!reportedUser||!reason||!details)return res.status(400).json({error:'Reported user, reason, and details are required.'});
  const row={
    id:id(),createdAt:new Date().toISOString(),status:'Pending Review',
    reportedUser,reporter:reporter||'Anonymous',reason,details,incidentDate,evidenceLinks,
    files:(req.files||[]).map(f=>({stored:f.filename,original:cleanText(f.originalname,180),type:f.mimetype,size:f.size}))
  };
  const rows=readDB();rows.unshift(row);writeDB(rows);
  res.status(201).json({ok:true,id:row.id,message:'Evidence submitted for staff review.'});
});

app.post('/api/staff/login',(req,res)=>{
  if(!STAFF_PASSWORD)return res.status(503).json({error:'Staff login is not configured.'});
  const ip=req.ip||'unknown';const now=Date.now();let a=attempts.get(ip)||{count:0,start:now};
  if(now-a.start>15*60*1000)a={count:0,start:now};
  if(a.count>=8)return res.status(429).json({error:'Too many attempts. Try again later.'});
  if(!safeEqual(req.body.password||'',STAFF_PASSWORD)){a.count++;attempts.set(ip,a);return res.status(401).json({error:'Incorrect password.'})}
  attempts.delete(ip);
  const token=crypto.randomBytes(32).toString('hex');sessions.set(token,{expires:now+12*60*60*1000});
  const secure=req.secure||req.get('x-forwarded-proto')==='https';
  res.setHeader('Set-Cookie',`tgi_staff=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${secure?'; Secure':''}`);
  res.json({ok:true});
});
app.post('/api/staff/logout',requireStaff,(req,res)=>{
  const token=cookieMap(req).tgi_staff;if(token)sessions.delete(token);
  res.setHeader('Set-Cookie','tgi_staff=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ok:true});
});
app.get('/api/staff/session',(req,res)=>res.json({authenticated:isStaff(req)}));
app.get('/api/staff/submissions',requireStaff,(req,res)=>res.json(readDB()));
app.patch('/api/staff/submissions/:id',requireStaff,(req,res)=>{
  const allowedStatus=new Set(['Pending Review','Under Review','Action Taken','Dismissed','Archived']);
  if(!allowedStatus.has(req.body.status))return res.status(400).json({error:'Invalid status'});
  const rows=readDB();const row=rows.find(x=>x.id===req.params.id);if(!row)return res.status(404).json({error:'Submission not found'});
  row.status=req.body.status;row.updatedAt=new Date().toISOString();writeDB(rows);res.json({ok:true,row});
});
app.get('/api/staff/files/:submission/:file',requireStaff,(req,res)=>{
  const rows=readDB();const row=rows.find(x=>x.id===req.params.submission);if(!row)return res.sendStatus(404);
  const f=(row.files||[]).find(x=>x.stored===req.params.file);if(!f)return res.sendStatus(404);
  res.download(path.join(UPLOAD_DIR,f.stored),f.original);
});

app.use(express.static(PUBLIC_DIR));
app.get('*',(req,res)=>res.sendFile(path.join(PUBLIC_DIR,'index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(400).json({error:err.message||'Request failed'})});
app.listen(port,'0.0.0.0',()=>console.log('TGI listening on '+port));