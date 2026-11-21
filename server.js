// Pintarika Perkalian v2 - Node 22.13+ , tanpa npm
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {DatabaseSync}=require('node:sqlite');
const PROD=process.env.NODE_ENV==='production',DIR=process.env.DATA_DIR||(process.env.VERCEL?'/tmp':__dirname);fs.mkdirSync(DIR,{recursive:true});
const db=new DatabaseSync(path.join(DIR,'data.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,nisn TEXT UNIQUE,nama TEXT,kelas TEXT,role TEXT,hash TEXT,bintang INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS materi(id INTEGER PRIMARY KEY,judul TEXT,ket TEXT,aktif INT DEFAULT 1);
CREATE TABLE IF NOT EXISTS soal(id INTEGER PRIMARY KEY,materi_id INT,q TEXT,opsi TEXT,kunci TEXT,aktif INT DEFAULT 1);
CREATE TABLE IF NOT EXISTS kuis(id INTEGER PRIMARY KEY,user_id INT,materi_id INT,mode TEXT,benar INT,total INT,skor INT,tgl TEXT);
CREATE TABLE IF NOT EXISTS game(id INTEGER PRIMARY KEY,user_id INT,poin INT,tgl TEXT);
CREATE TABLE IF NOT EXISTS sesi(token TEXT PRIMARY KEY,uid INT,exp INT);
CREATE TABLE IF NOT EXISTS kuasai(user_id INT,soal_id INT,PRIMARY KEY(user_id,soal_id));`);
const Q=(s,...p)=>db.prepare(s).all(...p),G=(s,...p)=>db.prepare(s).get(...p),R=(s,...p)=>db.prepare(s).run(...p);
const hash=(pw,salt=crypto.randomBytes(8).toString('hex'))=>salt+':'+crypto.scryptSync(String(pw),salt,32).toString('hex');
const cek=(pw,h)=>{const[s,x]=h.split(':');return crypto.timingSafeEqual(Buffer.from(hash(pw,s).split(':')[1]),Buffer.from(x))};
const now=()=>new Date().toISOString();
if(!G('SELECT 1 x FROM users')){
  if(PROD&&!process.env.GURU_PASS){console.error('Set GURU_PASS (sandi guru) saat produksi');process.exit(1)}
  R('INSERT INTO users(nisn,nama,kelas,role,hash) VALUES(?,?,?,?,?)','guru','Ibu Siti Aminah, S.Pd.','-','guru',hash(process.env.GURU_PASS||'guru123'));
  if(!PROD||process.env.DEMO)R('INSERT INTO users(nisn,nama,kelas,role,hash) VALUES(?,?,?,?,?)','01458291','Budi Santoso','3A','siswa',hash('siswa123'));
  [['Bab 1: Perkalian 1–5',1,5],['Bab 2: Perkalian 6–7',6,7],['Bab 3: Perkalian 8–9',8,9],['Bab 4: Perkalian 10',10,10]].forEach(([j,lo,hi])=>{
    const m=R('INSERT INTO materi(judul,ket) VALUES(?,?)',j,'Latihan perkalian').lastInsertRowid;
    for(let a=lo;a<=hi;a++)for(let b=1;b<=10;b++){const k=a*b,o=[...new Set([k+a,k-a,k+b,k-b,k+1,k-1].filter(x=>x>0&&x!==k))].slice(0,3).concat(k).map(String);
      R('INSERT INTO soal(materi_id,q,opsi,kunci) VALUES(?,?,?,?)',m,`${a} × ${b} = ?`,JSON.stringify(o),String(k))}});
}
const AGUR='Akses khusus guru',fails=new Map(),SEC={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin'};
const body=r=>new Promise(ok=>{let s='';r.on('data',c=>{s+=c;if(s.length>1e6)r.destroy()});r.on('end',()=>{try{ok(JSON.parse(s||'{}'))}catch{ok({})}})});
const str=(v,n=200)=>String(v??'').trim().slice(0,n);
const err=(c,e)=>{throw{c,e}};
const ringkas=id=>{
  const materi=Q(`SELECT m.id,m.judul,(SELECT COUNT(*) FROM soal s WHERE s.materi_id=m.id AND s.aktif=1) semua,
    (SELECT COUNT(*) FROM kuasai k JOIN soal s ON s.id=k.soal_id WHERE k.user_id=? AND s.materi_id=m.id AND s.aktif=1) ok FROM materi m WHERE m.aktif=1`,id);
  const total=materi.reduce((t,m)=>t+m.ok,0),semua=materi.reduce((t,m)=>t+m.semua,0);
  const rk=G('SELECT ROUND(AVG(skor),1) v,COUNT(*) n FROM kuis WHERE user_id=?',id),rg=G('SELECT ROUND(AVG(MIN(poin,100)),1) v FROM game WHERE user_id=?',id);
  return{materi,total,semua,rataKuis:rk.v||0,jumlahKuis:rk.n,rataGame:rg.v||0,
    tujuan:[...materi.map(m=>({t:'Kuasai '+m.judul,done:m.ok>=m.semua&&m.semua>0})),{t:'Kuasai semua perkalian 1–100',done:semua>0&&total>=semua}]}};
const handler=async(req,res)=>{
  const p=new URL(req.url,'http://x').pathname,m=req.method,u=new URL(req.url,'http://x');
  const ip=((PROD&&req.headers['x-forwarded-for'])||'').split(',')[0].trim()||req.socket.remoteAddress;
  if(p==='/healthz'){res.writeHead(200);return res.end('ok')}
  if(!p.startsWith('/api/')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8',...SEC});return res.end(fs.readFileSync(path.join(__dirname,'public','index.html')))}
  const out=(c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json',...SEC,...h});res.end(JSON.stringify(o))};
  try{
    const b=m==='GET'?{}:await body(req);
    if(p==='/api/login'){
      const x=G('SELECT * FROM users WHERE nisn=? AND role=?',str(b.nisn,30),b.role==='guru'?'guru':'siswa');
      const f=fails.get(ip)||{n:0,t:0};if(f.n>=8&&Date.now()-f.t<9e5)err(429,'Terlalu banyak percobaan, coba lagi 15 menit');
      if(!x||!cek(str(b.pw,100),x.hash)){fails.set(ip,{n:f.n+1,t:Date.now()});err(401,'NISN atau kata sandi salah')}
      const t=crypto.randomBytes(24).toString('hex');R('DELETE FROM sesi WHERE exp<?',Date.now());R('INSERT INTO sesi VALUES(?,?,?)',t,x.id,Date.now()+7*864e5);fails.delete(ip);
      return out(200,{ok:1},{'Set-Cookie':`sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${PROD?'; Secure':''}`});
    }
    const sid=(/sid=(\w+)/.exec(req.headers.cookie||'')||[])[1],uid=(G('SELECT uid FROM sesi WHERE token=? AND exp>?',sid||'',Date.now())||{}).uid;
    if(!uid)err(401,'Silakan masuk dulu');
    const me=G('SELECT id,nisn,nama,kelas,role,bintang FROM users WHERE id=?',uid),guru=me.role==='guru';
    const must=()=>{if(!guru)err(403,AGUR)};
    let r;
    if(p==='/api/logout'){R('DELETE FROM sesi WHERE token=?',sid||'');return out(200,{ok:1})}
    if(p==='/api/me')return out(200,me);
    if(p==='/api/ringkas'){const r2=ringkas(me.id);r2.notif=r2.tujuan.filter(t=>t.done).map(t=>'Selamat! Tujuan tercapai: '+t.t);
      if(!G('SELECT 1 x FROM kuis WHERE user_id=? AND tgl>?',me.id,new Date(Date.now()-864e5).toISOString()))r2.notif.push('Ayo kerjakan kuis hari ini!');return out(200,r2)}
    if(p==='/api/ganti-sandi'){const x=G('SELECT hash FROM users WHERE id=?',me.id);if(!cek(str(b.lama,100),x.hash))err(400,'Sandi lama salah');if(str(b.baru,100).length<6)err(400,'Sandi baru minimal 6 karakter');R('UPDATE users SET hash=? WHERE id=?',hash(str(b.baru,100)),me.id);return out(200,{ok:1})}
    if(p==='/api/nilai')return out(200,{kuis:Q('SELECT k.*,m.judul FROM kuis k JOIN materi m ON m.id=k.materi_id WHERE user_id=? ORDER BY k.id DESC LIMIT 50',me.id),game:Q('SELECT * FROM game WHERE user_id=? ORDER BY id DESC LIMIT 20',me.id),...ringkas(me.id)});
    if(p==='/api/kuis'&&m==='GET'){
      const n=Math.min(+u.searchParams.get('n')||10,30);
      return out(200,Q('SELECT id,q,opsi FROM soal WHERE materi_id=? AND aktif=1 ORDER BY RANDOM() LIMIT ?',+u.searchParams.get('materi'),n).map(s=>({...s,opsi:JSON.parse(s.opsi).sort(()=>Math.random()-.5)})));
    }
    if(p==='/api/kuis'&&m==='POST'){
      const js=(Array.isArray(b.jawaban)?b.jawaban:[]).slice(0,30);if(!js.length)err(400,'Tidak ada jawaban');
      const detail=js.map(j=>{const s=G('SELECT kunci FROM soal WHERE id=?',+j.id);const ok=!!s&&String(j.v)===s.kunci;if(ok)R('INSERT OR IGNORE INTO kuasai VALUES(?,?)',me.id,+j.id);return{id:j.id,benar:ok,kunci:s&&s.kunci}});
      const benar=detail.filter(d=>d.benar).length,skor=Math.round(benar/detail.length*100);
      R('INSERT INTO kuis(user_id,materi_id,mode,benar,total,skor,tgl) VALUES(?,?,?,?,?,?,?)',me.id,+b.materi,b.mode==='tantangan'?'tantangan':'santai',benar,detail.length,skor,now());
      R('UPDATE users SET bintang=bintang+? WHERE id=?',benar,me.id);
      return out(200,{benar,total:detail.length,skor,detail});
    }
    if(p==='/api/game'&&m==='POST'){const poin=Math.max(0,Math.min(+b.poin||0,1000));R('INSERT INTO game(user_id,poin,tgl) VALUES(?,?,?)',me.id,poin,now());R('UPDATE users SET bintang=bintang+? WHERE id=?',Math.floor(poin/10),me.id);return out(200,{ok:1})}
    if(p==='/api/materi'&&m==='GET')return out(200,Q(`SELECT * FROM materi ${guru?'':'WHERE aktif=1'}`));
    // ---- khusus guru ----
    must();
    if(p==='/api/materi'&&m==='POST'){const j=str(b.judul,80);if(!j)err(400,'Judul wajib');
      if(b.id)R('UPDATE materi SET judul=?,ket=?,aktif=? WHERE id=?',j,str(b.ket),b.aktif?1:0,+b.id);else R('INSERT INTO materi(judul,ket,aktif) VALUES(?,?,?)',j,str(b.ket),b.aktif?1:0);return out(200,{ok:1})}
    if(p==='/api/materi/hapus'){R('DELETE FROM soal WHERE materi_id=?',+b.id);R('DELETE FROM materi WHERE id=?',+b.id);return out(200,{ok:1})}
    if(p==='/api/soal'&&m==='GET')return out(200,Q('SELECT * FROM soal WHERE (?=0 OR materi_id=?) ORDER BY id DESC LIMIT 200',+u.searchParams.get('materi')||0,+u.searchParams.get('materi')||0));
    if(p==='/api/soal'&&m==='POST'){const o=str(b.opsi,300).split(',').map(x=>x.trim()).filter(Boolean),k=str(b.kunci,50);
      if(!str(b.q)||o.length<2||!o.includes(k))err(400,'Isi soal, minimal 2 opsi, dan kunci harus ada di opsi');
      if(b.id)R('UPDATE soal SET q=?,opsi=?,kunci=? WHERE id=?',str(b.q),JSON.stringify(o),k,+b.id);else R('INSERT INTO soal(materi_id,q,opsi,kunci,aktif) VALUES(?,?,?,?,?)',+b.materi_id,str(b.q),JSON.stringify(o),k,b.aktif?1:0);return out(200,{ok:1})}
    if(p==='/api/soal/hapus'){R('DELETE FROM kuasai WHERE soal_id=?',+b.id);R('DELETE FROM soal WHERE id=?',+b.id);return out(200,{ok:1})}
    if(p==='/api/siswa'&&m==='GET')return out(200,Q("SELECT id,nisn,nama,kelas,bintang FROM users WHERE role='siswa' ORDER BY kelas,nama").map(s=>({...s,...(r=ringkas(s.id),{dikuasai:r.total,rata:r.rataKuis})})));
    if(p==='/api/siswa'&&m==='POST'){const n=str(b.nisn,20),nm=str(b.nama,60);if(!n||!nm||!str(b.kelas,10))err(400,'NISN, nama, kelas wajib');
      if(G('SELECT 1 x FROM users WHERE nisn=?',n))err(400,'NISN sudah terdaftar');
      R('INSERT INTO users(nisn,nama,kelas,role,hash) VALUES(?,?,?,?,?)',n,nm,str(b.kelas,10),'siswa',hash(str(b.pw,50)||n));return out(200,{ok:1})}
    if(p==='/api/siswa/hapus'){const i=+b.id;['kuis','game','kuasai'].forEach(t=>R(`DELETE FROM ${t} WHERE user_id=?`,i));R("DELETE FROM users WHERE id=? AND role='siswa'",i);return out(200,{ok:1})}
    if(p==='/api/siswa/reset'){if(str(b.pw,50).length<6)err(400,'Minimal 6 karakter');R("UPDATE users SET hash=? WHERE id=? AND role='siswa'",hash(str(b.pw,50)),+b.id);return out(200,{ok:1})}
    if(p==='/api/rekap.csv'){const rows=Q("SELECT id,nisn,nama,kelas FROM users WHERE role='siswa' ORDER BY kelas,nama").map(s=>{const r=ringkas(s.id);return[s.nisn,s.nama,s.kelas,r.total,r.rataKuis,r.rataGame].map(v=>'"'+String(v).replace(/"/g,'""').replace(/^[=+\-@]/,"'$&")+'"').join(',')});
      res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename=rekap-nilai.csv',...SEC});return res.end('\ufeffNISN,Nama,Kelas,Dikuasai,Rata Kuis,Rata Game\n'+rows.join('\n'))}
    if(p==='/api/rekap')return out(200,{siswa:G("SELECT COUNT(*) n FROM users WHERE role='siswa'").n,rata:G('SELECT ROUND(AVG(skor),1) v FROM kuis').v||0,bank:G('SELECT COUNT(*) n,SUM(aktif) a FROM soal'),materi:G('SELECT COUNT(*) n FROM materi').n});
    err(404,'Tidak ditemukan');
  }catch(e){out(e.c||500,{error:e.e||'Terjadi kesalahan server'});if(!e.c)console.error(e)}
};
module.exports=handler;
if(require.main===module)http.createServer(handler).listen(process.env.PORT||3000,()=>console.log('Buka http://localhost:'+(process.env.PORT||3000)));
