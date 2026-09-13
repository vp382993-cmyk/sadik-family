const express=require('express');
const session=require('express-session');
const pgSession=require('connect-pg-simple')(session);
const bcrypt=require('bcryptjs');
const {Pool}=require('pg');
const path=require('path');

const app=express();
const PORT=process.env.PORT||3000;
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?{rejectUnauthorized:false}:false});
const ROLES={
 owner:{name:'Владелец',p:['users','treasury','warehouse','operations','view']},
 admin:{name:'Администратор',p:['users','treasury','warehouse','operations','view']},
 cashier:{name:'Кассир',p:['treasury','operations','view']},
 warehouse:{name:'Кладовщик',p:['warehouse','view']},
 member:{name:'Участник',p:['view','member_expense','profile']}
};

app.use(express.json());
app.use(session({
 store:new pgSession({pool,tableName:'user_sessions',createTableIfMissing:true}),
 secret:process.env.SESSION_SECRET||'CHANGE_ME_NOW',
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:1000*60*60*24*7}
}));
app.use(express.static(path.join(__dirname,'public')));

async function init(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS settings(
   id integer PRIMARY KEY CHECK(id=1),
   treasury numeric NOT NULL DEFAULT 20000,
   weekly_income numeric NOT NULL DEFAULT 140000
 );
 CREATE TABLE IF NOT EXISTS users(
   id serial PRIMARY KEY,
   username text UNIQUE NOT NULL,
   password_hash text NOT NULL,
   role text NOT NULL,
   active boolean NOT NULL DEFAULT true,
   created_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS operations(
   id serial PRIMARY KEY,
   type text NOT NULL CHECK(type IN ('income','expense')),
   amount numeric NOT NULL,
   note text DEFAULT '',
   by_username text NOT NULL,
   created_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS warehouse(
   id serial PRIMARY KEY,
   name text NOT NULL,
   qty numeric NOT NULL,
   price numeric NOT NULL,
   by_username text NOT NULL,
   created_at timestamptz NOT NULL DEFAULT now()
 );
 INSERT INTO settings(id,treasury,weekly_income) VALUES(1,20000,140000)
 ON CONFLICT(id) DO NOTHING;
 `);
 const c=await pool.query('SELECT id FROM users LIMIT 1');
 if(c.rowCount===0){
   const hash=bcrypt.hashSync('admin123',10);
   await pool.query('INSERT INTO users(username,password_hash,role) VALUES($1,$2,$3)',[
     'admin',hash,'owner'
   ]);
 }
}
const safe=u=>({id:u.id,username:u.username,role:u.role,roleName:ROLES[u.role]?.name||u.role,active:u.active,createdAt:u.created_at});
async function auth(req,res,next){
 try{
   const u=await pool.query('SELECT * FROM users WHERE id=$1 AND active=true',[req.session.userId]);
   if(!u.rowCount)return res.status(401).json({error:'Требуется вход'});
   req.user=u.rows[0];next();
 }catch(e){next(e)}
}
const allow=p=>(req,res,next)=>ROLES[req.user.role]?.p.includes(p)?next():res.status(403).json({error:'Недостаточно прав'});

app.post('/api/login',async(req,res,next)=>{
 try{
  const username=String(req.body?.username||'').trim().toLowerCase();
  const password=String(req.body?.password||'');
  const q=await pool.query('SELECT * FROM users WHERE lower(username)=lower($1)',[username]);
  const u=q.rows[0];
  if(!u||!u.active||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:'Неверный логин или пароль'});
  req.session.userId=u.id;
  res.json({user:safe(u)});
 }catch(e){next(e)}
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',auth,(req,res)=>res.json({user:safe(req.user)}));

app.get('/api/dashboard',auth,async(req,res,next)=>{
 try{
  const s=await pool.query('SELECT * FROM settings WHERE id=1');
  const sums=await pool.query(`SELECT
    COALESCE(SUM(amount) FILTER(WHERE type='income'),0) income,
    COALESCE(SUM(amount) FILTER(WHERE type='expense'),0) expenses,
    COALESCE(SUM(amount) FILTER(WHERE type='income' AND created_at >= (date_trunc('week', now() AT TIME ZONE 'Europe/Moscow') + interval '6 hours') AT TIME ZONE 'Europe/Moscow'),0) weekly_income
    FROM operations`);
  const stock=await pool.query('SELECT COALESCE(SUM(qty*price),0) stock FROM warehouse');
  const ops=await pool.query('SELECT id,type,amount,note,by_username by,created_at at FROM operations ORDER BY id DESC LIMIT 100');
  const wh=await pool.query('SELECT id,name,qty,price,by_username by,created_at at FROM warehouse ORDER BY id DESC');
  const users=await pool.query('SELECT COUNT(*)::int count FROM users');
  const income=Number(sums.rows[0].income),expenses=Number(sums.rows[0].expenses);
  res.json({
    treasury:Number(s.rows[0].treasury)+income-expenses,
    weeklyIncome:Number(sums.rows[0].weekly_income),totalIncome:income,income,expenses,
    stockValue:Number(stock.rows[0].stock),users:users.rows[0].count,
    operations:ops.rows,warehouse:wh.rows
  });
 }catch(e){next(e)}
});

app.get('/api/settings',auth,allow('treasury'),async(req,res,next)=>{
 try{const q=await pool.query('SELECT treasury,weekly_income weeklyIncome FROM settings WHERE id=1');res.json(q.rows[0])}catch(e){next(e)}
});
app.put('/api/settings',auth,allow('treasury'),async(req,res,next)=>{
 try{
  const a=Number(req.body.treasury),b=Number(req.body.weeklyIncome);
  if(!Number.isFinite(a)||!Number.isFinite(b))return res.status(400).json({error:'Неверные числа'});
  await pool.query('UPDATE settings SET treasury=$1,weekly_income=$2 WHERE id=1',[a,b]);
  res.json({treasury:a,weeklyIncome:b});
 }catch(e){next(e)}
});

app.post('/api/operations',auth,async(req,res,next)=>{
 if(req.user.role==='member' && req.body.type!=='expense')return res.status(403).json({error:'Участник может добавлять только расходы'});
 if(!ROLES[req.user.role]?.p.includes('operations') && req.user.role!=='member')return res.status(403).json({error:'Недостаточно прав'});
 try{
  const type=req.body.type,amount=Number(req.body.amount);
  if(!['income','expense'].includes(type)||!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'Укажи корректный тип и сумму'});
  const q=await pool.query('INSERT INTO operations(type,amount,note,by_username) VALUES($1,$2,$3,$4) RETURNING id,type,amount,note,by_username by,created_at at',[type,amount,String(req.body.note||''),req.user.username]);
  res.json(q.rows[0]);
 }catch(e){next(e)}
});
app.delete('/api/operations/:id',auth,allow('operations'),async(req,res,next)=>{
 try{await pool.query('DELETE FROM operations WHERE id=$1',[Number(req.params.id)]);res.json({ok:true})}catch(e){next(e)}
});

app.post('/api/warehouse',auth,allow('warehouse'),async(req,res,next)=>{
 try{
  const name=String(req.body.name||'').trim(),qty=Number(req.body.qty),price=Number(req.body.price);
  if(!name||!Number.isFinite(qty)||qty<=0||!Number.isFinite(price)||price<0)return res.status(400).json({error:'Заполни товар, количество и цену'});
  const q=await pool.query('INSERT INTO warehouse(name,qty,price,by_username) VALUES($1,$2,$3,$4) RETURNING id,name,qty,price,by_username by,created_at at',[name,qty,price,req.user.username]);
  res.json(q.rows[0]);
 }catch(e){next(e)}
});
app.delete('/api/warehouse/:id',auth,allow('warehouse'),async(req,res,next)=>{
 try{await pool.query('DELETE FROM warehouse WHERE id=$1',[Number(req.params.id)]);res.json({ok:true})}catch(e){next(e)}
});

app.get('/api/users',auth,allow('users'),async(req,res,next)=>{
 try{const q=await pool.query('SELECT * FROM users ORDER BY id');res.json(q.rows.map(safe))}catch(e){next(e)}
});
app.post('/api/users',auth,allow('users'),async(req,res,next)=>{
 try{
  const username=String(req.body.username||'').trim(),password=String(req.body.password||''),role=req.body.role;
  if(!username||!password||!ROLES[role])return res.status(400).json({error:'Заполни логин, пароль и роль'});
  const exists=await pool.query('SELECT 1 FROM users WHERE lower(username)=lower($1)',[username]);
  if(exists.rowCount)return res.status(400).json({error:'Такой логин уже существует'});
  const hash=bcrypt.hashSync(password,10);
  const q=await pool.query('INSERT INTO users(username,password_hash,role) VALUES($1,$2,$3) RETURNING *',[username,hash,role]);
  res.json(safe(q.rows[0]));
 }catch(e){next(e)}
});
app.patch('/api/users/:id',auth,allow('users'),async(req,res,next)=>{
 try{
  const id=Number(req.params.id),q=await pool.query('SELECT * FROM users WHERE id=$1',[id]);
  if(!q.rowCount)return res.status(404).json({error:'Пользователь не найден'});
  const u=q.rows[0];
  if(req.body.role&&ROLES[req.body.role])u.role=req.body.role;
  if(typeof req.body.active==='boolean'&&id!==req.user.id)u.active=req.body.active;
  if(req.body.password)u.password_hash=bcrypt.hashSync(String(req.body.password),10);
  const r=await pool.query('UPDATE users SET role=$1,active=$2,password_hash=$3 WHERE id=$4 RETURNING *',[u.role,u.active,u.password_hash,id]);
  res.json(safe(r.rows[0]));
 }catch(e){next(e)}
});

app.get('/health',(req,res)=>res.json({ok:true}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Ошибка сервера'})});

init().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`SADIK Family shared v3: http://localhost:${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
