require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, {recursive:true});
const db = new Database(path.join(DATA_DIR, 'store.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, price_cny INTEGER NOT NULL,
 usd_label TEXT NOT NULL, quota_label TEXT NOT NULL, description TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, product_id TEXT NOT NULL,
 product_name TEXT NOT NULL, amount_cny INTEGER NOT NULL,
 payment_method TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
const initialProducts = [
 ['plus-monthly','GPT Plus 月付',150,'$20 / 月','Plus 标准额度','按月方案；具体权益以购买前核验的信息为准。'],
 ['pro-100','GPT Pro 100',690,'$100 / 月','约 5× 使用额度','额度倍数为商城展示说明，不是 OpenAI 官方套餐名称。'],
 ['pro-200','GPT Pro 200',1400,'$200 / 月','约 10× 使用额度','额度倍数为商城展示说明，不是 OpenAI 官方套餐名称。'],
 ['pro-500','GPT Pro 500',3500,'$500 / 月','约 20× 使用额度','额度倍数为商城展示说明，不是 OpenAI 官方套餐名称。']
];
const insertProduct = db.prepare('INSERT OR IGNORE INTO products(id,name,price_cny,usd_label,quota_label,description) VALUES(?,?,?,?,?,?)');
initialProducts.forEach(p=>insertProduct.run(...p));
const getSetting = db.prepare('SELECT value FROM settings WHERE key=?');
function setting(key, fallback='') { return getSetting.get(key)?.value ?? fallback; }
function setSetting(key,value) { db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,String(value)); }

const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || '';
if (adminEmail && adminPassword && !db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail)) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?,'admin')").run(adminEmail,hash);
}
if (setting('payment_enabled') === '') setSetting('payment_enabled', process.env.PAYMENT_ENABLED === 'true' ? 'true' : 'false');

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{
  defaultSrc:["'self'"], styleSrc:["'self'","'unsafe-inline'"], scriptSrc:["'self'"],
  imgSrc:["'self'","data:"], connectSrc:["'self'"], objectSrc:["'none'"], upgradeInsecureRequests:null
}}}));
app.use(express.json({limit:'32kb'}));
app.use(session({
  store:new SQLiteStore({db:'sessions.sqlite',dir:DATA_DIR}),
  secret:process.env.SESSION_SECRET || 'development-only-change-this-secret',
  resave:false,saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',maxAge:7*24*60*60*1000}
}));
const authLimiter = rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:true,legacyHeaders:false});
const orderLimiter = rateLimit({windowMs:60*60*1000,limit:15,standardHeaders:true,legacyHeaders:false});
const safeEmail = v => typeof v==='string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length<=190;
const currentUser = req => req.session.user || null;
function requireAuth(req,res,next){ if(!currentUser(req)) return res.status(401).json({error:'请先登录'}); next(); }
function requireAdmin(req,res,next){ if(currentUser(req)?.role!=='admin') return res.status(403).json({error:'需要管理员权限'}); next(); }
function publicProducts(){return db.prepare('SELECT id,name,price_cny,usd_label,quota_label,description FROM products WHERE active=1 ORDER BY CASE id WHEN "plus-monthly" THEN 1 WHEN "pro-100" THEN 2 WHEN "pro-200" THEN 3 ELSE 4 END').all();}
app.get('/api/config',(req,res)=>res.json({paymentEnabled:setting('payment_enabled','false')==='true',notice:setting('store_notice','第三方独立商城；非 OpenAI 官方网站。')}));
app.get('/api/products',(req,res)=>res.json(publicProducts()));
app.get('/api/me',(req,res)=>res.json({user:currentUser(req)}));
app.post('/api/register',authLimiter,async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
 if(!safeEmail(email)||password.length<10||password.length>100) return res.status(400).json({error:'请输入有效邮箱，密码长度需为 10–100 位'});
 if(db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(409).json({error:'该邮箱已注册'});
 const hash=await bcrypt.hash(password,12);
 const result=db.prepare('INSERT INTO users(email,password_hash) VALUES(?,?)').run(email,hash);
 req.session.user={id:Number(result.lastInsertRowid),email,role:'customer'};
 res.json({user:req.session.user});
});
app.post('/api/login',authLimiter,async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
 const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!user||!(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:'邮箱或密码不正确'});
 req.session.user={id:user.id,email:user.email,role:user.role}; res.json({user:req.session.user});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.post('/api/orders',requireAuth,orderLimiter,(req,res)=>{
 if(setting('payment_enabled','false')!=='true') return res.status(403).json({error:'在线收款尚未启用，请联系管理员'});
 const product=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(String(req.body.productId||''));
 const method=String(req.body.paymentMethod||'');
 if(!product||!['alipay','wechat'].includes(method)) return res.status(400).json({error:'套餐或支付方式无效'});
 const id='GM'+Date.now().toString(36).toUpperCase()+Math.random().toString(36).slice(2,6).toUpperCase();
 db.prepare('INSERT INTO orders(id,user_id,product_id,product_name,amount_cny,payment_method) VALUES(?,?,?,?,?,?)')
 .run(id,currentUser(req).id,product.id,product.name,product.price_cny,method);
 res.json({order:{id,productName:product.name,amountCny:product.price_cny,paymentMethod:method,status:'pending'}});
});
app.get('/api/orders',requireAuth,(req,res)=>{
 const rows=db.prepare('SELECT id,product_name,amount_cny,payment_method,status,created_at FROM orders WHERE user_id=? ORDER BY created_at DESC').all(currentUser(req).id);
 res.json(rows);
});
app.get('/api/admin/overview',requireAuth,requireAdmin,(req,res)=>{
 res.json({products:db.prepare('SELECT * FROM products ORDER BY rowid').all(),
 orders:db.prepare('SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.created_at DESC LIMIT 200').all(),
 paymentEnabled:setting('payment_enabled','false')==='true',notice:setting('store_notice','')});
});
app.patch('/api/admin/products/:id',requireAuth,requireAdmin,(req,res)=>{
 const id=req.params.id, name=String(req.body.name||'').trim(), price=Number(req.body.priceCny), usd=String(req.body.usdLabel||''), quota=String(req.body.quotaLabel||''), desc=String(req.body.description||'');
 if(!name||!Number.isInteger(price)||price<1||price>1000000) return res.status(400).json({error:'名称或价格无效'});
 const result=db.prepare('UPDATE products SET name=?,price_cny=?,usd_label=?,quota_label=?,description=? WHERE id=?').run(name,price,usd,quota,desc,id);
 if(!result.changes) return res.status(404).json({error:'套餐不存在'});
 res.json({ok:true});
});
app.patch('/api/admin/orders/:id',requireAuth,requireAdmin,(req,res)=>{
 const status=String(req.body.status||'');
 if(!['pending','paid','rejected'].includes(status)) return res.status(400).json({error:'状态无效'});
 const result=db.prepare('UPDATE orders SET status=? WHERE id=?').run(status,req.params.id);
 if(!result.changes) return res.status(404).json({error:'订单不存在'});
 res.json({ok:true});
});
app.patch('/api/admin/settings',requireAuth,requireAdmin,(req,res)=>{
 if(typeof req.body.paymentEnabled==='boolean') setSetting('payment_enabled',req.body.paymentEnabled?'true':'false');
 if(typeof req.body.notice==='string') setSetting('store_notice',req.body.notice.slice(0,500));
 res.json({ok:true});
});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`Membership store running at http://localhost:${PORT}`));
