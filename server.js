const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const path=require("path");

const app=express();
const db=new Database("kaziuganda.db");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',balance INTEGER NOT NULL DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS jobs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,company TEXT NOT NULL,
 location TEXT NOT NULL,description TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,type TEXT NOT NULL,
 amount INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 reference TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"change-this-secret",resave:false,saveUninitialized:false,cookie:{httpOnly:true}}));
https://uganda-online-jobs.onrender.com

function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:"Login required"});next();}
function admin(req,res,next){if(!req.session.user||req.session.user.role!=="admin")return res.status(403).json({error:"Admin only"});next();}

app.post("/api/register",(req,res)=>{
 const {name,email,password}=req.body;
 if(!name||!email||!password)return res.status(400).json({error:"Name, email and password are required"});
 try{
  const hash=bcrypt.hashSync(password,10);
  const info=db.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").run(name,email,hash);
  req.session.user={id:info.lastInsertRowid,name,email,role:"user"};
  res.json({ok:true,user:req.session.user});
 }catch(e){res.status(400).json({error:"Email already registered"});}
});
app.post("/api/login",(req,res)=>{
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(req.body.email);
 if(!u||!bcrypt.compareSync(req.body.password,u.password))return res.status(401).json({error:"Invalid email or password"});
 req.session.user={id:u.id,name:u.name,email:u.email,role:u.role};
 res.json({ok:true,user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/me",auth,(req,res)=>{
 const u=db.prepare("SELECT id,name,email,role,balance FROM users WHERE id=?").get(req.session.user.id);
 res.json(u);
});
app.get("/api/jobs",(req,res)=>res.json(db.prepare("SELECT * FROM jobs ORDER BY id DESC").all()));

app.get("/api/transactions",auth,(req,res)=>{
 res.json(db.prepare("SELECT id,type,amount,status,reference,created_at FROM transactions WHERE user_id=? ORDER BY id DESC").all(req.session.user.id));
});

/* Payment provider integration intentionally left behind a server-side boundary.
   Add your Uganda payment provider credentials only on the server, never in frontend JS. */
app.post("/api/withdraw",auth,(req,res)=>{
 const amount=Number(req.body.amount);
 if(!Number.isInteger(amount)||amount<=0)return res.status(400).json({error:"Enter a valid UGX amount"});
 const u=db.prepare("SELECT balance FROM users WHERE id=?").get(req.session.user.id);
 if(amount>u.balance)return res.status(400).json({error:"Insufficient balance"});
 const reference="WD-"+Date.now();
 const tx=db.prepare("INSERT INTO transactions(user_id,type,amount,status,reference) VALUES(?,?,?,?,?)")
   .run(req.session.user.id,"withdrawal",amount,"pending",reference);
 db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(amount,req.session.user.id);
 res.json({ok:true,transactionId:tx.lastInsertRowid,reference,status:"pending",
  message:"Withdrawal recorded. Connect your approved Uganda payment provider to complete the payout."});
});

app.post("/api/admin/jobs",admin,(req,res)=>{
 const {title,company,location,description}=req.body;
 if(!title||!company||!location||!description)return res.status(400).json({error:"All job fields are required"});
 const r=db.prepare("INSERT INTO jobs(title,company,location,description) VALUES(?,?,?,?)").run(title,company,location,description);
 res.json({ok:true,id:r.lastInsertRowid});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.listen(process.env.PORT||3000,()=>console.log("KaziUganda running on port "+(process.env.PORT||3000)));
