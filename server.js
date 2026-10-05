const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("kaziuganda.db");

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "CHANGE_THIS_IN_RENDER",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    }
  })
);

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  balance INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  company TEXT NOT NULL,
  location TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  type TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  reference TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

function auth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  next();
}

function admin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

/* REGISTER */
app.post("/api/register", (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!name || !email || !password) {
    return res.status(400).json({
      error: "Name, email and password are required."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "Password must contain at least 6 characters."
    });
  }

  try {
    const existing = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(email);

    if (existing) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const hash = bcrypt.hashSync(password, 12);

    const result = db
      .prepare(
        "INSERT INTO users(name,email,password,role,balance) VALUES(?,?,?,?,?)"
      )
      .run(name, email, hash, "user", 0);

    req.session.user = {
      id: Number(result.lastInsertRowid),
      name,
      email,
      role: "user"
    };

    res.status(201).json({
      ok: true,
      message: "Account created successfully.",
      user: req.session.user
    });
  } catch (error) {
    console.error("Registration error:", error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

/* LOGIN */
app.post("/api/login", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required."
    });
  }

  try {
    const user = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(email);

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session error:", err);

        return res.status(500).json({
          error: "Unable to start your session."
        });
      }

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      res.json({
        ok: true,
        message: "Login successful.",
        user: req.session.user
      });
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Unable to log in."
    });
  }
});

/* LOGOUT */
app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Unable to log out."
      });
    }

    res.clearCookie("connect.sid");

    res.json({
      ok: true
    });
  });
});

/* CURRENT USER */
app.get("/api/me", auth, (req, res) => {
  const user = db
    .prepare(
      "SELECT id,name,email,role,balance,created_at FROM users WHERE id = ?"
    )
    .get(req.session.user.id);

  if (!user) {
    return res.status(404).json({
      error: "User account not found."
    });
  }

  res.json(user);
});

/* TRANSACTIONS */
app.get("/api/transactions", auth, (req, res) => {
  const transactions = db
    .prepare(
      `SELECT id,type,amount,status,reference,created_at
       FROM transactions
       WHERE user_id = ?
       ORDER BY id DESC`
    )
    .all(req.session.user.id);

  res.json(transactions);
});

/* JOBS */
app.get("/api/jobs", (req, res) => {
  const jobs = db
    .prepare("SELECT * FROM jobs ORDER BY id DESC")
    .all();

  res.json(jobs);
});

/* WITHDRAWAL REQUEST */
app.post("/api/withdraw", auth, (req, res) => {
  const amount = Number(req.body.amount);

  if (!Number.isInteger(amount) || amount <= 0) {
    return res.status(400).json({
      error: "Enter a valid UGX amount."
    });
  }

  const user = db
    .prepare("SELECT balance FROM users WHERE id = ?")
    .get(req.session.user.id);

  if (!user) {
    return res.status(404).json({
      error: "User account not found."
    });
  }

  if (amount > user.balance) {
    return res.status(400).json({
      error: "Insufficient balance."
    });
  }

  const reference = "WD-" + Date.now();

  const transaction = db
    .prepare(
      `INSERT INTO transactions
       (user_id,type,amount,status,reference)
       VALUES(?,?,?,?,?)`
    )
    .run(
      req.session.user.id,
      "withdrawal",
      amount,
      "pending",
      reference
    );

  db.prepare(
    "UPDATE users SET balance = balance - ? WHERE id = ?"
  ).run(amount, req.session.user.id);

  res.json({
    ok: true,
    transactionId: Number(transaction.lastInsertRowid),
    reference,
    status: "pending"
  });
});

/* ADMIN: CREATE JOB */
app.post("/api/admin/jobs", admin, (req, res) => {
  const title = String(req.body.title || "").trim();
  const company = String(req.body.company || "").trim();
  const location = String(req.body.location || "").trim();
  const description = String(req.body.description || "").trim();

  if (!title || !company || !location || !description) {
    return res.status(400).json({
      error: "All job fields are required."
    });
  }

  const result = db
    .prepare(
      `INSERT INTO jobs(title,company,location,description)
       VALUES(?,?,?,?)`
    )
    .run(title, company, location, description);

  res.json({
    ok: true,
    id: Number(result.lastInsertRowid)
  });
});

/* HEALTH CHECK */
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "NovaFX",
    status: "online"
  });
});

/* WEBSITE */
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`NovaFX running on port ${PORT}`);
});
