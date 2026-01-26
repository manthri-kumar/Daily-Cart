const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5001;

/* ===================== MIDDLEWARE ===================== */

// ✅ FIXED CORS (VERY IMPORTANT)
app.use(cors({
  origin: "https://daily-cart-hqyw.onrender.com",
  credentials: true,
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ✅ Serve frontend files
app.use(express.static(path.join(__dirname, "public")));

/* ===================== SESSION ===================== */
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,          // REQUIRED on Render (HTTPS)
    sameSite: "lax",
  }
}));

/* ===================== PASSPORT ===================== */
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${process.env.BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));

/* ===================== MYSQL ===================== */
const connection = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10,
});

connection.getConnection((err, conn) => {
  if (err) {
    console.error("❌ MySQL connection failed:", err);
    process.exit(1);
  }
  console.log("✅ Connected to MySQL database");
  conn.release();
});

connection.promise()
  .query("SELECT DATABASE() AS db")
  .then(([rows]) => console.log("CONNECTED DATABASE:", rows))
  .catch(console.error);

connection.promise()
  .query("SHOW TABLES")
  .then(([rows]) => console.log("TABLES SEEN BY BACKEND:", rows))
  .catch(console.error);

/* ===================== JWT ===================== */
const JWT_SECRET = process.env.JWT_SECRET;

/* ===================== ROUTES ===================== */

/* ✅ ROOT FIX (NO MORE Cannot GET /) */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ---------- SIGNUP ---------- */
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const [existing] = await connection.promise().query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.promise().query(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "Signup successful" });

  } catch (err) {
    console.error("❌ Signup error:", err.sqlMessage || err);
    res.status(500).json({ message: "Signup failed" });
  }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    const [rows] = await connection.promise().query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 3600000,
    });

    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (err) {
    console.error("❌ Login error:", err.sqlMessage || err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* ---------- JWT MIDDLEWARE ---------- */
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.auth_token;

  if (!token) {
    return res.status(403).json({ message: "Access denied" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

/* ---------- PLACE ORDER ---------- */
app.post("/api/placeorder", authenticateJWT, async (req, res) => {
  const { cart, totalAmount } = req.body;

  if (!Array.isArray(cart) || cart.length === 0 || !totalAmount) {
    return res.status(400).json({ message: "Invalid order data" });
  }

  const orderId = `ORD-${Date.now()}`;
  const orderDate = new Date().toISOString().split("T")[0];

  try {
    await connection.promise().query(
      `INSERT INTO orders
      (order_id, user_id, order_date, delivery_date, total_payment, items)
      VALUES (?, ?, ?, ?, ?, ?)`,
      [
        orderId,
        req.user.id,
        orderDate,
        orderDate,
        totalAmount,
        JSON.stringify(cart),
      ]
    );

    res.json({ message: "Order placed successfully!", orderId });

  } catch (err) {
    console.error("Order error:", err);
    res.status(500).json({ message: "Failed to place order" });
  }
});

/* ---------- GOOGLE OAUTH ---------- */
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/DailyCart.html?justLoggedIn=true");
  }
);

/* ---------- PAGES ---------- */
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/DailyCart.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "DailyCart.html"));
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/login");
  });
});

/* ===================== START SERVER ===================== */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
