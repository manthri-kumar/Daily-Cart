const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cookieParser = require("cookie-parser");
const mysql = require("mysql2/promise");
require("dotenv").config();

/* ================= APP INIT ================= */
const app = express();

/* ================= BASIC SETUP ================= */
app.set("trust proxy", 1);

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

/* ================= SESSION ================= */
app.use(
  session({
    name: "dailycart.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: true,
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* ================= MYSQL (RAILWAY) ================= */
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
  waitForConnections: true,
  connectionLimit: 10,
});

(async () => {
  try {
    const conn = await db.getConnection();
    console.log("✅ MySQL connected");
    conn.release();
  } catch (err) {
    console.error("❌ MySQL error:", err);
    process.exit(1);
  }
})();

/* ================= AUTH CONFIG ================= */
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
  )
);

/* ================= ROUTES ================= */
app.get("/", (req, res) => {
  res.send("DailyCart Backend is running 🚀");
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

/* ---------- SIGNUP ---------- */
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const [rows] = await db.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (rows.length > 0)
      return res.status(409).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const secret = speakeasy.generateSecret({ name: `DailyCart (${email})` });
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    await db.query(
      "INSERT INTO users (username, email, password, twofa_secret) VALUES (?, ?, ?, ?)",
      [username, email, hashedPassword, secret.base32]
    );

    res.status(201).json({ message: "Signup successful", qrCode });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Signup failed" });
  }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0)
      return res.status(401).json({ message: "User not found" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match)
      return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 3600000,
    });

    res.json({
      message: "Login successful",
      user: { email: user.email, username: user.username },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* ---------- JWT MIDDLEWARE ---------- */
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(403).json({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

/* ---------- PLACE ORDER ---------- */
app.post("/api/placeorder", authenticateJWT, async (req, res) => {
  const { cart, totalAmount } = req.body;
  const orderId = `ORD-${Date.now()}`;

  try {
    await db.query(
      "INSERT INTO orders (order_id, user_id, total_payment, items) VALUES (?, ?, ?, ?)",
      [orderId, req.user.id, totalAmount, JSON.stringify(cart)]
    );

    res.json({ message: "Order placed", orderId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Order failed" });
  }
});

/* ---------- GOOGLE AUTH ---------- */
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect(`${process.env.FRONTEND_URL}/DailyCart.html`);
  }
);

/* ================= START SERVER (ONLY ONCE) ================= */
const PORT = process.env.PORT || 8080;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
