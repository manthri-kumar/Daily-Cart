require("dotenv").config();

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

const app = express();
const PORT = process.env.PORT || 8080;

/* ================= SAFETY CHECK ================= */
if (!process.env.JWT_SECRET || !process.env.SESSION_SECRET) {
  console.error("❌ Missing secrets");
  process.exit(1);
}

/* ================= BASIC SETUP ================= */
app.set("trust proxy", 1);

/* ================= CORS ================= */
app.use(
  cors({
    origin: [
      "https://daily-cart-iqh8.vercel.app",
      "http://localhost:5500",
    ],
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

/* ================= HEALTH CHECK ================= */
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

/* ================= MYSQL ================= */
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

/* ================= PASSPORT ================= */
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (_, __, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const username = profile.displayName;

        const [rows] = await db.query(
          "SELECT id FROM users WHERE email = ?",
          [email]
        );

        let userId;

        if (rows.length === 0) {
          const [result] = await db.query(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            [username, email, "GOOGLE_AUTH"]
          );
          userId = result.insertId;
        } else {
          userId = rows[0].id;
        }

        done(null, { id: userId, email });
      } catch (err) {
        done(err, null);
      }
    }
  )
);

/* ================= ROUTES ================= */
app.get("/", (_, res) => {
  res.send("DailyCart Backend is running 🚀");
});

/* ---------- SIGNUP ---------- */
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  const [rows] = await db.query(
    "SELECT id FROM users WHERE email = ?",
    [email]
  );

  if (rows.length > 0)
    return res.status(409).json({ message: "Email already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const secret = speakeasy.generateSecret({ name: `DailyCart (${email})` });
  const qrCode = await QRCode.toDataURL(secret.otpauth_url);

  await db.query(
    "INSERT INTO users (username, email, password, twofa_secret) VALUES (?, ?, ?, ?)",
    [username, email, hashed, secret.base32]
  );

  res.status(201).json({ message: "Signup successful", qrCode });
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM users WHERE email = ?",
    [email]
  );

  if (!rows.length)
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
});

/* ---------- JWT MIDDLEWARE ---------- */
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

/* ---------- GOOGLE AUTH ---------- */
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 3600000,
    });

    // ✅ IMPORTANT FIX
    res.redirect(
      "https://daily-cart-iqh8.vercel.app/index.html?googleLogin=true"
    );
  }
);

app.listen(PORT, "0.0.0.0", () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
