const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5001;

/* ================= MIDDLEWARE ================= */

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      sameSite: "none",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* ================= DATABASE (POSTGRES) ================= */

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
});

pool
  .connect()
  .then(() => console.log("✅ PostgreSQL connected"))
  .catch((err) => {
    console.error("❌ PostgreSQL connection failed", err);
    process.exit(1);
  });

/* ================= AUTH CONFIG ================= */

const JWT_SECRET = process.env.JWT_SECRET;

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
    },
    (accessToken, refreshToken, profile, done) => done(null, profile)
  )
);

/* ================= ROUTES ================= */

app.get("/", (req, res) => {
  res.send("DailyCart Backend is running 🚀");
});

/* ---------- SIGNUP ---------- */
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const { rows } = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (rows.length > 0)
      return res.status(409).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword]
    );

    const secret = speakeasy.generateSecret({ name: `DailyCart (${email})` });

    await pool.query(
      "UPDATE users SET twofa_secret = $1 WHERE email = $2",
      [secret.base32, email]
    );

    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

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
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE email = $1",
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
      JWT_SECRET,
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

  jwt.verify(token, JWT_SECRET, (err, user) => {
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
    await pool.query(
      `INSERT INTO orders (order_id, user_id, total_payment, items)
       VALUES ($1, $2, $3, $4)`,
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

/* ================= START ================= */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
