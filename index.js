const express = require("express");
const mysql = require("mysql2");
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
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5001;

/* ===================== MIDDLEWARE ===================== */
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* ===================== SESSION ===================== */
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
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

/* ===================== MYSQL (AIVEN SAFE) ===================== */
const connection = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false
  },
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

/* ===================== JWT ===================== */
const JWT_SECRET = process.env.JWT_SECRET;

/* ===================== ROUTES ===================== */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ---------- SIGNUP WITH 2FA ---------- */
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "Please provide all fields" });
  }

  try {
    const [existingUser] = await connection.promise().query(
      "SELECT id FROM user WHERE email = ?",
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.promise().query(
      "INSERT INTO user (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    const secret = speakeasy.generateSecret({ name: `DailyCart (${email})` });

    await connection.promise().query(
      "UPDATE user SET twofa_secret = ? WHERE email = ?",
      [secret.base32, email]
    );

    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    res.status(201).json({
      message: "User registered successfully!",
      qrCode,
    });

  } catch (err) {
    console.error(err);
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
    const [users] = await connection.promise().query(
      "SELECT * FROM user WHERE email = ?",
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 3600000,
    });

    res.json({
      message: "Login successful",
      user: { username: user.username, email: user.email },
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* ---------- JWT AUTH MIDDLEWARE ---------- */
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.auth_token;

  if (!token) {
    return res.status(403).json({ message: "Access denied" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
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
    console.error(err);
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
app.get("/DailyCart.html", (req, res) => {
  if (req.isAuthenticated()) {
    res.sendFile(path.join(__dirname, "public", "DailyCart.html"));
  } else {
    res.redirect("/login");
  }
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/login");
  });
});

app.get("/order.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "order.html"));
});

/* ===================== START SERVER ===================== */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
