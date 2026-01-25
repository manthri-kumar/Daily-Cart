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
const PORT = process.env.PORT || 10000;

/* =======================
   MIDDLEWARE
======================= */

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  secret: process.env.SESSION_SECRET || "session_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax"
  }
}));

app.use(passport.initialize());
app.use(passport.session());

/* =======================
   DATABASE CONNECTION
======================= */

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false
  }
});


connection.connect(err => {
  if (err) {
    console.error("❌ Database connection failed:", err);
    process.exit(1);
  }
  console.log("✅ Connected to MySQL database");
});

/* =======================
   AUTH CONFIG
======================= */

const JWT_SECRET = process.env.JWT_SECRET || "jwt_secret";

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BASE_URL}/auth/google/callback`
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

/* =======================
   ROUTES
======================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ---------- SIGNUP ---------- */

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  try {
    const [existing] = await connection.promise().query(
      "SELECT * FROM user WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
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
      message: "Signup successful",
      qrCode,
      secret: secret.base32
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Signup failed" });
  }
});

/* ---------- LOGIN ---------- */

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await connection.promise().query(
      "SELECT * FROM user WHERE email = ?",
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
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
      maxAge: 3600000
    });

    res.json({
      message: "Login successful",
      user: { username: user.username, email: user.email }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* ---------- JWT MIDDLEWARE ---------- */

const authenticateJWT = (req, res, next) => {
  const token = req.cookies.auth_token;

  if (!token) {
    return res.status(403).json({ message: "Unauthorized" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

/* ---------- PLACE ORDER ---------- */

app.post("/api/placeorder", authenticateJWT, (req, res) => {
  const { cart, totalAmount } = req.body;

  if (!cart || !Array.isArray(cart)) {
    return res.status(400).json({ message: "Invalid order data" });
  }

  const orderId = `ORD-${Date.now()}`;
  const orderDate = new Date().toISOString().split("T")[0];
  const deliveryDate = new Date(Date.now() + 7 * 86400000)
    .toISOString()
    .split("T")[0];

  connection.query(
    `INSERT INTO orders 
     (order_id, user_id, order_date, delivery_date, total_payment, items)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      orderId,
      req.user.id,
      orderDate,
      deliveryDate,
      totalAmount,
      JSON.stringify(cart)
    ],
    err => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Order failed" });
      }

      res.json({ message: "Order placed", orderId });
    }
  );
});

/* ---------- GOOGLE AUTH ---------- */

app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/DailyCart.html");
  }
);

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/login");
  });
});

/* =======================
   START SERVER
======================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
