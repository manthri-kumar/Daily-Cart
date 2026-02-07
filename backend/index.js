const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cookieParser = require("cookie-parser");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 8080;

/* ================= SAFETY ================= */
if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET missing");
  process.exit(1);
}

/* ================= TRUST PROXY ================= */
app.set("trust proxy", 1);

/* ================= CORS (VERY IMPORTANT) ================= */
app.use(
  cors({
    origin: [
      "http://localhost:5500",
      "http://127.0.0.1:5500",
      "https://daily-cart-iqh8.vercel.app",
    ],
    credentials: true,
  })
);

/* ================= MIDDLEWARE ================= */
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

/* ================= DATABASE ================= */
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
});

/* ================= PASSPORT ================= */
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;

        const [rows] = await db.query(
          "SELECT * FROM users WHERE email = ?",
          [email]
        );

        if (rows.length === 0) {
          await db.query(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            [profile.displayName, email, "GOOGLE_AUTH"]
          );
        }

        return done(null, { email });
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

/* ================= ROUTES ================= */
app.get("/", (req, res) => {
  res.send("DailyCart Backend is running 🚀");
});

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const [rows] = await db.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (rows.length > 0)
      return res.status(409).json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashed]
    );

    res.status(201).json({ message: "Signup successful" });
  } catch {
    res.status(500).json({ message: "Signup failed" });
  }
});

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
  });

  res.json({ message: "Login successful", user });
});

/* ================= GOOGLE ================= */
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("https://daily-cart-iqh8.vercel.app/DailyCart.html");
  }
);

/* ================= START ================= */
app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});
