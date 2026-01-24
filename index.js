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
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors({
  origin: "http://localhost:3000", // Adjust frontend origin
  credentials: true,
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Session middleware (required for Passport)
app.use(session({
  secret: process.env.SESSION_SECRET || "your-session-secret",
  resave: false,
  saveUninitialized: true,
}));

// Initialize Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// MySQL connection
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

connection.connect(err => {
  if (err) {
    console.error("Error connecting to database:", err);
    process.exit(1);
  }
  console.log("Connected to MySQL database.");
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

// Passport serialize/deserialize user
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// Configure Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID || "YOUR_GOOGLE_CLIENT_ID",
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || "YOUR_GOOGLE_CLIENT_SECRET",
    callbackURL: "http://localhost:5001/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    // TODO: Save or find user in your database here
    return done(null, profile);
  }
));

// Root route - serves login page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// ---------------------- SIGNUP WITH 2FA ----------------------
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: true, message: "Please provide all fields" });
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: true, message: "Invalid email format" });
  }

  try {
    const [existingUser] = await connection.promise().query(
      "SELECT * FROM user WHERE email = ?",
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({ error: true, message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    await connection.promise().query(
      "INSERT INTO user (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    // Generate 2FA secret
    const secret = speakeasy.generateSecret({ name: `YourApp (${email})` });

    // Store 2FA secret in DB
    await connection.promise().query(
      "UPDATE user SET twofa_secret = ? WHERE email = ?",
      [secret.base32, email]
    );

    // Generate QR code for authenticator apps
    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) {
        return res.status(500).json({ error: true, message: "QR code generation failed" });
      }

      return res.status(201).json({
        message: "User registered successfully!",
        qrCode: data_url,
        secret: secret.base32,
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: true, message: "Signup failed" });
  }
});

// ---------------------- LOGIN WITH 2FA ----------------------
app.post("/login", async (req, res) => {
  const { email, password, token } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: true, message: "Email and password are required" });
  }

  try {
    const [results] = await connection.promise().query("SELECT * FROM user WHERE email = ?", [email]);

    if (results.length === 0) {
      return res.status(401).json({ error: true, message: "User not found" });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: true, message: "Invalid password"});
    }

  

    // Create JWT token
    const jwtToken = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Set cookie (adjust options for production HTTPS)
    res.cookie("auth_token", jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 3600000, // 1 hour
    });

    res.status(200).json({
      message: "Login successful",
      user: { username: user.username, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: true, message: "Login failed" });
  }
});

// ---------------------- AUTH MIDDLEWARE ----------------------
const authenticateJWT = (req, res, next) => {
  const cookieHeader = req.headers.cookie || "";
  const cookies = Object.fromEntries(
    cookieHeader.split("; ").map((c) => {
      const [key, v] = c.split("=");
      return [key, v];
    })
  );

  const token = cookies["auth_token"];

  if (!token) {
    return res.status(403).json({ error: true, message: "Access denied" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: true, message: "Invalid token" });
    }

    req.user = user;
    next();
  });
};

// ---------------------- PLACE ORDER ----------------------
app.post("/api/placeorder", authenticateJWT, (req, res) => {
  const { cart, totalAmount } = req.body;

  if (!cart || !totalAmount || !Array.isArray(cart) || cart.length === 0) {
    return res.status(400).json({ message: "Invalid order data" });
  }

  const userId = req.user.id;
  const orderId = `ORD-${Date.now()}`;
  const orderDate = new Date().toISOString().split("T")[0];
  const deliveryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    .toISOString()
    .split("T")[0];
  const itemsJson = JSON.stringify(cart);

  const query = `
    INSERT INTO orders (order_id, user_id, order_date, delivery_date, total_payment, items)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  connection.query(
    query,
    [orderId, userId, orderDate, deliveryDate, totalAmount, itemsJson],
    (err) => {
      if (err) {
        console.error("Error inserting order:", err);
        return res.status(500).json({ message: "Failed to place order" });
      }

      res.status(200).json({
        message: "Order placed successfully!",
        orderId,
      });
    }
  );
});

// ---------------------- GOOGLE OAUTH ROUTES ----------------------

// Start OAuth flow
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })
);

// OAuth callback - redirect to DailyCart.html with flag
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/DailyCart.html?justLoggedIn=true');
  }
);

// Protect DailyCart route
app.get('/DailyCart.html', (req, res) => {
  if (req.isAuthenticated()) {
    res.sendFile(path.join(__dirname, "public", "DailyCart.html"));
  } else {
    res.redirect('/login');
  }
});

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login');
  });
});

// Serve other frontend pages
app.get("/order.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "order.html"));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});