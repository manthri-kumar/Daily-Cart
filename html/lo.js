const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());
app.use(
  session({
    secret: "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",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: "76773692775-35giisaujs0jemce27k8jtih12pq3k1g.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("http://localhost:5500/DailyCart.html");
  }
);

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

app.listen(5001, () => {
  console.log("Server started on port 5001");
});
