const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require("cookie-session");

require("dotenv").config();

/**************** Constants *******************/

const PORT = 3000;

const CONFIG = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: CONFIG.CLIENT_ID,
  clientSecret: CONFIG.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  // console.log(`Google Profile: ${JSON.stringify(profile)}`);
  console.log("verifyCallBack!");
  done(null, profile);
}

/**************** Passport.js Stuff *******************/
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session to the cookie
passport.serializeUser((user, done) => {
  console.log("Serialized User!");
  done(null, user.id);
});

// Read the session from the cookie
passport.deserializeUser((id, done) => {
  console.log("Derialized User!");
  done(null, id);
});

/******************************************************/

/**************** Middleware *******************/
const app = express();

app.use(helmet());
app.use(
  cookieSession({
    name: "session", // session name
    maxAge: 24 * 60 * 60 * 1000, // expires in 24 hours
    keys: [CONFIG.COOKIE_KEY_1, CONFIG.COOKIE_KEY_2], // needs to be signed
  })
);
app.use(passport.initialize());
app.use(passport.session());

/**********************************************/

/**************** oAuth Steps + Minimal Routes *******************/

function checkLoggedIn(req, res, next) {
  console.log("current user is: ", req.user);
  const isLoggedIn = req.isAuthenticated() && req.user; // TODO
  if (!isLoggedIn) {
    return res.status(401).json({
      error: "You must log in!",
    });
  }
  console.log("checkLoggedIn!");
  next();
}

// 1st step
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

// callback URL to send authorization code
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("Google called us back!");
  }
);

// logout functionality
app.get("/auth/logout", (req, res) => {
  req.logout();
  return res.redirect("/");
});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Your personal secret value is 42!");
});

app.get("/failure", (req, res) => {
  return res.send("Failed to login.");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`listening on ${PORT}...`);
  });
