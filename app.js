const express = require("express");
const app = express();
const port = 3000;
app.use(express.static("public"));

//authentication
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

//connecting ejs
const ejs = require("ejs");
app.set("view engine", "ejs");

//connecting body-parser
const bodyParser = require("body-parser");
app.use(bodyParser.urlencoded({ extended: true }));

//connecting mongoose with session
const mongoose = require("mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

app.use(
  session({
    //defining a session
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize()); //initialize a passport
app.use(passport.session()); //initialize a session

mongoose.connect("mongodb://127.0.0.1:27017/secretsDB");
// mongoose.set("useCreateIndex", true);

const usersSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

usersSchema.plugin(passportLocalMongoose); //to hash and salt our passport
usersSchema.plugin(findOrCreate);

const User = mongoose.model("User", usersSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID:
        "337871802814-he0ea9pedqlqevj548joh2q5nm9c9h3p.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (_accessToken, _refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//get requests
app.get("/", (req, res) => {
  res.render("home");
});
app.get("/register", (req, res) => {
  res.render("register");
});
app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/secrets", async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const foundUsers = await User.find({ secret: { $ne: null } });

      if (foundUsers && foundUsers.length > 0) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      } else {
        // No users with secrets found
        res.render("secrets", { usersWithSecrets: [] });
      }
    } else {
      res.redirect("/login");
    }
  } catch (err) {
    console.error(err);
    res.redirect("/login"); // Handle the error as per your requirements
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;

  try {
    // Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    const foundUser = await User.findById(req.user.id);

    if (foundUser) {
      foundUser.secret = submittedSecret;
      await foundUser.save();
      res.redirect("/secrets");
    }
  } catch (err) {
    console.error(err);
    res.redirect("/secrets"); // Handle the error as per your requirements
  }
});

//post requests
app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});
app.post("/login", async (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
