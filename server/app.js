require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public"));
app.set("view engine", "ejs");

mongoose.connect(process.env.DATABASE_URL);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } }, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        res.render("secrets", { usersSecrets: foundUser });
      }
    }
  });
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/logout", (req, res) => {
  req.session.destroy(function (err) {
    res.redirect("/"); //Inside a callback… bulletproof!
  });
});

app.get("/submit", (req, res) => {
  res.render("submit");
});

app.post("/submit", async (req, res) => {
  const storeSecrets = req.body.secret;
  if (!mongoose.Types.ObjectId.isValid(req.user._id)) {
    return res.json("User not Found");
  }
  try {
    await User.findByIdAndUpdate(req.user._id, {
      $set: { secret: storeSecrets },
    });
    res.redirect("/secrets");
  } catch (error) {
    res.status(400).json(error);
  }
});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username, secret: "" },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});
//this will automatically search and authenticate from the database user is registerd or not.
app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.listen(3000, function () {
  console.log("server started at port 3000");
});
