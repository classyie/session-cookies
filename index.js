import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(session({
  secret: "TOPSECRET",
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000*60 },
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "123456",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

/* This code snippet is defining a route handler for the GET request to '/secrets'. Here's what it
does: */
app.get('/secrets', (req, res)=>{
/* This code snippet is checking if the user is authenticated or logged in. Here's what it does: */
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }
  else{
    res.redirect('/login');
  }
});

app.get('/logout', (req, res)=>{
  req.logout( function(err){
    if(err)
      return next(err);
    res.redirect('/');
  } );
});
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) returning *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err)=>{
            console.log("Success", user);
            res.redirect('/secrets');
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

passport.use(new Strategy (async function verify(username, password, cb){
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, valid) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        } else {
          if (valid) {
            return cb(null, user);
          } else {
            res.send("Incorrect Password");
            return cb(null, false);
          }
        }
      });
    } else {
      // res.send("User not found");
      return cb("user not found")
    }
  } catch (err) {
    console.log(err);
  }
}));

passport.serializeUser((user, cb)=>{
  cb(null, user);
});
passport.deserializeUser((user, cb)=>{
  cb(null, user);
});
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
