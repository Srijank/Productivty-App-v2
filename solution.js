import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session, { Session } from "express-session";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
   secret:"Secured",
   resave :false,
   saveUninitialized:true

}));
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "world",
  password: "191023",
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

app.get("/secrets", (req, res) => {
   console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM testuser WHERE users = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      
      res.redirect('/login');
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          await db.query(
            "INSERT INTO testuser (users, passwords) VALUES ($1, $2)",
            [email, hash]
          );
          res.redirect('/secrets');
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local",{
successRedirect:'/secrets',
failureRedirect:'/login'
}
));

passport.use(
  new Strategy(async function verify(username,password,cb){
    try{
      const result = await db.query("SELECT * FROM testuser WHERE users=($1)",[username]);
    
    if(result.rows.length>0){
        const user = result.rows[0];
        const userpassword = user.passwords;
        bcrypt.compare(password,userpassword,(err,valid)=>{
          if(err){
            return cb(err)
          }
          else{
            if(valid){
            return cb(null,user);
          }
          else {
            return cb(null,false);
          }
        }
        });
    }
    else {
      return cb("user not found");
    }
  }
    catch{
         console.log(err);
    }
  })
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
