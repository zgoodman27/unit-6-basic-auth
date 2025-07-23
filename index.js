// Your code goes here
// import necessary modules
const express = require("express");
const User = require("./userModel.js");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

// load environment variables
dotenv.config();

// create an instance of express
const app = express();

// Set the port from environment variables or default to 8080
const PORT = process.env.PORT || 8080;
const MONGO = process.env.MONGODB;
const SALT = parseInt(process.env.SALT) || 10;

// Middleware to parse JSON request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Connect to MongoDB
mongoose.connect(`${MONGO}/basicAuth`);
const db = mongoose.connection;
db.once("open", () => {
  console.log(`connected: ${MONGO}`);
});

// create login route
app.post("/login", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;

    // find the user by username
    const userObj = await User.findOne({ username });
    console.log("User Object: ", userObj);
    if (!userObj) {
      return res.status(404).send("User not found.");
    }

    bcrypt.compare(password, userObj.password, (err, result) => {
      if (err || !result) {
        return res.status(403).send("Access denied");
      } else {
        // issue token
        const token = jwt.sign({ id: userObj._id }, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });
        res.redirect(`/dashboard/${userObj.username}`);
      }
    });
  } catch (error) {
    console.error("Error occured during login: ", error);
    res.status(500).send("Internal server error");
  }
});

// create the signup route
app.post("/signup", async (req, res) => {
  try {
    let saltRounds = SALT;
    bcrypt.hash(req.body.password, saltRounds, async (err, hash) => {
      if (err) {
        return res.status(500).send("Error hashing password");
      }
      let userDoc = {
        username: req.body.username,
        password: hash,
      };
      let user = new User(userDoc);
      await user.save();
      res.redirect("/");
    });
  } catch (error) {
    console.error("Error occured during signup: ", error);
    res.status(500).send("Internal server error");
  }
});

//create the dashboard route
app.get("/dashboard/:username", (req, res) => {
res.sendFile(__dirname + "/public/dashboard.html");
});

// listen on the specified port
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
