console.log("🔥 REAL SERVER FILE IS RUNNING 🔥");
console.log("🔥 SERVER STARTING...");

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// =========================
// 🔗 MongoDB Connection
// =========================
mongoose.connect("mongodb+srv://admin:moustapha%401981@cluster0.8nrej3b.mongodb.net/myapp?retryWrites=true&w=majority")
  .then(() => console.log("MongoDB Connected 🚀"))
  .catch(err => console.log("DB Error:", err));

// =========================
// 👤 User Model
// =========================
const User = mongoose.model("User", {
  username: String,
  password: String
});

// =========================
// 🔐 JWT Middleware
// =========================
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, "secret");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// =========================
// 🟢 Register
// =========================
app.post("/register", async (req, res) => {
  try {
    const existingUser = await User.findOne({ username: req.body.username });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashed = await bcrypt.hash(req.body.password, 10);

    const user = new User({
      username: req.body.username,
      password: hashed
    });

    await user.save();

    res.json({ message: "User created" });
  } catch (err) {
    res.status(500).json({ message: "Error registering user" });
  }
});

// =========================
// 🔵 Login
// =========================
app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(req.body.password, user.password);

    if (!match) {
      return res.status(401).json({ message: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username }, // 🔥 أضفنا username هنا
      "secret",
      { expiresIn: "1h" }
    );

    res.json({
      token,
      username: user.username // 🔥 نرجعه للفرونت
    });

  } catch (err) {
    res.status(500).json({ message: "Login error" });
  }
});

// =========================
// 🔒 Protected Route
// =========================
app.get("/dashboard", verifyToken, (req, res) => {
  res.json({
    message: "Welcome to dashboard 🔐",
    userId: req.user.id,
    username: req.user.username // 🔥 مهم
  });
});

// =========================
// 🌐 Test Route
// =========================
app.get("/", (req, res) => {
  res.send("API working 🚀");
});

// =========================
// 🚀 Start Server
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

