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
// ⚠️ ENV VARIABLES CHECK
// =========================
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URL || !JWT_SECRET) {
  console.log("❌ Missing ENV variables (MONGO_URL or JWT_SECRET)");
  process.exit(1);
}

// =========================
// 🔗 MongoDB Connection
// =========================
mongoose.connect(MONGO_URL)
  .then(() => console.log("MongoDB Connected 🚀"))
  .catch(err => {
    console.log("DB Error:", err);
    process.exit(1);
  });

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
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// =========================
// 🟢 REGISTER
// =========================
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    const exists = await User.findOne({ username });

    if (exists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      password: hashed
    });

    await user.save();

    res.json({ message: "User created ✅" });

  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Register error" });
  }
});

// =========================
// 🔵 LOGIN
// =========================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      username: user.username
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Login error" });
  }
});

// =========================
// 🔒 DASHBOARD
// =========================
app.get("/dashboard", verifyToken, (req, res) => {
  res.json({
    message: "Welcome to dashboard 🔐",
    userId: req.user.id,
    username: req.user.username
  });
});

// =========================
// 🌐 TEST ROUTE
// =========================
app.get("/", (req, res) => {
  res.send("API WORKING 🚀");
});

// =========================
// 🚀 START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});