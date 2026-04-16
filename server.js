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
// 🛑 حماية من انهيار السيرفر
// =========================
process.on("uncaughtException", (err) => {
  console.log("Uncaught Exception:", err);
});

process.on("unhandledRejection", (err) => {
  console.log("Unhandled Rejection:", err);
});

// =========================
// 🔗 MongoDB Connection (مُحسن)
// =========================
const MONGO_URL = process.env.MONGO_URL;

if (!MONGO_URL) {
  console.log("❌ MONGO_URL is missing!");
} else {
  mongoose.connect(MONGO_URL)
    .then(() => console.log("MongoDB Connected 🚀"))
    .catch(err => console.log("DB Error:", err));
}

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
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret");
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
    const exists = await User.findOne({ username: req.body.username });

    if (exists) {
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
    console.log(err);
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
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || "secret",
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
// 🔒 Dashboard
// =========================
app.get("/dashboard", verifyToken, (req, res) => {
  res.json({
    message: "Welcome to dashboard 🔐",
    userId: req.user.id,
    username: req.user.username
  });
});

// =========================
// 🌐 Test Route
// =========================
app.get("/", (req, res) => {
  res.send("API working 🚀");
});

// =========================
// 🚀 Start Server (Railway Safe)
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
