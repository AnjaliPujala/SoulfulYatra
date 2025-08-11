require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path'); // ✅ added

const app = express();
app.use(cors());
app.use(express.json());

// Serve React frontend in production
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const User = require('./models/Users');
const connectDB = require('./database');

// Example API endpoint
app.get('/get-user', async (req, res) => {
  const { email, phone } = req.query;

  if (!email || !phone) {
    return res.status(400).json({ error: "Email and phone are required" });
  }

  try {
    const user = await User.findOne({ email, phone: phone.toString() });
    if (user) {
      return res.json({ user, message: "User already exists" });
    }
    return res.json({ message: "User not found" });
  } catch (error) {
    console.error("Error fetching user:", error.stack);
    return res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Register user
app.post('/register', async (req, res) => {
  const { name, email, password, phone } = req.body;
  if (!name || !email || !password || !phone) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      phone,
      password: hashedPassword,
    });

    await newUser.save();

    const token = jwt.sign({ email }, process.env.TOKEN_KEY, { expiresIn: '1h' });

    res.status(201).json({
      user: { name, email, phone },
      token,
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post('/valid-login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ email }, process.env.TOKEN_KEY, { expiresIn: '1h' });

    res.json({
      message: "Login successful",
      user: { name: user.name, email: user.email, phone: user.phone },
      token,
    });
  } catch (error) {
    console.error("Error validating login:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Start server after DB connects
connectDB().then(() => {
  const PORT = process.env.PORT || 5000; // ✅ dynamic port for Azure
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
});
