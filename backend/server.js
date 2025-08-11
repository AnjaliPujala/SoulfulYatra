require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../build')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../build', 'index.html'));
});

const User = require('./models/Users');
const connectDB = require('./database');
app.get('/get-user', async (req, res) => {
  const { email, phone } = req.query;

  console.log('GET /get-user called with:', { email, phone });

  if (!email || !phone) {
    return res.status(400).json({ error: "Email and phone are required" });
  }

  try {
    const user = await User.findOne({ email, phone: phone.toString() });
    console.log('Found user:', user);
    if (user) {
      return res.json({ user, message: "User already exists" });
    }
    return res.json({ message: "User not found" });
  } catch (error) {
    console.error("Error fetching user:", error.stack);
    return res.status(500).json({ error: "Server error", details: error.message });
  }
});



// Register user with hashed password
app.post('/register', async (req, res) => {
  const { name, email, password, phone } = req.body;
  if (!name || !email || !password || !phone) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // Check if user exists
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

    // Create JWT token
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

// Login validation with password check
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

// Start server only after DB connects
connectDB().then(() => {
  app.listen(5000, () => {
    console.log("Server listening on port 5000");
  });
});
