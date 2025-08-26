require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const OpenAI = require('openai');
const SavedTrip = require('./models/SavedTrip');
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? 'https://soulful-yatra.netlify.app'
    : 'http://localhost:3000',
  credentials: true
}));


// MongoDB connection
let db;
const connectDB = async () => {
  try {
    const client = await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB');
    db = client.connection.db;
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
};


// User model
const User = require('./models/Users');

// ------------------- AUTH -------------------
app.get('/check-auth', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ loggedIn: false });

  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    return res.json({ loggedIn: true, email: decoded.email });
  } catch (err) {
    return res.json({ loggedIn: false });
  }
});

// Register
app.post('/register', async (req, res) => {
  const { name, email, password, phone } = req.body;
  if (!name || !email || !password || !phone) {
    return res.status(400).json({ error: "All fields are required" });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, phone, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ email }, process.env.TOKEN_KEY, { expiresIn: '1h' });

    res.status(201).json({
      user: { name, email, phone },
      token
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ error: "Server error" });
  }
});
let otpStore = {}; // { email: { otp: 123456, expires: Date } }

// ------------------- Endpoints -------------------

// Save OTP in backend
app.post('/forgot-password', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }

  try {
    const user = await User.findOne({ email: email });
    if (!user) return res.status(400).json({ error: 'Email not registered' });

    otpStore[email] = { otp: parseInt(otp), expires: Date.now() + 10 * 60 * 1000 }; // 10 mins
    res.json({ message: 'OTP saved on server' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset Password using OTP
app.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword)
    return res.status(400).json({ error: 'Email, OTP and new password are required' });

  const record = otpStore[email];
  if (!record) return res.status(400).json({ error: 'No OTP request found' });

  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.status(400).json({ error: 'OTP expired. Try again' });
  }

  if (parseInt(otp) !== record.otp)
    return res.status(400).json({ error: 'Invalid OTP' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });

    // Hash the new password before saving
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    await user.save();
    delete otpStore[email];

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error while resetting password' });
  }
});
// Login
const isProd = process.env.NODE_ENV === 'production';
app.post('/valid-login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ email }, process.env.TOKEN_KEY, { expiresIn: '1h' });



    res.cookie('token', token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      maxAge: 3600000
    });


    res.json({
      message: "Login successful",
      user: { name: user.name, email: user.email, phone: user.phone }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});


// Token validation
const validateToken = (token) => {
  try { return jwt.verify(token, process.env.TOKEN_KEY); }
  catch { return null; }
};

//logout
app.post('/logout', (req, res) => {
  res.cookie('token', '', {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 0 // expire immediately
  });
  res.json({ message: 'Logged out successfully' });
});
// Protected route example
app.get('/home', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  const decoded = validateToken(token);
  if (!decoded) return res.status(401).json({ error: "Invalid token" });

  res.json({ message: "Welcome home!", email: decoded.email });
});

// ------------------- PLACES -------------------
async function getLatLonFromName(name) {
  const url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(name)}&limit=1`;
  const response = await fetch(url, { headers: { 'User-Agent': 'PlaceFinder/1.0 (anjalipujala001@example.com)' } });
  if (!response.ok) throw new Error('Failed to fetch from Nominatim');
  const data = await response.json();
  if (data.length === 0) return null;
  return { lat: parseFloat(data[0].lat), lon: parseFloat(data[0].lon), boundingbox: data[0].boundingbox };
}

// Get places from MongoDB
let placesCache = null;
app.get('/get-places', async (req, res) => {
  if (placesCache) return res.json({ places: placesCache });
  try {
    const collection = db.collection('places');
    const places = await collection.find({}).toArray();
    if (!places.length) return res.status(404).json({ message: 'No places found' });
    placesCache = places;
    res.json({ places });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
// Get places by state using OpenTripMap
async function getPlacesByName(name) {
  const apiKey = process.env.OPEN_TRIP_MAP_API_KEY;
  if (!apiKey) throw new Error('OpenTripMap API key is missing');

  const geocodeData = await getLatLonFromName(name);
  if (!geocodeData) return [];

  const [lat_min, lat_max, lon_min, lon_max] = geocodeData.boundingbox.map(Number);

  const url = `https://api.opentripmap.com/0.1/en/places/bbox?lon_min=${lon_min}&lat_min=${lat_min}&lon_max=${lon_max}&lat_max=${lat_max}&apikey=${apiKey}&limit=50`;

  try {
    const response = await fetch(url);

    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      console.error('Failed to parse JSON from OpenTripMap:', text);
      return [];
    }

    return data.features || [];
  } catch (err) {
    console.error('Error fetching places:', err);
    return [];
  }
}
// get-place-image
app.get('/get-place-image', async (req, res) => {
  const { xid } = req.query;
  const apiKey = process.env.OPEN_TRIP_MAP_API_KEY;

  if (!xid) return res.status(400).json({ error: 'XID is required' });

  try {
    const response = await fetch(`https://api.opentripmap.com/0.1/en/places/xid/${xid}?apikey=${apiKey}`);
    const text = await response.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      console.error(`Invalid JSON for XID ${xid}:`, text);
      return res.status(404).json({ error: 'Place not found or no data available' });
    }

    res.json({ data });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// API endpoint
app.get('/get-places-by-name', async (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'State name is required' });

  try {
    const places = await getPlacesByName(name);
    if (!places.length) return res.status(404).json({ message: 'No places found' });
    res.json({ places });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// ------------------- ITINERARY -------------------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.post('/generate-itinerary', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    if (!validateToken(token)) return res.status(401).json({ error: 'Invalid token' });

    const { destination, days, interests } = req.body;
    if (!destination || !days) return res.status(400).json({ error: 'Destination and days are required' });

    const prompt = `
Plan a ${days}-day trip to ${destination} for a user interested in ${interests || 'general activities'}.
Provide the response in plain text only, without Markdown, asterisks, or headers.
Include daily schedule, travel tips, and approximate durations.
`;

    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: 'You are a helpful travel assistant.' },
        { role: 'user', content: prompt }
      ],
      max_tokens: 1000
    });

    const itinerary = response.choices[0].message.content;
    res.json({ itinerary });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to generate itinerary' });
  }
});

// ------------------- HOTELS & FOODS -------------------
const hotelsCache = {};
const restaurantsCache = {};

const fetchPlacesByRadius = async (lat, lon, radius, kinds, limit, cache) => {
  const cacheKey = `${lat}-${lon}-${radius}-${kinds}`;
  if (cache[cacheKey] && Date.now() - cache[cacheKey].timestamp < 10 * 60 * 1000) {
    return cache[cacheKey].data;
  }

  const apiKey = process.env.OPEN_TRIP_MAP_API_KEY;
  const url = `https://api.opentripmap.com/0.1/en/places/radius?radius=${radius}&lon=${lon}&lat=${lat}&kinds=${kinds}&limit=${limit}&apikey=${apiKey}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to fetch ${kinds}`);
  const data = await response.json();
  cache[cacheKey] = { data: data.features || [], timestamp: Date.now() };
  return cache[cacheKey].data;
};

app.get('/get-hotels', async (req, res) => {
  const token = req.cookies.token;
  if (!token || !validateToken(token)) return res.status(401).json({ error: 'Unauthorized' });

  const { lat, lon, radius = 10000 } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'lat & lon required' });

  try {
    const hotels = await fetchPlacesByRadius(lat, lon, radius, 'accomodations,hostels,guest_houses,other_hotels', 50, hotelsCache);
    res.json({ hotels });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch hotels' });
  }
});

app.get('/famous-restaurants', async (req, res) => {
  const token = req.cookies.token;
  if (!token || !validateToken(token)) return res.status(401).json({ error: 'Unauthorized' });

  const { lat, lon, radius = 10000 } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'lat & lon required' });

  try {
    const restaurants = await fetchPlacesByRadius(lat, lon, radius, 'foods', 10, restaurantsCache);
    res.json({ restaurants });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch restaurants' });
  }
});
//save trips


app.post('/save-trip', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    const email = decoded.email;

    const { destination, interests, tripData, days } = req.body;
    const daysNumber = Number(days);
    if (!destination || !tripData)
      return res.status(400).json({ error: 'Destination and trip data are required' });


    const existingTrip = await SavedTrip.findOne({ email, destination, days: daysNumber });
    if (existingTrip) {
      return res.status(400).json({ error: 'This trip is already saved!' });
    }


    await SavedTrip.create({ email, destination, days: daysNumber, interests, tripData });

    res.json({ message: 'Trip saved successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error saving trip' });
  }
});
//profile
app.get('/profile', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "No token provided" });
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    const user = await User.findOne({ email: decoded.email }).select('-password');
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ user });
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
});
//get saved trips
app.get("/get-saved-trips", async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    const trips = await SavedTrip.find({ email: decoded.email });

    res.json({ trips });
  } catch (err) {
    console.error("Error fetching saved trips:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ------------------- SERVER START -------------------
connectDB().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(err => console.error(err));

