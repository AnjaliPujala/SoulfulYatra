require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const SavedTrip = require('./models/SavedTrip');
const app = express();
const OpenAI = require('openai');
const redisClient = require('./redisClient');
// Middleware
app.use(express.json());
app.use(cookieParser());
const fs = require('fs');
const uploadDir = './uploads';

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const allowedOrigins = [
  'http://localhost:3000',
  'https://soulful-yatra.netlify.app',
  'https://soulful-yatra-updated.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('CORS not allowed for this origin'), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

// MongoDB connection
const mongoURI = process.env.MONGO_URI;
let db;
const connectDB = async () => {
  try {
    const client = await mongoose.connect(mongoURI, {
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

// ------------------- AUTHENTICATION -------------------


async function getAuthenticatedUser(req, res = null) {
  let accessToken = null;

  // 1️⃣ Check Authorization header first
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    accessToken = authHeader.split(' ')[1];
  }

  // 2️⃣ Try verifying access token
  if (accessToken) {
    try {
      const payload = jwt.verify(accessToken, process.env.TOKEN_KEY);
      const user = await User.findById(payload.userId).select('-password');
      if (!user) return { user: null };
      return { user, authType: 'jwt' };
    } catch (err) {
      // If token expired, continue to check refresh token
      if (err.name !== 'TokenExpiredError') return { user: null };
    }
  }

  // 3️⃣ Check refresh token cookie
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) return { user: null };

  try {
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY);
    const user = await User.findById(payload.userId).select('-password');
    if (!user) return { user: null };

    // 4️⃣ Issue new access token if res is provided (optional)
    if (res) {
      const newAccessToken = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.TOKEN_KEY,
        { expiresIn: '1d' }
      );
      res.setHeader('x-access-token', newAccessToken); // send to frontend for memory storage
    }

    return { user, authType: 'jwt' };
  } catch (err) {
    return { user: null };
  }
}


// ------------------- AUTH ENDPOINTS -------------------

// Register

// Check authentication
app.get('/check-auth', async (req, res) => {
  try {
    const { user } = await getAuthenticatedUser(req, res); // res allows issuing new access token
    if (!user) return res.json({ loggedIn: false });

    res.json({ loggedIn: true, user });
  } catch (err) {
    console.error('Check auth error:', err);
    res.json({ loggedIn: false });
  }
});



// Check login status (legacy endpoint)
app.get('/check-login', async (req, res) => {
  try {
    const { user, authType } = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        loggedIn: false,
        error: 'No valid authentication found'
      });
    }

    return res.status(200).json({
      loggedIn: true,
      user: authType === 'oauth' ? user : { email: user.email }
    });
  } catch (err) {
    console.error('Check login error:', err);
    return res.status(500).json({
      loggedIn: false,
      error: 'Internal server error'
    });
  }
});

// ------------------- TRADITIONAL AUTH -------------------
let otpStore = {};

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



// Login
app.post('/valid-login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.TOKEN_KEY,
      { expiresIn: '1d' } // short-lived (better security)
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_KEY,
      { expiresIn: '7d' }
    );

    // 🛠 FIX 1: Cross-site compatible cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,       // Render uses HTTPS, must be true
      sameSite: 'None',   // must be None for cross-site cookies
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'           // make sure it's accessible everywhere
    });

    res.json({
      message: "Login successful",
      user: { name: user.name, email: user.email, phone: user.phone, role: user.role },
      accessToken
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// ---------- REFRESH TOKEN ----------
app.post('/refresh-token', async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) {
    return res.status(401).json({ error: "No refresh token found" });
  }

  try {
    const payload = jwt.verify(token, process.env.REFRESH_TOKEN_KEY);

    const newAccessToken = jwt.sign(
      { userId: payload.userId },
      process.env.TOKEN_KEY,
      { expiresIn: '1d' } // match your short-lived rule
    );

    res.json({ accessToken: newAccessToken });

  } catch (err) {
    console.error('Refresh token error:', err);
    return res.status(403).json({ error: "Invalid refresh token" });
  }
});
// Forgot password and reset password endpoints (keeping existing functionality)
app.post('/forgot-password', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }
  try {
    const user = await User.findOne({ email: email });
    if (!user) return res.status(400).json({ error: 'Email not registered' });
    otpStore[email] = { otp: parseInt(otp), expires: Date.now() + 10 * 60 * 1000 };
    res.json({ message: 'OTP saved on server' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

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

app.get('/get-user', async (req, res) => {
  const { email, phone } = req.query;
  if (!email || !phone) {
    return res.status(400).json({ error: 'Email and phone required' });
  }
  try {
    const user = await User.findOne({ $or: [{ email }, { phone }] }).select('-password');
    if (user) {
      return res.json({ message: 'User already exists', user });
    } else {
      return res.json({ message: 'User not found' });
    }
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// Logout (updated for OAuth)
app.post('/logout', (req, res) => {
  res.cookie('token', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 0
  });
  res.cookie('session_token', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 0,
    path: '/'
  });
  res.json({ message: 'Logged out successfully' });
});

// ------------------- ENHANCED AI FEATURES -------------------
// Enhanced itinerary generation with Emergent LLM
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.post('/generate-itinerary', async (req, res) => {
  try {
    const { user } = await getAuthenticatedUser(req, res);
    if (!user) return res.status(401).json({ loggedIn: false, error: 'Authentication required' });

    const { destination, days, interests, lang } = req.body;
    if (!destination || !days) return res.status(400).json({ error: 'Destination and days are required' });

    const prompt = `
Plan a ${days}-day trip to ${destination} for a user interested in ${interests || 'general activities'} in language ${lang}.
Provide the response in plain text only, without Markdown, asterisks, or headers.
Include daily schedule, travel tips, and approximate durations.
Please provide:
1. Daily detailed schedule with specific timings
2. Transportation recommendations between locations
3. Accommodation suggestions for each area
4. Local dining recommendations
5. Cultural tips and local customs
6. Budget estimates for activities
7. Weather considerations and packing tips
`;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a helpful travel assistant." },
        { role: "user", content: prompt }
      ]
    });

    const itinerary = response.choices[0].message.content;
    res.json({ itinerary });

  } catch (err) {
    console.error('Itinerary generation error:', err);
    res.status(500).json({ error: 'Failed to generate itinerary' });
  }
});

// Suggest places in India based on interests
function tryParseJSON(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (err) {
    // try to extract a json substring
    const arrMatch = raw.match(/\[[\s\S]*\]/);
    if (arrMatch) {
      try { return JSON.parse(arrMatch[0]); } catch (e) { }
    }
    const objMatch = raw.match(/\{[\s\S]*\}/);
    if (objMatch) {
      try { return JSON.parse(objMatch[0]); } catch (e) { }
    }
    return null;
  }
}

/**
 * POST /suggest-places
 * Body: { interests: "beaches, temples" }
 * Response: { suggestions: ["Goa","Rishikesh", ...] }
 */
// helper: reverse geocode coords -> nearest city

async function reverseGeocode(lat, lon) {
  try {
    const res = await fetch(
      `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}`,
      {
        headers: {
          "User-Agent": "travel-app/1.0 (anjalipujala001@gmail.com)", // required by Nominatim
        },
      }
    );

    if (!res.ok) {
      throw new Error(`HTTP error ${res.status}`);
    }

    const data = await res.json();

    const city =
      data.address.city ||
      data.address.town ||
      data.address.village ||
      data.address.hamlet ||
      "Unknown City";

    const state = data.address.state || "Unknown State";

    return { city, state };
  } catch (err) {
    console.error("Reverse geocoding failed:", err);
    return { city: "Unknown City", state: "Unknown State" };
  }
}


app.post("/suggest-places", async (req, res) => {
  try {
    const { place, interests, limit = 20 } = req.body;

    if (!place || !interests) {
      return res.status(400).json({ error: "Place and interests are required" });
    }

    const prompt = `
You are a travel assistant. Suggest ${limit} vacation destinations related to "${place}" 
matching these interests: "${interests}". 
For each, give a 80-100 word description.

Return strictly a JSON array in this format:
[
  { "destination": "Place Name", "description": "About the place, best time to visit" }
]
Do NOT return anything else.
`;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a travel assistant. Only output JSON array of {destination, description}." },
        { role: "user", content: prompt }
      ],
      temperature: 0.6,
    });

    const raw = response?.choices?.[0]?.message?.content;
    const parsed = tryParseJSON(raw);

    if (!Array.isArray(parsed) || parsed.length === 0) {
      return res.status(500).json({ error: "Invalid AI response", raw: raw?.slice?.(0, 1000) });
    }

    res.json({ suggestions: parsed });
  } catch (err) {
    return res.status(500).json({ error: "Server error", details: String(err.message || err) });
  }
});

app.post("/suggest-hotels", async (req, res) => {
  try {
    const { lat, lon } = req.body;

    if (!lat || !lon) {
      return res
        .status(400)
        .json({ error: "Latitude and longitude are required" });
    }

    // 🔄 Get city/state from reverse geocoding
    const { city, state } = await reverseGeocode(lat, lon);

    const prompt = `
You are a travel assistant. Suggest 10 of the best hotels within 10 km radius 
from these coordinates: (${lat}, ${lon}) near "${city}, ${state}".
For each hotel, include:
- Hotel name
- Rating (out of 5, decimal allowed)
- Short summary of reviews (1–2 sentences)
- Address
- Distance from current location in km

Return a JSON array of objects strictly in this format:
[
  { 
    "hotel": "Hotel Name", 
    "rating": 4.5, 
    "reviews": "Guests love the clean rooms and friendly staff.", 
    "address": "123 Main Road, ${city}", 
    "distance": "3.2 km"
  }
]
Do NOT return anything else.
`;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a travel assistant. Only output JSON array of {hotel, rating, reviews, address, distance}.",
        },
        { role: "user", content: prompt },
      ],
      temperature: 0.6,
    });

    const raw = response?.choices?.[0]?.message?.content;
    const parsed = tryParseJSON(raw);

    if (!Array.isArray(parsed) || parsed.length === 0) {
      return res
        .status(500)
        .json({ error: "Invalid AI response", raw: raw?.slice?.(0, 1000) });
    }

    const hotels = parsed
      .map((item) => ({
        hotel: item.hotel || "Unknown Hotel",
        rating: item.rating || "N/A",
        reviews: item.reviews || "",
        address: item.address || `${city}, ${state}`,
        distance: item.distance || "Unknown",
      }))
      .slice(0, 5);

    res.json({ city, state, hotels });
  } catch (err) {
    console.error("Error /suggest-hotels:", err);
    return res
      .status(500)
      .json({ error: "Server error", details: String(err.message || err) });
  }
});
// 📍 Famous Foods + Restaurants Endpoint

app.post("/suggest-local-foods", async (req, res) => {
  try {
    const { lat, lon } = req.body;

    if (!lat || !lon) {
      return res
        .status(400)
        .json({ error: "Latitude and longitude are required" });
    }

    // 🔄 Get city/state from coordinates
    const { city, state } = await reverseGeocode(lat, lon);

    // Prompt for OpenAI to suggest foods & restaurants
    const prompt = `
    rapid fire for you, get foods and restaurants for "${city}, ${state}" from internet.
You are a food and travel assistant. Based on the coordinates (${lat}, ${lon}) near "${city}, ${state}":

1. Suggest 5 famous local foods in this area with short 2–3 sentence descriptions.
2. Suggest 5 popular restaurants in this area with cuisine type and what they are best known for.

Return a JSON object strictly in this format:
{
  "foods": [
    { "food": "Food Name", "description": "About the food" }
  ],
  "restaurants": [
    { "restaurant": "Restaurant Name", "cuisine": "Type", "description": "About the restaurant" }
  ]
}
Do NOT return anything else.
`;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a travel/food assistant. Only output JSON with keys: foods, restaurants.",
        },
        { role: "user", content: prompt },
      ],
      temperature: 0.6,
    });

    const raw = response?.choices?.[0]?.message?.content;
    const parsed = tryParseJSON(raw);

    if (!parsed || !parsed.foods || !parsed.restaurants) {
      return res
        .status(500)
        .json({ error: "Invalid AI response", raw: raw?.slice?.(0, 1000) });
    }

    const foods = parsed.foods.slice(0, 5);
    const restaurants = parsed.restaurants.slice(0, 5);

    res.json({ city, state, foods, restaurants });
  } catch (err) {
    console.error("Error /suggest-local-foods:", err);
    return res
      .status(500)
      .json({ error: "Server error", details: String(err.message || err) });
  }
});



app.post("/get-destination-details", async (req, res) => {
  try {
    const { destinations } = req.body;
    if (!Array.isArray(destinations) || destinations.length === 0) {
      return res.status(400).json({ error: "destinations array required" });
    }

    const geoKey = process.env.GEOAPIFY_API_KEY;
    const otmKey = process.env.OPEN_TRIP_MAP_API_KEY;
    if (!geoKey || !otmKey) return res.status(500).json({ error: "Missing GEOAPIFY_API_KEY or OPEN_TRIP_MAP_API_KEY" });

    const results = [];
    for (const dest of destinations) {
      try {
        const geo = await geocodePlace(dest);
        if (!geo) { console.warn("No geocode for", dest); continue; }
        const { lat, lon } = geo;

        // Geoapify local spots (restaurants, hotels)
        const localUrl = `https://api.geoapify.com/v2/places?categories=catering.restaurant,hospitality.hotel&filter=circle:${lon},${lat},20000&limit=10&apiKey=${geoKey}`;
        const localRes = await fetch(localUrl);
        const localJson = localRes.ok ? await localRes.json() : { features: [] };
        const localSpots = (localJson.features || []).map(f => ({
          name: f.properties?.name || "",
          category: f.properties?.categories || [],
          address: f.properties?.formatted || "",
          lat: f.properties?.lat,
          lon: f.properties?.lon,
        }));

        // OpenTripMap attractions list (radius)
        const otmUrl = `https://api.opentripmap.com/0.1/en/places/radius?radius=20000&lon=${lon}&lat=${lat}&limit=10&apikey=${otmKey}`;
        const otmRes = await fetch(otmUrl);
        const otmJson = otmRes.ok ? await otmRes.json() : { features: [] };
        const otmFeatures = otmJson.features || [];

        // Enrich attractions by fetching xid-details (preview + extracts)
        const attractions = [];
        for (const f of otmFeatures) {
          const props = f.properties || {};
          const xid = props.xid;
          const basic = { name: props.name || "", kind: props.kinds || "", xid };
          if (xid) {
            try {
              const details = await fetchOTMXidDetails(xid);
              if (details) {
                basic.image = details.preview?.source || null;
                basic.description = details.wikipedia_extracts?.text || details.info?.descr_long || details.info?.descr || null;
                basic.address = details.address ? Object.values(details.address).filter(Boolean).join(", ") : null;
              }
            } catch (e) {
              // ignore individual fetch errors
            }
          }
          attractions.push(basic);
        }

        results.push({
          destination: dest,
          coordinates: { lat, lon },
          localSpots,
          attractions,
        });

      } catch (err) {
        console.error("Error building details for", dest, err);
      }
    } // end loop

    return res.json({ results });

  } catch (err) {
    console.error("Error /get-destination-details:", err);
    return res.status(500).json({ error: "Server error", details: String(err.message || err) });
  }
});
async function geocodePlace(name) {
  const url = `https://api.geoapify.com/v1/geocode/search?text=${encodeURIComponent(name)}&limit=1&apiKey=${process.env.GEOAPIFY_API_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Geoapify geocode failed: ${r.status}`);
  const json = await r.json();
  if (!json.features || json.features.length === 0) return null;
  const props = json.features[0].properties;
  return { lat: props.lat, lon: props.lon, raw: json.features[0] };
}

// Helper: Fetch OpenTripMap details by XID

async function fetchOTMXidDetails(xid) {
  if (!xid) return null;
  try {
    const url = `https://api.opentripmap.com/0.1/en/places/xid/${encodeURIComponent(xid)}?apikey=${process.env.OPEN_TRIP_MAP_API_KEY}`;
    const res = await fetch(url);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

// GET /nearby-hotels?lat=...&lon=...&radius=...
app.get('/nearby-hotels', async (req, res) => {
  try {
    const { lat, lon, radius = 10000 } = req.query;
    if (!lat || !lon) return res.status(400).json({ error: 'lat and lon required' });

    const geoUrl = `https://api.geoapify.com/v2/places?categories=accommodation.hotel&filter=circle:${lon},${lat},${radius}&limit=20&apiKey=${process.env.GEOAPIFY_API_KEY}`;
    const geoRes = await fetch(geoUrl);
    if (!geoRes.ok) throw new Error(`Geoapify API error: ${geoRes.status}`);
    const geoJson = await geoRes.json();
    if (!geoJson.features || geoJson.features.length === 0) return res.json({ hotels: [] });

    const hotels = await Promise.all(
      geoJson.features.map(async (f) => {
        let image = null;
        const xid = f.properties.xid;
        if (xid) {
          const details = await fetchOTMXidDetails(xid);
          image = details?.preview?.source || null;
        }

        return {
          name: f.properties.name,
          address: f.properties.formatted,
          rating: 'N/A', // ratings not available in free APIs
          lat: f.properties.lat,
          lon: f.properties.lon,
          image
        };
      })
    );

    res.json({ hotels });
  } catch (err) {
    console.error('Error fetching nearby hotels:', err);
    res.status(500).json({ error: 'Failed to fetch hotels', details: err.message });
  }
});

app.get('/nearby-restaurants', async (req, res) => {
  try {
    const { lat, lon, radius = 10000 } = req.query;
    if (!lat || !lon) return res.status(400).json({ error: 'lat and lon required' });

    // Geoapify API for restaurants
    const geoUrl = `https://api.geoapify.com/v2/places?categories=catering.restaurant&filter=circle:${lon},${lat},${radius}&limit=20&apiKey=${process.env.GEOAPIFY_API_KEY}`;
    const geoRes = await fetch(geoUrl);
    if (!geoRes.ok) throw new Error(`Geoapify API error: ${geoRes.status}`);
    const geoJson = await geoRes.json();
    if (!geoJson.features || geoJson.features.length === 0) return res.json({ restaurants: [] });

    const restaurants = await Promise.all(
      geoJson.features.map(async (f) => {
        let image = null;
        const xid = f.properties.xid;
        let mustTry = null;

        if (xid) {
          const details = await fetchOTMXidDetails(xid);
          image = details?.preview?.source || null;

          // If available in OpenTripMap, use description text to find "must try" foods
          if (details?.wikipedia_extracts?.text) {
            const match = details.wikipedia_extracts.text.match(/must try[:\-]\s*([\w ,]+)/i);
            mustTry = match ? match[1] : null;
          }
        }

        return {
          name: f.properties.name,
          address: f.properties.formatted,
          rating: 'N/A', // free APIs don’t provide ratings
          lat: f.properties.lat,
          lon: f.properties.lon,
          image,
          mustTry
        };
      })
    );

    res.json({ restaurants });
  } catch (err) {
    console.error('Error fetching nearby restaurants:', err);
    res.status(500).json({ error: 'Failed to fetch restaurants', details: err.message });
  }
});

// ------------------- PLACES -------------------
async function getLatLonFromName(name) {
  const url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(name)}&limit=1`;
  const response = await fetch(url, { headers: { 'User-Agent': 'SoulfulYatra/2.0' } });
  if (!response.ok) throw new Error('Failed to fetch from Nominatim');
  const data = await response.json();
  if (data.length === 0) return null;
  return { lat: parseFloat(data[0].lat), lon: parseFloat(data[0].lon), boundingbox: data[0].boundingbox };
}

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

app.get('/get-places-by-name', async (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'Place name is required' });

  try {
    const places = await getPlacesByName(name);
    if (!places.length) return res.status(404).json({ message: 'No places found' });
    res.json({ places });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/get-transportation', async (req, res) => {
  const { user, authType } = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({
      loggedIn: false,
      error: 'Authentication required'
    });
  }

  const { origin, destination, mode } = req.query;
  if (!origin || !destination) {
    return res.status(400).json({ error: 'Origin and destination are required' });
  }

  try {
    // Using free routing API as alternative to Google Directions
    const routeUrl = `https://router.project-osrm.org/route/v1/driving/${origin};${destination}?overview=false&steps=true`;

    const response = await fetch(routeUrl);
    const data = await response.json();

    if (data.routes && data.routes.length > 0) {
      const route = data.routes[0];
      const transportOptions = {
        driving: {
          duration: Math.round(route.duration / 60), // Convert to minutes
          distance: Math.round(route.distance / 1000), // Convert to km
          mode: 'driving',
          estimatedCost: Math.round(route.distance / 1000 * 1.0), // Rough estimate
          bookingUrl: `https://www.uber.com/?pickup=${origin}&dropoff=${destination}`
        },
        public_transit: {
          duration: Math.round(route.duration / 60 * 2.0), // Assume transit takes 50% longer
          distance: Math.round(route.distance / 1000),
          mode: 'transit',
          estimatedCost: Math.round(route.distance / 1000 * 0.1),
          bookingUrl: `https://www.rome2rio.com/s/${origin}/${destination}`
        }
      };

      res.json({ transportOptions });
    } else {
      res.status(404).json({ error: 'No routes found' });
    }
  } catch (err) {
    console.error('Transportation API error:', err);
    res.status(500).json({ error: 'Failed to fetch transportation options' });
  }
});

// ------------------- HOTELS & RESTAURANTS -------------------

const fetchPlacesByRadius = async (lat, lon, radius, kinds, limit, cacheKeyPrefix) => {
  const cacheKey = `${cacheKeyPrefix}:${lat}:${lon}:${radius}:${kinds}`;

  // Check Redis cache
  const cachedData = await redisClient.get(cacheKey);
  if (cachedData) {
    return JSON.parse(cachedData);
  }

  const apiKey = process.env.OPEN_TRIP_MAP_API_KEY;
  const url = `https://api.opentripmap.com/0.1/en/places/radius?radius=${radius}&lon=${lon}&lat=${lat}&kinds=${kinds}&limit=${limit}&apikey=${apiKey}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to fetch ${kinds}`);
  const data = await response.json();

  // Cache in Redis for 10 minutes
  await redisClient.set(cacheKey, JSON.stringify(data.features || []), "EX", 10 * 60);

  return data.features || [];
};


app.get('/get-hotels', async (req, res) => {
  const { user } = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ loggedIn: false, error: 'Authentication required' });

  const { lat, lon, radius = 10000 } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'lat & lon required' });

  try {
    const hotels = await fetchPlacesByRadius(lat, lon, radius, 'accomodations,hostels,guest_houses,other_hotels', 50, 'hotels');
    res.json({ hotels });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch hotels' });
  }
});

app.get('/famous-restaurants', async (req, res) => {
  const { user } = await getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ loggedIn: false, error: 'Authentication required' });

  const { lat, lon, radius = 10000 } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'lat & lon required' });

  try {
    const restaurants = await fetchPlacesByRadius(lat, lon, radius, 'foods', 50, 'restaurants');
    res.json({ restaurants });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch restaurants' });
  }
});

// ------------------- SAVE TRIPS -------------------
app.post('/save-trip', async (req, res) => {
  try {
    const { user, authType } = await getAuthenticatedUser(req, res);
    if (!user) return res.status(401).json({ loggedIn: false, error: 'Authentication required' });

    const email = user.email; // use user email
    const { destination, interests, tripData, days } = req.body;

    //console.log('Saving trip payload:', req.body); // log payload
    //console.log('User email:', email);

    if (!destination || !tripData)
      return res.status(400).json({ error: 'Destination and trip data are required' });

    const existingTrip = await SavedTrip.findOne({ email, destination, days });
    if (existingTrip) return res.status(400).json({ error: 'This trip is already saved!' });

    const savedTrip = await SavedTrip.create({
      email,
      destination,
      days,
      interests,
      tripData
    });

    await redisClient.del(`savedTrips:${email}`);
    res.json({ message: 'Trip saved successfully' });
  } catch (err) {
    console.error('Save trip error:', err);
    res.status(500).json({ error: 'Server error saving trip' });
  }
});


app.delete('/delete-trip/:tripId', async (req, res) => {
  try {
    const { user } = await getAuthenticatedUser(req, res);
    if (!user) return res.status(401).json({ loggedIn: false, error: 'Authentication required' });

    const email = user.email;
    const { tripId } = req.params;

    const deletedTrip = await SavedTrip.findOneAndDelete({ _id: tripId, email });
    if (!deletedTrip) return res.status(404).json({ error: 'Trip not found' });

    // ✅ Invalidate cache after deleting
    await redisClient.del(`savedTrips:${email}`);

    res.json({ message: 'Trip deleted successfully', trip: deletedTrip });
  } catch (err) {
    console.error('Delete trip error:', err);
    res.status(500).json({ error: 'Server error deleting trip' });
  }
});

// ------------------- PROFILE -------------------
app.get('/profile', async (req, res) => {
  try {
    const { user, authType } = await getAuthenticatedUser(req, res);
    if (!user) return res.status(401).json({ loggedIn: false, error: 'Authentication required' });

    // For JWT users, fetch fresh from DB
    if (authType === 'jwt') {
      const freshUser = await User.findById(user._id).select('-password');
      if (!freshUser) return res.status(404).json({ error: 'User not found' });
      return res.json({ user: freshUser });
    }

    // For OAuth users, return as is
    res.json({ user });
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});




app.get("/get-saved-trips", async (req, res) => {
  try {
    const { user } = await getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ loggedIn: false, error: 'Authentication required' });
    }

    const email = user.email;
    const cacheKey = `savedTrips:${email}`;

    // 1️⃣ Check Redis cache first
    const cachedTrips = await redisClient.get(cacheKey);
    if (cachedTrips) {
      return res.json({ trips: JSON.parse(cachedTrips), cached: true });
    }

    // 2️⃣ Fetch from DB if cache miss
    const trips = await SavedTrip.find({ email });

    // 3️⃣ Store in Redis with TTL (e.g., 10 minutes)
    await redisClient.set(cacheKey, JSON.stringify(trips), {
      EX: 600 // TTL in seconds
    });

    res.json({ trips, cached: false });
  } catch (err) {
    console.error("Error fetching saved trips:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// puah notifications
const webpush = require('web-push');
const cron = require('node-cron');
const UserSubscription = require('./models/UserSubscription');

webpush.setVapidDetails(
  "mailto:anjalipujala001@gmail.com",
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// Route to save subscription
app.post('/subscribe', async (req, res) => {
  try {
    const { email, subscription } = req.body;
    if (!email || !subscription) return res.status(400).json({ error: 'Email & subscription required' });

    await UserSubscription.findOneAndUpdate(
      { email },
      { subscription },
      { upsert: true, new: true }
    );

    //console.log(`🔔 Subscription saved for ${email}`);
    res.status(201).json({ message: 'Subscription saved' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save subscription' });
  }
});

// VAPID key route for frontend
app.get('/vapidPublicKey', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

// Send push notifications for trips
async function sendTripNotifications(minutesAgo = 1440) {
  try {
    const dateThreshold = new Date(Date.now() - minutesAgo * 60 * 1000);

    // Find trips not notified yet, older than threshold
    const trips = await SavedTrip.find({
      savedAt: { $lte: dateThreshold },
      notified: false
    });

    //console.log(`Found ${trips.length} trips to notify.`);

    for (const trip of trips) {
      const subscriptionDoc = await UserSubscription.findOne({ email: trip.email });
      if (!subscriptionDoc) continue;

      const payload = JSON.stringify({
        title: "Your saved trip is waiting!",
        body: `Hey, your trip to ${trip.destination} is ready to explore!`
      });

      try {
        await webpush.sendNotification(subscriptionDoc.subscription, payload);
        //console.log(`✅ Notification sent to ${trip.email}`);

        // Mark trip as notified
        trip.notified = true;
        await trip.save();
      } catch (err) {
        console.error(`❌ Failed to send to ${trip.email}`, err);
      }
    }
  } catch (err) {
    console.error("Error in sendTripNotifications:", err);
  }
}


// ---------- PRODUCTION: 24 hours after save ----------
cron.schedule('0 * * * *', () => { // every hour
  sendTripNotifications(1440); // 1440 minutes = 24 hours
});

const multer = require('multer');
const path = require('path');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const Vlog = require('./models/Vlogs');
const Like = require('./models/Like');
const Comment = require('./models/Comment');

// ---------------- Cloudinary Config ----------------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ---------------- Multer Cloudinary Storage ----------------
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'vlogs', // folder name in cloudinary
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'mp4', 'webm', 'ogg'],
    public_id: (req, file) => `vlogs-image-${Date.now()}-${path.parse(file.originalname).name}`
  }
});

const upload = multer({ storage });

// ---------------- Create Vlog ----------------
app.post('/create-vlog', upload.single('vlog'), async (req, res) => {
  try {
    const { userEmail, userName, title, description, tags } = req.body;
    if (!userEmail || !title || !req.file)
      return res.status(400).json({ error: 'Missing required fields' });

    // Cloudinary gives secure_url for CDN
    const cloudUrl = req.file.path || req.file.secure_url;

    const newVlog = new Vlog({
      userEmail,
      userName,
      title,
      description,
      tags: tags ? tags.split(',').map(t => t.trim()) : [],
      imageUrl: cloudUrl // <-- Store Cloudinary URL directly
    });

    await newVlog.save();
    res.status(201).json({ message: 'Vlog uploaded successfully', vlog: newVlog });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create vlog' });
  }
});
// UPDATE VLOG
app.put('/update-vlog/:id', upload.single('vlog'), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, tags } = req.body;

    // Find vlog by id
    const vlog = await Vlog.findById(id);
    if (!vlog) return res.status(404).json({ error: "Vlog not found" });

    // Update fields
    if (title) vlog.title = title;
    if (description) vlog.description = description;
    if (tags) vlog.tags = tags.split(',').map(t => t.trim());

    // If user uploaded a new file, update Cloudinary URL
    if (req.file) {
      const cloudUrl = req.file.path || req.file.secure_url;
      vlog.imageUrl = cloudUrl;
    }

    await vlog.save();
    res.json({ message: "Vlog updated successfully", vlog });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update vlog" });
  }
});

// DELETE VLOG
app.delete('/delete-vlog/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const vlog = await Vlog.findByIdAndDelete(id);
    if (!vlog) return res.status(404).json({ error: "Vlog not found" });

    res.json({ message: "Vlog deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete vlog" });
  }
});

// ---------------- Fetch All Vlogs ----------------
app.get('/vlogs', async (req, res) => {
  try {
    const { search = "", page = 0, limit = 4 } = req.query;

    // Build search query
    const query = {};
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { tags: { $regex: search, $options: "i" } }
      ];
    }

    // Pagination
    const skip = parseInt(page) * parseInt(limit);

    // Fetch only the slice of vlogs needed
    const vlogs = await Vlog.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Format with like count and comments
    const formatted = await Promise.all(
      vlogs.map(async vlog => {
        const likeCount = await Like.countDocuments({ vlogId: vlog._id });
        const comments = await Comment.find({ vlogId: vlog._id })
          .sort({ createdAt: 1 })
          .limit(5); // optionally limit comments here
        return {
          _id: vlog._id,
          userEmail: vlog.userEmail,
          userName: vlog.userName,
          title: vlog.title,
          description: vlog.description,
          tags: vlog.tags,
          imageUrl: vlog.imageUrl, // CDN URL
          createdAt: vlog.createdAt,
          likeCount,
          comments
        };
      })
    );

    res.json({ vlogs: formatted });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch vlogs' });
  }
});


// make sure you import your helper:
const sendNotification = require('./helper/sendNotification');

// ---------------- Like / Unlike Vlog ----------------
app.post('/vlogs/:id/like', async (req, res) => {
  try {
    const vlogId = req.params.id;
    const { userEmail, userName } = req.body;
    if (!userEmail) return res.status(400).json({ error: 'User email required' });

    const vlog = await Vlog.findById(vlogId);
    if (!vlog) return res.status(404).json({ error: 'Vlog not found' });

    const existing = await Like.findOne({ vlogId, userEmail });
    if (existing) {
      await existing.deleteOne();
      return res.json({ message: 'Vlog unliked' });
    } else {
      await Like.create({ vlogId, userEmail, userName });

      // 🔔 Send notification to vlog owner (if not self-like)
      if (vlog.userEmail !== userEmail) {
        await sendNotification(vlog.userEmail, {
          title: "New Like on Your Vlog ❤️",
          body: `${userName} liked your vlog: ${vlog.title}`
        });
      }

      return res.json({ message: 'Vlog liked' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to like/unlike vlog' });
  }
});

// ---------------- Add Comment ----------------
app.post('/vlogs/:id/comment', async (req, res) => {
  try {
    const vlogId = req.params.id;
    const { userEmail, userName, text } = req.body;
    if (!userEmail || !text || !userName) return res.status(400).json({ error: 'Missing fields' });

    const vlog = await Vlog.findById(vlogId);
    if (!vlog) return res.status(404).json({ error: 'Vlog not found' });

    const comment = await Comment.create({ vlogId, userEmail, userName, text });

    // 🔔 Send notification to vlog owner (if not self-comment)
    if (vlog.userEmail !== userEmail) {
      await sendNotification(vlog.userEmail, {
        title: "New Comment on Your Vlog 💬",
        body: `${userName} commented: "${text}"`
      });
    }

    res.status(201).json({ message: 'Comment added', comment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// ---------------- Fetch Comments ----------------
app.get('/vlogs/:id/comments', async (req, res) => {
  try {
    const vlogId = req.params.id;
    const limit = parseInt(req.query.limit, 10) || 0;
    const sortOrder = req.query.sort === 'asc' ? 1 : -1;

    let query = Comment.find({ vlogId }).sort({ createdAt: sortOrder });
    if (limit > 0) query = query.limit(limit);

    const comments = await query.exec();
    res.json({ comments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// ---------------- Fetch Like Count ----------------
app.get('/vlogs/:id/likes', async (req, res) => {
  try {
    const vlogId = req.params.id;
    const likeCount = await Like.countDocuments({ vlogId });
    res.json({ likeCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch likes' });
  }
});
// GET /get-user-vlogs?userEmail=...&page=0&limit=4
app.get('/get-user-vlogs', async (req, res) => {
  try {
    const { userEmail, page = 0, limit = 4 } = req.query;
    if (!userEmail) return res.status(400).json({ error: "User email required" });

    const skip = parseInt(page) * parseInt(limit);

    const userVlogs = await Vlog.find({ userEmail })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const formatted = await Promise.all(
      userVlogs.map(async (vlog) => {
        const likeCount = await Like.countDocuments({ vlogId: vlog._id });
        const comments = await Comment.find({ vlogId: vlog._id })
          .sort({ createdAt: 1 })
          .limit(5);
        return {
          _id: vlog._id,
          userEmail: vlog.userEmail,
          userName: vlog.userName,
          title: vlog.title,
          description: vlog.description,
          tags: vlog.tags,
          imageUrl: vlog.imageUrl,
          createdAt: vlog.createdAt,
          likeCount,
          comments,
        };
      })
    );

    res.json({ vlogs: formatted, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user vlogs' });
  }
});
const ProfileImage = require("./models/ProfileImage");
const profileStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'profile_images',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif'],
    public_id: (req, file) => `profile-${Date.now()}-${path.parse(file.originalname).name}`
  }
});

const profileUpload = multer({ storage: profileStorage });

// ---------------- Fetch Profile Image ----------------
app.get('/profile-image', async (req, res) => {
  try {
    const { userEmail } = req.query;
    if (!userEmail) return res.status(400).json({ error: 'userEmail required' });

    const profile = await ProfileImage.findOne({ userEmail });
    if (!profile) return res.json({ profileImageUrl: null });

    res.json({ profileImageUrl: profile.profileImageUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch profile image' });
  }
});

// ---------------- Add or Update Profile Image ----------------
app.post('/profile-image', profileUpload.single('profileImage'), async (req, res) => {
  try {
    const { userEmail } = req.body;
    if (!userEmail || !req.file) {
      return res.status(400).json({ error: 'userEmail and profileImage are required' });
    }

    const cloudUrl = req.file.path || req.file.secure_url;

    let profile = await ProfileImage.findOne({ userEmail });
    if (profile) {
      profile.profileImageUrl = cloudUrl;
      await profile.save();
    } else {
      profile = new ProfileImage({ userEmail, profileImageUrl: cloudUrl });
      await profile.save();
    }

    res.json({
      message: 'Profile image saved successfully',
      profileImageUrl: profile.profileImageUrl
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add/update profile image' });
  }
});
// GET /api/likes/check?vlogId=...&email=...
app.get('/check', async (req, res) => {
  try {
    const { vlogId, email } = req.query;
    if (!vlogId || !email) {
      return res.status(400).json({ error: 'vlogId and email are required' });
    }

    const existing = await Like.findOne({ vlogId, userEmail: email });
    res.json({ liked: !!existing });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});


//-----------------------------------GUIDES-----------------------
const Booking = require("./models/Bookings");
// ensure you import your model

// ------------------ Get Bookings ------------------
app.get("/bookings", async (req, res) => {
  try {
    let { guideEmail } = req.query;
    if (!guideEmail) return res.status(400).json({ error: "guideEmail required" });

    // Decode Base64 email
    guideEmail = Buffer.from(guideEmail, "base64").toString("utf-8");

    const bookings = await Booking.find({ guideEmail }).sort({ date: 1 });
    res.json({ bookings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

// ------------------ Confirm / Reject Booking ------------------
app.patch("/bookings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!["Confirmed", "Rejected", "Completed"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const booking = await Booking.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    if (!booking) return res.status(404).json({ error: "Booking not found" });

    res.json({ message: "Booking updated", booking });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update booking" });
  }
});


// ---------------- Availability APIs ----------------
const Availability = require('./models/Availability');

// Get guide availability
app.get("/availability", async (req, res) => {
  try {
    const { guideEmail } = req.query;
    if (!guideEmail) return res.status(400).json({ error: "guideEmail required" });

    const availability = await Availability.findOne({ guideEmail });
    res.json({ availableDates: availability ? availability.availableDates : [] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch availability" });
  }
});

// Add new dates
app.post("/availability", async (req, res) => {
  try {
    const { guideEmail, dates } = req.body;
    if (!guideEmail || !dates || !Array.isArray(dates)) {
      return res.status(400).json({ error: "guideEmail and dates array required" });
    }

    let availability = await Availability.findOne({ guideEmail });
    if (!availability) {
      availability = new Availability({ guideEmail, availableDates: dates });
    } else {
      const newDates = dates.map(d => new Date(d));
      availability.availableDates = Array.from(new Set([...availability.availableDates, ...newDates]));
    }

    await availability.save();
    res.json({ message: "Availability updated", availableDates: availability.availableDates });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update availability" });
  }
});

// Remove a date
app.delete("/availability", async (req, res) => {
  try {
    const { guideEmail, date } = req.body;
    if (!guideEmail || !date) return res.status(400).json({ error: "guideEmail and date required" });

    const availability = await Availability.findOne({ guideEmail });
    if (!availability) return res.status(404).json({ error: "Availability not found" });

    availability.availableDates = availability.availableDates.filter(
      d => d.toISOString() !== new Date(date).toISOString()
    );
    await availability.save();

    res.json({ message: "Date removed", availableDates: availability.availableDates });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to remove date" });
  }
});

const Guide = require("./models/Guide");
app.get("/guides", async (req, res) => {
  try {
    const guides = await Guide.aggregate([
      {
        $lookup: {
          from: "users",
          localField: "email",
          foreignField: "email",
          as: "userInfo"
        }
      },
      { $unwind: "$userInfo" },
      {
        $lookup: {
          from: "availabilities", // collection name
          localField: "email",
          foreignField: "guideEmail",
          as: "availability"
        }
      },
      {
        $project: {
          email: 1,
          places: 1,
          rating: 1,
          description: 1,
          baseFare: 1,
          name: "$userInfo.name",
          availableDates: {
            $ifNull: [{ $first: "$availability.availableDates" }, []]
          }
        }
      }
    ]);

    res.status(200).json({ success: true, guides });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});



// ------------------ Get Guides by Place ------------------
app.get("/guides/place/:place", async (req, res) => {
  const { place } = req.params;
  try {
    // Case-insensitive search for place
    const guides = await Guide.find({ places: { $regex: new RegExp(`^${place}$`, "i") } });
    res.status(200).json({ success: true, guides });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

//---------------------BOOKINGS-------------
app.post("/book-guide", async (req, res) => {
  const { guideEmail, guideName, userEmail, userName, date, totalCost } = req.body;

  if (!guideEmail || !guideName || !userEmail || !userName || !date || !totalCost) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const availability = await Availability.findOne({ guideEmail });
    if (!availability) {
      return res.status(400).json({ error: "❌ Guide availability not found" });
    }

    // Normalize to date-only (yyyy-mm-dd)
    const selectedDate = new Date(date).toISOString().split("T")[0];

    const match = availability.availableDates.some(d =>
      new Date(d).toISOString().split("T")[0] === selectedDate
    );

    if (!match) {
      return res.status(400).json({
        error: `❌ Guide is not available on ${new Date(date).toLocaleDateString()}`
      });
    }

    // Create booking
    const booking = new Booking({
      guideEmail,
      userEmail,
      userName,
      date: new Date(date),
      price: totalCost,
      notes: "",
      status: "Pending",
    });
    await booking.save();

    // Remove booked date
    availability.availableDates = availability.availableDates.filter(d =>
      new Date(d).toISOString().split("T")[0] !== selectedDate
    );
    await availability.save();

    return res.status(201).json({
      message: "✅ Booking created successfully",
      booking,
    });
  } catch (err) {
    console.error("Booking creation error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/get-user-bookings", async (req, res) => {
  const { user } = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ loggedIn: false, error: 'Authentication required' });
  }
  try {
    const bookings = await Booking.find({ userEmail: user.email }).sort({ createdAt: -1 });
    res.json({ bookings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

//-----------------------BOOKING RAZOR--------------------
// backend/razorpay.js or in your booking route
const Razorpay = require("razorpay");

const razorpay = new Razorpay({
  key_id: process.env.RAZOR_PAY_KEY_ID,
  key_secret: process.env.RAZOR_PAY_KEY_SECRET,
});
// =====================
// Create Razorpay Order
// =====================
app.post("/create-razorpay-order", async (req, res) => {
  const { amount } = req.body; // amount in paise
  if (!amount) {
    return res.status(400).json({ error: "Amount is required" });
  }

  try {
    const options = {
      amount, // ₹500 → 50000
      currency: "INR",
      payment_capture: 1, // automatic capture
    };
    const order = await razorpay.orders.create(options);
    res.json(order);
  } catch (err) {
    console.error("Razorpay order creation failed:", err);
    res.status(500).json({ error: "Failed to create order" });
  }
});


const crypto = require("crypto"); // adjust path if needed

// =====================
// Verify Payment & Create Booking
// =====================
app.post("/verify-payment", async (req, res) => {
  const {
    payment_id,
    order_id,
    signature,
    guideEmail,
    guideName,
    userEmail,
    userName,
    date,
    totalCost,
  } = req.body;

  if (!payment_id || !order_id || !signature || !guideEmail || !userEmail || !date) {
    return res.status(400).json({ success: false, error: "Missing required fields" });
  }

  try {
    // Step 1: Verify Razorpay signature
    const body = order_id + "|" + payment_id;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZOR_PAY_KEY_SECRET)
      .update(body.toString())
      .digest("hex");

    if (expectedSignature !== signature) {
      return res.status(400).json({ success: false, error: "Payment verification failed" });
    }

    // Step 2: Payment verified ✅
    const advanceAmount = Math.ceil(totalCost / 2);

    const booking = new Booking({
      guideEmail,
      guideName,
      userEmail,
      userName,
      date,
      price: totalCost,
      paidAmount: advanceAmount,
      balanceAmount: totalCost - advanceAmount,
      status: "Confirmed",
      paymentDetails: {
        paymentId: payment_id,
        orderId: order_id,
        signature,
        paidAt: new Date(),
      },
    });

    await booking.save();

    // Step 3: Update guide availability
    const availability = await Availability.findOne({ guideEmail });
    if (!availability) {
      return res.status(400).json({ success: false, error: "❌ Guide availability not found" });
    }

    // Normalize to date-only (yyyy-mm-dd)
    const selectedDate = new Date(date).toISOString().split("T")[0];

    const match = availability.availableDates.some(
      (d) => new Date(d).toISOString().split("T")[0] === selectedDate
    );

    if (!match) {
      return res.status(400).json({
        success: false,
        error: `❌ Guide is not available on ${new Date(date).toLocaleDateString()}`,
      });
    }

    // Remove the booked date
    availability.availableDates = availability.availableDates.filter(
      (d) => new Date(d).toISOString().split("T")[0] !== selectedDate
    );

    await availability.save();

    // Step 4: Success response
    return res.status(201).json({
      success: true,
      message: "✅ Booking created and availability updated successfully",
      booking,
    });

  } catch (err) {
    console.error("Payment verification error:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});





// ✅ Change Booking Date
app.put("/change-booking-date/:id", async (req, res) => {
  const { newDate } = req.body;
  if (!newDate) {
    return res.status(400).json({ error: "New date is required" });
  }

  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    if (booking.status === "Cancelled") {
      return res.status(400).json({ error: "Cannot change date of a cancelled booking" });
    }

    const availability = await Availability.findOne({ guideEmail: booking.guideEmail });
    if (!availability) {
      return res.status(400).json({ error: "Guide availability not found" });
    }

    const selectedDate = new Date(newDate).toISOString().split("T")[0];

    // Check if new date is available
    const isAvailable = availability.availableDates.some(
      d => new Date(d).toISOString().split("T")[0] === selectedDate
    );
    if (!isAvailable) {
      return res.status(400).json({ error: "Guide not available on this date" });
    }

    // Restore old date
    const oldDate = new Date(booking.date).toISOString().split("T")[0];
    if (!availability.availableDates.some(d => new Date(d).toISOString().split("T")[0] === oldDate)) {
      availability.availableDates.push(booking.date);
    }

    // Remove new date from availability
    availability.availableDates = availability.availableDates.filter(
      d => new Date(d).toISOString().split("T")[0] !== selectedDate
    );

    // Save booking + availability
    booking.date = newDate;
    await booking.save();
    await availability.save();

    return res.json({ message: "Booking date updated successfully", booking });
  } catch (err) {
    console.error("Change booking date error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Cancel booking
app.put("/cancel-booking/:id", async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ error: "Booking not found" });

    const tripDate = new Date(booking.date);
    const now = new Date();
    const diffHours = (tripDate - now) / (1000 * 60 * 60);

    let refundAmount = 0;
    const advancePaid = booking.paidAmount * 100; // paise

    if (diffHours >= 24 * 7) {
      refundAmount = advancePaid; // Full refund
    } else if (diffHours >= 48) {
      refundAmount = advancePaid / 2; // 50% refund
    }

    let refundResult = null;

    try {
      if (refundAmount > 0) {
        refundResult = await razorpay.payments.refund(booking.paymentDetails.paymentId, {
          amount: refundAmount,
        });
      }
    } catch (err) {
      if (
        err.error?.description === "The payment has been fully refunded already"
      ) {
        // Payment already refunded, ignore Razorpay error
        refundResult = { id: "already_refunded" };
      } else {
        throw err; // Other errors
      }
    }

    // Update booking status and refund info in DB
    booking.status = "Cancelled";
    booking.refund = {
      amount: refundAmount / 100,
      refunded: refundAmount > 0,
      refundId: refundResult?.id || null,
      refundDate: new Date(),
    };
    await booking.save();

    // Restore guide availability
    const availability = await Availability.findOne({ guideEmail: booking.guideEmail });
    if (availability) {
      availability.availableDates.push(booking.date);
      await availability.save();
    }

    res.json({
      message: "Booking cancelled successfully",
      refundAmount: refundAmount / 100,
      booking,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/delete-booking/:id", async (req, res) => {
  try {
    const booking = await Booking.findByIdAndDelete(req.params.id);
    if (!booking) return res.status(404).json({ error: "Booking not found" });
    res.json({ message: "Booking deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
app.put('/complete-booking/:id', async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ error: 'Booking not found' });

    // Update status to Completed
    booking.status = "Completed";
    await booking.save();

    res.json({ message: 'Booking marked as completed', booking });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

//------Guide register----------
const guideStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    const hash = crypto.randomBytes(16).toString("hex"); // ❌ unpredictable ID
    return {
      folder: "guides",
      allowed_formats: ["jpg", "jpeg", "png", "pdf"],
      public_id: `guide-${hash}`,
      resource_type: "auto",
      type: file.fieldname === "aadhaarCard" ? "private" : "authenticated",
      // Aadhaar is private, others can be authenticated
    };
  },
});

const guideUpload = multer({ storage: guideStorage });
const GuideRegistration = require("./models/GuideRegistration");
// ---------------- POST /register-guide ----------------
app.post(
  "/register-guide",
  guideUpload.fields([
    { name: "govtCertificate", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { name, email, phone, password, places, description, languages, reviewLinks, baseFare, fareType } = req.body;

      if (!name || !email || !phone || !password || !places || !fareType) {
        return res.status(400).json({ error: "All required fields must be filled" });
      }

      const existing = await GuideRegistration.findOne({ email });
      if (existing) return res.status(400).json({ error: "Registration already submitted" });

      const hashedPassword = await bcrypt.hash(password, 10);

      const guideReg = new GuideRegistration({
        name,
        email,
        phone,
        password: hashedPassword,
        places: places.split(",").map((p) => p.trim()),
        description,
        languages: languages ? languages.split(",").map((l) => l.trim()) : [],
        reviewLinks: reviewLinks ? reviewLinks.split(",").map((r) => r.trim()) : [],
        baseFare,
        fareType,
        govtCertificatePublicId: req.files["govtCertificate"] ? req.files["govtCertificate"][0].filename : null,
        //aadhaarCardPublicId: req.files["aadhaarCard"][0].filename,
      });

      await guideReg.save();

      res.status(201).json({ message: "Guide registration submitted, pending admin approval", guideReg });
    } catch (err) {
      console.error("Guide Registration Error:", err);
      res.status(500).json({ error: "Failed to submit guide registration" });
    }
  }
);

// ✅ Get all guides
app.get("/guides", async (req, res) => {
  try {
    // Fetch only guides that are not approved
    const guides = await GuideRegistration.find({ isApproved: false }).sort({ createdAt: -1 });
    res.json(guides);
  } catch (err) {
    console.error("Error fetching guides:", err);
    res.status(500).json({ error: "Failed to fetch guides" });
  }
});


// ✅ Approve/Reject guide
app.patch("/guides/:id/approve", async (req, res) => {
  try {
    const { isApproved } = req.body;

    // Update guide approval status
    const updatedGuide = await GuideRegistration.findByIdAndUpdate(
      req.params.id,
      { isApproved },
      { new: true }
    );

    if (!updatedGuide) {
      return res.status(404).json({ error: "Guide not found" });
    }

    // If guide is approved, add to User collection
    if (isApproved) {
      // Check if user already exists
      const existingUser = await User.findOne({ email: updatedGuide.email });
      if (!existingUser) {
        const newUser = new User({
          name: updatedGuide.name,
          email: updatedGuide.email,
          phone: updatedGuide.phone,
          password: updatedGuide.password, // already hashed
          role: "guide",
          isActive: true,
        });
        await newUser.save();
      }
    }

    res.json(updatedGuide);
  } catch (err) {
    console.error("Error updating guide:", err);
    res.status(500).json({ error: "Failed to update guide" });
  }
});


// Admin route to get signed URL for a guide's Aadhaar
app.get("/admin/guide/:id/aadhaar", async (req, res) => {
  try {
    const guideId = req.params.id;

    // Fetch guide from DB
    const guide = await GuideRegistration.findById(guideId);
    if (!guide || !guide.aadhaarCardPublicId) {
      return res.status(404).json({ error: "Aadhaar not found" });
    }

    // Generate signed URL (valid for 10 min)
    const signedUrl = cloudinary.url(guide.aadhaarCardPublicId, {
      type: "private",
      sign_url: true,
      expires_at: Math.floor(Date.now() / 1000) + 600, // 10 minutes
    });

    res.json({ signedUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to generate signed URL" });
  }
});

// ------------------- SERVER START -------------------
connectDB().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Enhanced SoulfulYatra server running on port ${PORT}`));
}).catch(err => console.error(err));