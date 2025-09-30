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
let db;
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
/*const mongoURI = process.env.MONGO_URI;
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
};*/

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
          fareType: 1,
          languages: 1,
          name: "$userInfo.name",
          phone: "$userInfo.phone",
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
      type: "authenticated",
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

app.get("/guides/pending", async (req, res) => {
  try {
    const guides = await GuideRegistration.find({ isApproved: false }).sort({ createdAt: -1 });
    const guidesData = guides.map(guide => ({
      ...guide._doc,
      // only include publicId, not signed URL
      govtCertificatePublicId: guide.govtCertificatePublicId || null
    }));
    res.json(guidesData);
  } catch (err) {
    console.error("Error fetching guides:", err);
    res.status(500).json({ error: "Failed to fetch guides" });
  }
});

app.get("/guides/:id/certificate", async (req, res) => {
  try {
    const guideId = req.params.id;

    // Fetch guide from DB
    const guide = await GuideRegistration.findById(guideId);
    if (!guide || !guide.govtCertificatePublicId) {
      return res.status(404).json({ error: "Govt Certificate not found" });
    }

    // Generate signed URL (valid for 10 minutes)
    const signedUrl = cloudinary.url(guide.govtCertificatePublicId, {
      type: "authenticated", // because it’s uploaded as authenticated
      sign_url: true,
      expires_at: Math.floor(Date.now() / 1000) + 600,
    });

    res.json({ signedUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to generate signed URL" });
  }
});


// ✅ Approve/Reject guide
app.patch("/guides/:id/approve", async (req, res) => {
  try {
    const { isApproved } = req.body;

    // Update guide approval status in GuideRegistration
    const updatedGuide = await GuideRegistration.findByIdAndUpdate(
      req.params.id,
      { isApproved },
      { new: true }
    );

    if (!updatedGuide) {
      return res.status(404).json({ error: "Guide not found" });
    }

    if (isApproved) {
      // 1. Ensure User exists
      const existingUser = await User.findOne({ email: updatedGuide.email });
      if (!existingUser) {
        const newUser = new User({
          name: updatedGuide.name,
          email: updatedGuide.email,
          phone: updatedGuide.phone,
          password: updatedGuide.password,
          role: "guide",
          isActive: true,
        });
        await newUser.save();
      }

      // 2. Ensure Guide exists
      const existingGuide = await Guide.findOne({ email: updatedGuide.email });
      if (!existingGuide) {
        const newGuide = new Guide({
          name: updatedGuide.name,
          email: updatedGuide.email,
          phone: updatedGuide.phone,
          places: updatedGuide.places,
          languages: updatedGuide.languages || [],
          rating: 0, // default
          description: updatedGuide.description,
          baseFare: updatedGuide.baseFare,
          fareType: updatedGuide.fareType || "per_day",
          reviewLinks:
            updatedGuide.reviewLinks && updatedGuide.reviewLinks.length > 0
              ? updatedGuide.reviewLinks
              : [],
          govtCertificateUrl: updatedGuide.govtCertificatePublicId
            ? cloudinary.url(updatedGuide.govtCertificatePublicId, {
              type: "authenticated",
              sign_url: true,
              secure: true,
            })
            : null,
          isApproved: true,
        });
        await newGuide.save();
      }
    }

    // Format rating for response
    res.json({
      ...updatedGuide.toObject(),
      rating:
        updatedGuide.rating && updatedGuide.rating > 0
          ? updatedGuide.rating
          : "No ratings yet",
    });
  } catch (err) {
    console.error("Error approving guide:", err);
    res.status(500).json({ error: "Failed to approve guide" });
  }
});




// DELETE /guides/:id/reject
app.delete("/guides/:id/reject", async (req, res) => {
  try {
    const { id } = req.params;

    // Find and remove the guide
    const deletedGuide = await GuideRegistration.findByIdAndDelete(id);

    if (!deletedGuide) {
      return res.status(404).json({ error: "Guide not found" });
    }

    // Optionally: delete the govt certificate from Cloudinary
    if (deletedGuide.govtCertificatePublicId) {
      await cloudinary.uploader.destroy(deletedGuide.govtCertificatePublicId, {
        resource_type: "auto",
      });
    }

    res.json({ message: "Guide rejected and removed successfully" });
  } catch (err) {
    console.error("Error rejecting guide:", err);
    res.status(500).json({ error: "Failed to reject guide" });
  }
});

// Admin route to get signed URL for a guide's Aadhaar
/*app.get("/admin/guide/:id/adhaar", async (req, res) => {
  try {
    const guideId = req.params.id;

    // Fetch guide from DB
    const guide = await GuideRegistration.findById(guideId);
    if (!guide || !guide.govtCertificatePublicId) {
      return res.status(404).json({ error: "Aadhaar not found" });
    }

    // Generate signed URL (valid for 10 min)
    const signedUrl = cloudinary.url(guide.govtCertificatePublicId, {
      type: "private",
      sign_url: true,
      expires_at: Math.floor(Date.now() / 1000) + 600,
    });

    res.json({ signedUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to generate signed URL" });
  }
});*/


// Update guide info
app.patch("/update-guide-profile", async (req, res) => {
  const { email } = req.user; // from auth middleware
  const { name, phone, baseFare, fareType, languages, description } = req.body;
  try {
    const updatedGuide = await Guide.findOneAndUpdate(
      { email },
      { name, phone, baseFare, fareType, languages, description },
      { new: true }
    );
    res.json({ success: true, guide: updatedGuide });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Failed to update profile" });
  }
});
app.get("/earnings", async (req, res) => {
  try {
    // Get guideEmail from query instead of req.user
    const guideEmail = req.query.guideEmail;
    if (!guideEmail) return res.status(400).json({ error: "guideEmail required" });

    const completedBookings = await Booking.find({
      guideEmail,
      status: "Completed",
    });

    const totalEarnings = completedBookings.reduce((sum, b) => sum + b.price, 0);
    res.json({ totalEarnings, completedBookings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch earnings" });
  }
});

app.get('/guide-details', async (req, res) => {
  try {
    const { email } = req.query; // pass guide email as query parameter
    if (!email) return res.status(400).json({ success: false, error: "Email is required" });

    const guide = await Guide.findOne({ email });
    if (!guide) return res.status(404).json({ success: false, error: "Guide not found" });

    res.status(200).json({ success: true, guide });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Failed to fetch guide details" });
  }
});

///----------places for planning

let placesDb;
// GET places in a state
app.get('/places-state-regions', async (req, res) => {
  try {
    const state = req.query.state; 
    if (!state) {
      return res.status(400).json({ error: 'State query parameter is required' });
    }

    const collection = placesDb.collection('places_regions');
    const places = await collection.find({ state: state }).toArray();

    res.json({ count: places.length, data: places });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});
app.get('/places-by-categories', async (req, res) => {
  try {
    const categoriesQuery = req.query.categories; // e.g., ?categories=Beaches,Natural
    if (!categoriesQuery) {
      return res.status(400).json({ error: 'Categories query parameter is required' });
    }

    // Convert string into array, trim spaces
    const categories = categoriesQuery.split(',').map(c => c.trim());

    const collection = placesDb.collection('places_regions');

    // Match if any category from user exists in "categories" field
    const places = await collection.find({
      $or: categories.map(cat => ({
        categories: { $regex: new RegExp(cat, 'i') }  // case-insensitive match
      }))
    }).toArray();

    res.json({ count: places.length, data: places });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});
app.get('/spots-by-region/:region_id', async (req, res) => {
  try {
    const regionId = req.params.region_id; // e.g., /spots-by-region/1011

    if (!regionId) {
      return res.status(400).json({ error: 'region_id parameter is required' });
    }

    const collection = placesDb.collection('places_spots'); // adjust name if different

    // Find spots with matching region_id (make sure both are same type: string/number)
    const spots = await collection.find({ region_id: regionId }).toArray();

    res.json({ count: spots.length, data: spots });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/get-places-from-region-id', async (req, res) => {
  try {
    const { region_ids, categories } = req.body;

    if (!region_ids || !region_ids.length) {
      return res.status(400).json({ message: 'Region IDs required' });
    }

    if (!categories || !categories.length) {
      return res.status(400).json({ message: 'Categories required' });
    }

    
    const userCategories = categories.map(cat => cat.trim().toLowerCase());

    const allPlaces = await placesDb
      .collection('places_regions_spots')
      .find({ region_id: { $in: region_ids } })
      .toArray();

    
    const filteredPlaces = allPlaces.filter(place => {
      const placeCategories = place.categories
        .split(',')                   
        .map(cat => cat.trim().toLowerCase()); 
      return userCategories.some(cat => placeCategories.includes(cat));
    });

    res.json(filteredPlaces);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});




// ------------------- Helper: Haversine -------------------
const { Int32 } = require("mongodb");

// ------------------- Helper Functions -------------------
function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Travel time in minutes (4 min per km)
// Travel time in minutes (4 min per km)
function travelTime(distanceKm) {
  return Math.round(distanceKm * 4);
}

// Round to nearest half hour
function roundToHalfHour(hour, minute) {
  if (minute <= 15) return { hour, minute: 0 };
  if (minute <= 45) return { hour, minute: 30 };
  return { hour: hour + 1, minute: 0 };
}

// Format time as HH:MM AM/PM
function formatTime(hour, minute) {
  const suffix = hour >= 12 ? "PM" : "AM";
  const h = hour % 12 === 0 ? 12 : hour % 12;
  return `${h.toString().padStart(2, "0")}:${minute
    .toString()
    .padStart(2, "0")} ${suffix}`;
}

// Generate sequential realistic time slots
function generateTimeSlots(dailySpots) {
  const schedule = [];
  let hour = 9;
  let minute = 0;

  for (let i = 0; i < dailySpots.length; i++) {
    const spot = dailySpots[i];

    // Average duration in minutes
    const dur = spot.avg_duration
      ? parseInt(spot.avg_duration) // e.g., 60, 120
      : 60;

    // Round current start time
    ({ hour, minute } = roundToHalfHour(hour, minute));
    const startHour = hour;
    const startMinute = minute;

    // End time
    let endMinute = startMinute + dur;
    let endHour = startHour + Math.floor(endMinute / 60);
    endMinute = endMinute % 60;

    schedule.push({
      time: `${formatTime(startHour, startMinute)} - ${formatTime(
        endHour,
        endMinute
      )}`,
      activity: spot.place_name,
      travel: `${spot._distanceFromPrev}, ${spot._travelTime}`,
      tips: "", // AI fills later
      budget: "" // AI fills later
    });

    // Prepare time for next spot: end time + travel time
    const travel = i + 1 < dailySpots.length ? travelTime(parseFloat(dailySpots[i + 1]._distanceFromPrev)) : 0;
    minute = endMinute + travel;
    hour = endHour + Math.floor(minute / 60);
    minute = minute % 60;
  }

  return schedule;
}

// Order spots by interests + nearest distance
function orderSpots(spots, interests) {
  const visited = [];
  const remaining = [...spots];

  const scoreSpot = (spot) => {
    let score = 0;
    if (interests) {
      const lowerInt = interests.toLowerCase();
      if (spot.categories?.toLowerCase().includes(lowerInt)) score += 2;
      if (spot.activities?.toLowerCase().includes(lowerInt)) score += 1;
    }
    if (spot.popularity_level === "high") score += 2;
    else if (spot.popularity_level === "medium") score += 1;
    return score;
  };

  remaining.sort((a, b) => scoreSpot(b) - scoreSpot(a));
  let current = remaining.shift();
  current._distanceFromPrev = "0 km";
  current._travelTime = "0 min";
  visited.push(current);

  while (remaining.length > 0) {
    let nearestIdx = 0;
    let nearestDist = Infinity;
    for (let i = 0; i < remaining.length; i++) {
      const dist = haversineDistance(
        current.latitude,
        current.longitude,
        remaining[i].latitude,
        remaining[i].longitude
      );
      if (dist < nearestDist) {
        nearestDist = dist;
        nearestIdx = i;
      }
    }
    current = remaining.splice(nearestIdx, 1)[0];
    current._distanceFromPrev = nearestDist.toFixed(2) + " km";
    current._travelTime = travelTime(nearestDist) + " min";
    visited.push(current);
  }

  return visited;
}

// Split spots evenly across days
function splitSpotsByDays(orderedSpots, days) {
  const spotsPerDay = Math.ceil(orderedSpots.length / days);
  const dailySpots = [];
  for (let i = 0; i < days; i++) {
    dailySpots.push(orderedSpots.slice(i * spotsPerDay, (i + 1) * spotsPerDay));
  }
  return dailySpots;
}



// ------------------- API -------------------
app.post("/generate-itinerary-modified", async (req, res) => {
  try {
    const { region_id, days, interests, budget } = req.body;
    if (!region_id || !days) return res.status(400).json({ error: "region_id and days required" });

    const regionIdInt = new Int32(parseInt(region_id, 10));
    const collection = placesDb.collection("places_regions_spots");
    const spots = await collection.find({ region_id: regionIdInt }).toArray();
    if (!spots.length) return res.status(404).json({ error: "No spots found" });

    // 1. Order spots
    const orderedSpots = orderSpots(spots, interests);

    // 2. Split by days
    const dailySpotsList = splitSpotsByDays(orderedSpots, days);

    // 3. Generate time slots
    const dailySchedules = dailySpotsList.map((dailySpots, idx) => ({
      day: idx + 1,
      schedule: generateTimeSlots(dailySpots)
    }));

    // 4. Build AI prompt for tips & budget
    const aiPrompt = dailySchedules
      .map(
        (day) =>
          `Day ${day.day} schedule:\n${day.schedule
            .map((s) => `${s.activity} | Travel: ${s.travel}`)
            .join("\n")}`
      )
      .join("\n\n") +
      `\n\nFor each activity, provide short tips for visiting and estimated budget in INR. Return ONLY JSON matching the structure:
{
  "itinerary": [
    {
      "day": <day_number>,
      "schedule": [
        {
          "time": "start - end",
          "activity": "Place Name",
          "travel": "distance, time",
          "tips": "short tips",
          "budget": "₹100"
        }
      ]
    }
  ]
}`;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a travel assistant that only fills tips and budget in JSON." },
        { role: "user", content: aiPrompt }
      ]
    });

    let aiContent = response.choices[0].message.content.trim();

// Extract the first {...} block
    const jsonMatch = aiContent.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return res.status(500).json({ error: "AI response JSON not found" });
    }

    let aiItinerary;
    try {
      aiItinerary = JSON.parse(jsonMatch[0]);
    } catch (e) {
      console.error("AI JSON parse error:", e, "AI content:", aiContent);
      return res.status(500).json({ error: "Failed to parse AI JSON" });
    }


    // 5. Merge AI tips & budget with computed times
    const finalItinerary = aiItinerary.itinerary.map((day, i) => ({
      day: day.day,
      schedule: day.schedule.map((s, j) => ({
        ...dailySchedules[i].schedule[j],
        tips: s.tips,
        budget: s.budget
      }))
    }));

    res.json({ itinerary: finalItinerary });
  } catch (err) {
    console.error("Itinerary generation error:", err);
    res.status(500).json({ error: "Failed to generate itinerary" });
  }
});




// Haversine formula to calculate distance between lat/lon in km
function getDistanceFromLatLonInKm(lat1, lon1, lat2, lon2) {
  function deg2rad(deg) {
    return deg * (Math.PI / 180);
  }
  const R = 6371; // Radius of earth in KM
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(deg2rad(lat1)) *
      Math.cos(deg2rad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Parse timing strings into approximate start/end hours (24h)
function parseTimings(timingStr) {
  // timingStr example: "Open from 6 AM to 12:30 PM and 3:30 PM to 8 PM."
  // Return array of { start: hourDecimal, end: hourDecimal }
  const regexTimes = /\b(\d{1,2})(?::(\d{2}))?\s?(AM|PM)\b/gi;
  const times = [];
  let match;
  while ((match = regexTimes.exec(timingStr))) {
    let hour = parseInt(match[1], 10);
    const mins = match[2] ? parseInt(match[2], 10) : 0;
    const pm = match[3].toUpperCase() === 'PM';
    if (hour === 12 && !pm) hour = 0; // 12 AM = 0 hour
    if (pm && hour !== 12) hour += 12;
    const timeDecimal = hour + mins / 60;
    times.push(timeDecimal);
  }
  // Expect pairs for start/end times
  const intervals = [];
  for (let i = 0; i + 1 < times.length; i += 2) {
    intervals.push({ start: times[i], end: times[i + 1] });
  }
  return intervals;
}

// Average visit duration parsing (in hours) from string like "1 to 2 hours"
function parseDuration(durationStr) {
  if (!durationStr) return 1; // default 1 hour if missing
  const match = durationStr.match(/(\d+)(?:\s*to\s*(\d+))?\s*hours?/i);
  if (match) {
    const low = parseInt(match[1], 10);
    const high = match[2] ? parseInt(match[2], 10) : low;
    return (low + high) / 2;
  }
  return 1; // fallback
}

// Average travel speed km/h (local roads)
const TRAVEL_SPEED = 30;

// Function to find best order of places per day minimizing travel & fulfilling popularity/interests priority
function planDayPlaces(places, startPlace = null, interests = []) {
  const popularityScore = { high: 3, medium: 2, low: 1 };

  function matchesInterest(placeCategories, interests) {
    if (!interests || interests.length === 0) return false;
    const cats = placeCategories.toLowerCase();
    return interests.some((interest) =>
      cats.includes(interest.toLowerCase())
    );
  }

  places.forEach((p) => {
    p._popularityScore = popularityScore[p.popularity_level?.toLowerCase()] || 0;
    p._interestMatch = matchesInterest(p.categories, interests) ? 1 : 0;
    p._score = p._popularityScore * 2 + p._interestMatch;
  });

  places.sort((a, b) => b._score - a._score);

  let dayPlan = [];

  let currentPlace = startPlace;
  if (!currentPlace) {
    currentPlace = places.shift();
    dayPlan.push(currentPlace);
  } else {
    const idx = places.findIndex((p) => p.ID === currentPlace.ID);
    if (idx >= 0) places.splice(idx, 1);
    dayPlan.push(currentPlace);
  }

  while (places.length > 0) {
    places.forEach((p) => {
      p._dist = getDistanceFromLatLonInKm(
        currentPlace.latitude,
        currentPlace.longitude,
        p.latitude,
        p.longitude
      );
    });

    places.sort((a, b) => {
      if (b._score !== a._score) return b._score - a._score;
      return a._dist - b._dist;
    });

    const nextPlace = places.shift();
    dayPlan.push(nextPlace);
    currentPlace = nextPlace;
  }

  return dayPlan;
}

// Function to split places into days balancing count and travel
function splitPlacesIntoDays(places, days, interests) {
  let allDays = [];
  let remainingPlaces = [...places];
  let lastPlace = null;

  for (let d = 0; d < days; d++) {
    if (remainingPlaces.length === 0) break;

    let startPlace = null;
    if (lastPlace) {
      remainingPlaces.forEach((p) => {
        p._distFromLast = getDistanceFromLatLonInKm(
          lastPlace.latitude,
          lastPlace.longitude,
          p.latitude,
          p.longitude
        );
      });
      remainingPlaces.sort((a, b) => a._distFromLast - b._distFromLast);
      startPlace = remainingPlaces[0];
    }

    let placeCountForDay = Math.ceil(remainingPlaces.length / (days - d));

    let todayPlaces = remainingPlaces.slice(0, placeCountForDay);

    let dayPlan = planDayPlaces(todayPlaces, startPlace, interests);

    const plannedIds = new Set(dayPlan.map((p) => p.ID));
    remainingPlaces = remainingPlaces.filter((p) => !plannedIds.has(p.ID));

    allDays.push(dayPlan);
    lastPlace = dayPlan[dayPlan.length - 1];
  }

  return allDays;
}

// Assign visit time windows and travel times avoiding overlaps
function assignTimesToDayPlan(dayPlan) {
  let results = [];
  let currentTime = 6.0; // Start 6 AM

  for (let i = 0; i < dayPlan.length; i++) {
    const place = dayPlan[i];

    let intervals = parseTimings(place.timings || place.best_time || '');
    if (!intervals || intervals.length === 0) {
      intervals = [{ start: 6, end: 22 }]; // fallback
    }

    const duration = parseDuration(place.avg_duration || '1 hour');

    let travelDist = 'Starting point';
    let travelTime = 0;
    if (i > 0) {
      const prev = dayPlan[i - 1];
      const distKm = getDistanceFromLatLonInKm(
        prev.latitude,
        prev.longitude,
        place.latitude,
        place.longitude
      );
      travelDist = distKm.toFixed(2) + ' km';
      travelTime = distKm / TRAVEL_SPEED;
      currentTime += travelTime;
    }

    let visitStart = null;
    let visitEnd = null;
    for (const interval of intervals) {
      if (interval.start <= currentTime && currentTime + duration <= interval.end) {
        visitStart = currentTime;
        visitEnd = currentTime + duration;
        break;
      } else if (interval.start > currentTime && interval.start + duration <= interval.end) {
        visitStart = interval.start;
        visitEnd = interval.start + duration;
        break;
      }
    }
    if (visitStart === null) {
      visitStart = intervals[0].start;
      visitEnd = Math.min(visitStart + duration, intervals[0].end);
    }

    function to12hFormat(decimalHours) {
      const h = Math.floor(decimalHours);
      const m = Math.round((decimalHours - h) * 60);
      const ampm = h >= 12 ? 'PM' : 'AM';
      const hour12 = h % 12 === 0 ? 12 : h % 12;
      const mm = m < 10 ? '0' + m : m;
      return `${hour12}:${mm} ${ampm}`;
    }

    results.push({
      time: `${to12hFormat(visitStart)} - ${to12hFormat(visitEnd)}`,
      activity: place.place_name,
      tips: place.tips || '',
      distance_from_prev: travelDist,
    });

    currentTime = visitEnd;
  }

  return results;
}

app.post('/generate-trip-plan', async (req, res) => {
  try {
    const { user } = await getAuthenticatedUser(req, res);
    if (!user) return res.status(401).json({ loggedIn: false, error: 'Authentication required' });

    const { destination, days, interests = '', region_id } = req.body;
    if (!destination || !days || !region_id) {
      return res.status(400).json({ error: 'Destination, days, and region_id are required' });
    }

    if (!placesDb) {
      await connectPlacesDB();
    }

    const placesCollection = placesDb.collection('places_regions_spots');
    let placesCursor = placesCollection.find({ region_id: parseInt(region_id) });
    let places = await placesCursor.toArray();

    if (!places || places.length === 0) {
      return res.status(404).json({ error: 'No places found for this region_id' });
    }

    const interestsArray = interests ? interests.split(',').map((s) => s.trim()) : [];

    const daysPlans = splitPlacesIntoDays(places, days, interestsArray);

    let structuredDays = {};
    for (let i = 0; i < daysPlans.length; i++) {
      const dayPlan = daysPlans[i];
      const timedPlan = assignTimesToDayPlan(dayPlan);
      structuredDays[`day_${i + 1}`] = timedPlan;
    }

    const prompt = `
You are a helpful travel assistant. Given the JSON object below representing a trip plan with days containing places to visit with visitation time windows, distances, and tips, please generate a daily trip itinerary that:

- Arranges the visits in the given order as close as possible
- Makes it sound like a human planned it naturally with travel tips and flow
- Does NOT mention hotels, dining, or unrelated topics
- Ensures each day's activities are clear and easy to follow

Trip plan JSON:
${JSON.stringify(structuredDays, null, 2)}

Respond with the itinerary in plain text without markdown or special characters.
`;

    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: 'You are a helpful travel assistant.' },
        { role: 'user', content: prompt },
      ],
    });

    const itinerary = response.choices[0].message.content;

    res.json({ itinerary, structured_plan: structuredDays });
  } catch (err) {
    console.error('Trip plan generation error:', err);
    res.status(500).json({ error: 'Failed to generate trip plan' });
  }
});



// ------------------- SERVER START -------------------



const mongoURI = process.env.MONGO_URI;

const connectDB = async () => {
  try {
    const client = await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB');
    db = client.connection.db;
    return db;
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
};


const connectPlacesDB = async () => {
  return new Promise((resolve, reject) => {
    try {
      const connection = mongoose.createConnection(process.env.MONGO_PLACES_URI);

      connection.once('open', () => {
        console.log('Connected to Places database');
        placesDb = connection.db;
        resolve(placesDb);
      });

      connection.on('error', (err) => {
        console.error('Places DB connection error:', err);
        reject(err);
      });
    } catch (error) {
      console.error('MongoDB connection error (Places DB):', error);
      reject(error);
    }
  });
};

const startServer = async () => {
  try {
    await connectDB();         // main DB
    await connectPlacesDB();   // places DB

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Enhanced SoulfulYatra server running on port ${PORT}`));
  } catch (err) {
    console.error(err);
  }
};

startServer();
