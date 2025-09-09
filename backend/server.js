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
const path = require('path');
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
      user: { name: user.name, email: user.email, phone: user.phone },
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

    const { destination, days, interests } = req.body;
    if (!destination || !days) return res.status(400).json({ error: 'Destination and days are required' });

    const prompt = `
Plan a ${days}-day trip to ${destination} for a user interested in ${interests || 'general activities'}.
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


/*app.post('/generate-itinerary', async (req, res) => {
  try {
    const auth = await validateAuth(req);
    if (!auth.valid) return res.status(401).json({ error: 'Unauthorized' });

    const { destination, days, interests, budget, travelStyle } = req.body;
    if (!destination || !days) return res.status(400).json({ error: 'Destination and days are required' });

    // Use Emergent LLM for enhanced AI features
    const prompt = `Create a detailed ${days}-day travel itinerary for ${destination}.

User Preferences:
- Interests: ${interests || 'general activities'}
- Budget: ${budget || 'moderate'}
- Travel Style: ${travelStyle || 'balanced'}

Please provide:
1. Daily detailed schedule with specific timings
2. Transportation recommendations between locations
3. Accommodation suggestions for each area
4. Local dining recommendations
5. Cultural tips and local customs
6. Budget estimates for activities
7. Weather considerations and packing tips

Format the response as a structured itinerary with clear day-by-day breakdown.`;

    try {
      // Initialize Emergent LLM Chat
      const { LlmChat, UserMessage } = require('emergentintegrations/llm/chat');

      const chat = new LlmChat(
        process.env.EMERGENT_LLM_KEY,
        `itinerary-${Date.now()}`,
        "You are an expert travel planner with extensive knowledge of destinations worldwide. Provide detailed, practical, and personalized travel recommendations."
      ).with_model("openai", "gpt-4o");

      const userMessage = new UserMessage(prompt);
      const response = await chat.send_message(userMessage);

      res.json({ itinerary: response });
    } catch (llmError) {
      console.error('LLM error, falling back to basic response:', llmError);
      // Fallback to basic itinerary
      const basicItinerary = `${days}-day trip to ${destination}\n\nDay 1: Arrival and city exploration\n- Morning: Check-in to accommodation\n- Afternoon: Visit main attractions\n- Evening: Try local cuisine\n\nAdditional days would include cultural sites, local experiences, and recommended activities based on ${interests || 'general travel interests'}.`;
      res.json({ itinerary: basicItinerary });
    }
  } catch (err) {
    console.error('Itinerary generation error:', err);
    res.status(500).json({ error: 'Failed to generate itinerary' });
  }
});*/

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

// ------------------- TRANSPORTATION -------------------
// Google Directions API integration for transportation options
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
          estimatedCost: Math.round(route.distance / 1000 * 0.5), // Rough estimate
          bookingUrl: `https://www.uber.com/?pickup=${origin}&dropoff=${destination}`
        },
        public_transit: {
          duration: Math.round(route.duration / 60 * 1.5), // Assume transit takes 50% longer
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

// ---------- TEST PUSH: 5 minutes after save ----------
//cron.schedule('*/1 * * * * ', () => {
//console.log('⏰ Running test trip notification job (5 min delay)...');
//sendTripNotifications(5); // check trips older than 5 minutes
//});

// ---------- PRODUCTION: 24 hours after save ----------
cron.schedule('0 * * * *', () => { // every hour
  sendTripNotifications(1440); // 1440 minutes = 24 hours
});

//vlogs
const multer = require('multer');


/*const storage = new GridFsStorage({
  url: mongoURI,
  options: { useUnifiedTopology: true },
  file: (req, file) => {
    return {
      filename: `vlog-${Date.now()}${path.extname(file.originalname)}`,
      bucketName: 'vlogs',
    };
  },
});*/

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads')
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, "vlogs-image-" + Date.now() + "-" + file.originalname);
  }
})

const upload = multer({ storage })

// ----------------- Vlog Schema -----------------
const Vlog = require('./models/Vlogs');

// ----------------- Upload Route -----------------
app.post('/create-vlog', upload.single('vlog'), async (req, res) => {
  try {
    const { userEmail, title, description, tags } = req.body;
    const { path } = req.file;
    if (!userEmail || !title || !req.file) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const newVlog = new Vlog({
      userEmail,
      title,
      description,
      tags: tags ? tags.split(',').map((t) => t.trim()) : [],
      path
    });

    await newVlog.save();
    res.status(201).json({ message: 'Vlog uploaded successfully', vlog: newVlog });
  } catch (err) {
    console.error('Error creating vlog:', err);
    res.status(500).json({ error: 'Failed to create vlog' });
  }
});

// ----------------- Fetch Vlog File -----------------
aapp.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Get all vlogs
app.get('/vlogs', async (req, res) => {
  const searchQuery = req.query.search || "";
  const filter = searchQuery
    ? {
      $or: [
        { title: { $regex: searchQuery, $options: "i" } },
        { description: { $regex: searchQuery, $options: "i" } },
      ]
    }
    : {};

  try {
    const vlogs = await Vlog.find(filter).sort({ createdAt: -1 });
    const formattedVlogs = vlogs.map(vlog => ({
      _id: vlog._id,
      userEmail: vlog.userEmail,
      title: vlog.title,
      description: vlog.description,
      tags: vlog.tags,
      fileUrl: `${req.protocol}://${req.get("host")}/${vlog.path}`,
      createdAt: vlog.createdAt,
    }));
    res.json({ vlogs: formattedVlogs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch vlogs" });
  }
});

// Get single vlog file
app.get("/vlogs/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const vlog = await Vlog.findById(id);
    if (!vlog) return res.status(404).json({ msg: "Vlog Not Found" });
    const filePath = path.join(__dirname, vlog.path);
    res.sendFile(filePath);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Unable to get vlog file" });
  }
});
// ------------------- SERVER START -------------------
connectDB().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Enhanced SoulfulYatra server running on port ${PORT}`));
}).catch(err => console.error(err));