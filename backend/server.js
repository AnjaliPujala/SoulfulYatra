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
// Middleware
app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: ['https://soulful-yatra.netlify.app', 'http://localhost:3000'],
  credentials: true
}));

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

// Session model for OAuth
const sessionSchema = new mongoose.Schema({
  sessionToken: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Session = mongoose.model('Session', sessionSchema);

// ------------------- OAUTH AUTH -------------------
// Emergent OAuth endpoint
app.post('/auth/oauth/session', async (req, res) => {
  const { session_id } = req.body;

  if (!session_id) {
    return res.status(400).json({ error: 'Session ID required' });
  }

  try {
    // Call Emergent auth API
    const response = await fetch('https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data', {
      method: 'GET',
      headers: {
        'X-Session-ID': session_id,
        'Content-Type': 'application/json'
      }
    });

    const authData = await response.json();

    if (!response.ok) {
      return res.status(400).json({ error: 'Invalid session ID' });
    }

    // Check if user exists, if not create new user
    let user = await User.findOne({ email: authData.email });
    if (!user) {
      user = new User({
        name: authData.name,
        email: authData.email,
        picture: authData.picture,
        phone: '', // OAuth users may not have phone initially
        oauthProvider: 'google'
      });
      await user.save();
    }

    // Create session token
    const sessionToken = authData.session_token;
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await Session.create({
      sessionToken,
      userId: user._id,
      expiresAt
    });

    // Set session cookie
    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      secure: true,//process.env.NODE_ENV === 'production',//true
      sameSite: 'none',//none
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });

    res.json({
      message: 'Authentication successful',
      user: {
        name: user.name,
        email: user.email,
        picture: user.picture
      }
    });

  } catch (error) {
    console.error('OAuth authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// ------------------- AUTHENTICATION MIDDLEWARE FUNCTIONS -------------------

// Function to validate JWT token
const validateToken = (token) => {
  try {
    return jwt.verify(token, process.env.TOKEN_KEY);
  } catch {
    return null;
  }
};

// Function to validate OAuth session
const validateOAuthSession = async (sessionToken) => {
  try {
    const session = await Session.findOne({
      sessionToken,
      expiresAt: { $gt: new Date() }
    }).populate('userId');

    return session ? session.userId : null;
  } catch (err) {
    console.error('OAuth session validation error:', err);
    return null;
  }
};

// Function to get user from authentication (tries OAuth first, then JWT)
const getAuthenticatedUser = async (req) => {
  try {
    const sessionToken = req.cookies.session_token;
    const jwtToken = req.cookies.token;

    // Try OAuth session first
    if (sessionToken) {
      const oauthUser = await validateOAuthSession(sessionToken);
      if (oauthUser) {
        return { user: oauthUser, authType: 'oauth' };
      }
    }

    // Fallback to JWT token
    if (jwtToken) {
      const jwtUser = validateToken(jwtToken);
      if (jwtUser) {
        return { user: jwtUser, authType: 'jwt' };
      }
    }

    return { user: null, authType: null };
  } catch (err) {
    console.error('Authentication error:', err);
    return { user: null, authType: null };
  }
};

// Middleware function to check authentication
const requireAuth = async (req, res, next) => {
  const { user, authType } = await getAuthenticatedUser(req);

  if (!user) {
    return res.status(401).json({
      loggedIn: false,
      error: 'Authentication required'
    });
  }

  req.user = user;
  req.authType = authType;
  next();
};

// ------------------- AUTHENTICATION ENDPOINTS -------------------

// Check authentication status
app.get('/check-auth', async (req, res) => {
  try {
    const { user, authType } = await getAuthenticatedUser(req);

    if (!user) {
      return res.json({ loggedIn: false });
    }

    // For OAuth users, return user object
    //if (authType === 'oauth') {
    //return res.json({
    //loggedIn: true,
    //user: user
    //});
    //}

    // For JWT users, fetch full user data from database
    try {
      const fullUser = await User.findOne({ email: user.email }).select('-password');
      //console.log(password);
      return res.json({
        loggedIn: true,
        user: fullUser
      });
    } catch (dbErr) {
      console.error('Database error fetching user:', dbErr);
      // Fallback to email only if database query fails
      return res.json({
        loggedIn: true,
        user: { email: user.email }
      });
    }
  } catch (err) {
    console.error('Check auth error:', err);
    return res.json({ loggedIn: false });
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
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ email }, process.env.TOKEN_KEY, { expiresIn: '1h' });


    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
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

// Token validation (updated for OAuth)
const validateAuth = async (req) => {
  const token = req.cookies.token;
  const sessionToken = req.cookies.session_token;

  try {
    // Check OAuth session first
    if (sessionToken) {
      const session = await Session.findOne({
        sessionToken,
        expiresAt: { $gt: new Date() }
      }).populate('userId');

      if (session) {
        return { valid: true, user: session.userId };
      }
    }

    // Fallback to JWT token
    if (token) {
      const decoded = jwt.verify(token, process.env.TOKEN_KEY);
      const user = await User.findOne({ email: decoded.email });
      return { valid: true, user };
    }

    return { valid: false };
  } catch {
    return { valid: false };
  }
};

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
    const { user, authType } = await getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({
        loggedIn: false,
        error: 'Authentication required'
      });
    }

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
    console.error(err);
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
  const { user, authType } = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({
      loggedIn: false,
      error: 'Authentication required'
    });
  }

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
  const { user, authType } = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({
      loggedIn: false,
      error: 'Authentication required'
    });
  }

  const { lat, lon, radius = 10000 } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'lat & lon required' });

  try {
    const restaurants = await fetchPlacesByRadius(lat, lon, radius, 'foods', 50, restaurantsCache);
    res.json({ restaurants });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch restaurants' });
  }
});

// ------------------- SAVE TRIPS -------------------
app.post('/save-trip', async (req, res) => {
  const { user, authType } = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({
      loggedIn: false,
      error: 'Authentication required'
    });
  }

  try {
    const email = authType === 'oauth' ? user.email : user.email;
    const { destination, interests, tripData, days, transportation, hotels } = req.body;
    const daysNumber = Number(days);

    if (!destination || !tripData)
      return res.status(400).json({ error: 'Destination and trip data are required' });

    const existingTrip = await SavedTrip.findOne({ email, destination, days: daysNumber });
    if (existingTrip) {
      return res.status(400).json({ error: 'This trip is already saved!' });
    }

    await SavedTrip.create({
      email,
      destination,
      days: daysNumber,
      interests,
      tripData,
      transportation: transportation || {},
      hotels: hotels || []
    });

    res.json({ message: 'Trip saved successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error saving trip' });
  }
});

// ------------------- PROFILE -------------------
app.get('/profile', async (req, res) => {
  try {
    const { user: authUser, authType } = await getAuthenticatedUser(req);
    if (!authUser) {
      return res.status(401).json({
        loggedIn: false,
        error: 'Authentication required'
      });
    }

    // For OAuth users, we already have the user object
    if (authType === 'oauth') {
      return res.json({ user: authUser });
    }

    // For JWT users, fetch from database
    const email = authUser.email;
    const user = await User.find({ email: email });
    //console.log(user_details);
    //const user = await User.findById(authUser._id).select('-password');
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ user });
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
});

app.get("/get-saved-trips", async (req, res) => {
  try {
    const { user, authType } = await getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({
        loggedIn: false,
        error: 'Authentication required'
      });
    }

    const email = authType === 'oauth' ? user.email : user.email;
    const trips = await SavedTrip.find({ email });
    res.json({ trips });
  } catch (err) {
    console.error("Error fetching saved trips:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------- SERVER START -------------------
connectDB().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Enhanced SoulfulYatra server running on port ${PORT}`));
}).catch(err => console.error(err));