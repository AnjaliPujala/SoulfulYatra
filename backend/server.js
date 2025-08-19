require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
<<<<<<< HEAD
const path = require('path'); 
const util = require('util');
=======
const path = require('path'); // ✅ added

>>>>>>> 9e9cadd91467a37f41aa099c2b8791bb0f88c70f
const app = express();
const fetch = require('node-fetch');
const OpenAI = require('openai');
app.use(cors());
app.use(express.json());

<<<<<<< HEAD

let db;
const connectDB = async () => {
  try {
    const client=await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to database');
    db= client.connection.db; 
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
};


const User = require('./models/Users');


// get user by email and phone
=======
// Serve React frontend in production
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const User = require('./models/Users');
const connectDB = require('./database');

// Example API endpoint
>>>>>>> 9e9cadd91467a37f41aa099c2b8791bb0f88c70f
app.get('/get-user', async (req, res) => {
  const { email, phone } = req.query;

  if (!email || !phone) {
    return res.status(400).json({ error: "Email and phone are required" });
  }

  try {
<<<<<<< HEAD
    const user = await User.findOne({ email});
=======
    const user = await User.findOne({ email, phone: phone.toString() });
>>>>>>> 9e9cadd91467a37f41aa099c2b8791bb0f88c70f
    if (user) {
      return res.json({ user, message: "User already exists" });
    }
    const userByPhone = await User.findOne({phone: phone.toString() });
    if (userByPhone) {
      return res.json({ user: userByPhone, message: "User already exists with this phone number" });
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
//get places
async function getLatLonFromName(name) {
  const url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(name)}&limit=1`;
  const response = await fetch(url, {
    headers: { 'User-Agent': 'PlaceFinder/1.0 (anjalipujala001@gmail.com)' }
  });
  if (!response.ok) throw new Error('Failed to fetch from Nominatim');
  const data = await response.json();
  if (data.length === 0) return null;
  return {
    lat: parseFloat(data[0].lat),
    lon: parseFloat(data[0].lon),
    boundingbox: data[0].boundingbox 
  };
}

<<<<<<< HEAD
//get places from mongodb
app.get('/get-places',async(req,res)=>{
  try{
    const collection=db.collection('places'); 
    const places=await collection.find({}).toArray();
    if(places.length === 0) {
      return res.status(404).json({ message: 'No places found' });
    }
    return res.status(200).json({ places });
  }catch(err){
    console.error('Error fetching places:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
})

//get place by state from open trip map api

app.get('/get-places-by-name', async (req, res) => {
  const { name } = req.query;
  if (!name) {
    return res.status(400).json({ error: 'State name is required' });
  } 
  try {
    const places = await getPlacesByName(name);
    if (places.length === 0) {
      return res.status(404).json({ message: 'No places found' });
    }
    res.status(200).json({ places });
  } catch (error) {
    console.error('Error fetching places by state:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

async function getPlacesByName(name) {
  const apiKey = process.env.OPEN_TRIP_MAP_API_KEY;
  const geocodeData = await getLatLonFromName(name);

  if (!geocodeData) return [];

  const [lat_min, lat_max, lon_min, lon_max] = geocodeData.boundingbox.map(Number);

  const url = `https://api.opentripmap.com/0.1/en/places/bbox?lon_min=${lon_min}&lat_min=${lat_min}&lon_max=${lon_max}&lat_max=${lat_max}&apikey=${apiKey}&limit=50`;

  const response = await fetch(url);
  if (!response.ok) throw new Error('Failed to fetch places');

  const data = await response.json();
  return data.features || [];
}




//fetch place images by xid
app.get('/get-place-image', async (req, res) => {
  const { xid } = req.query;
  if (!xid) {
    return res.status(400).json({ error: 'XID is required' });
  }

  try {
    const apiKey = process.env.OPEN_TRIP_MAP_API_KEY;
    const url = `https://api.opentripmap.com/0.1/en/places/xid/${xid}?apikey=${apiKey}`;
    const response = await fetch(url);

    if (!response.ok) {
      const errorData = await response.json();
      return res.status(response.status).json({ error: errorData.error || 'Failed to fetch place' });
    }

    const data = await response.json();

    // Send the preview image if available
    if (data) {
      res.json({ data});
    } else {
      res.status(404).json({ error: 'Image not found for this place' });
    }
  } catch (error) {
    console.error('Error fetching place image:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// Generate itinerary
const openai = new OpenAI({
  apiKey: process.env.OPEN_AI_API,
});


function validateToken(token) {
  try {
    // This will throw an error if token is invalid or expired
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    return decoded; // contains the payload, e.g., { email, iat, exp }
  } catch (err) {
    return null; // invalid token
  }
}

app.post('/generate-itinerary', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (!validateToken(token)) return res.status(401).json({ error: 'Invalid token' });

    const { destination, days, interests } = req.body;

    if (!destination || !days) {
      return res.status(400).json({ error: 'Destination and days are required' });
    }

    const prompt = `
Plan a ${days}-day trip to ${destination} for a user interested in ${interests || 'general activities'}.
Provide the response in plain text only, without Markdown, asterisks, or headers.
Include daily schedule, travel tips, and approximate durations.
`;


    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: 'You are a helpful travel assistant.' },
        { role: 'user', content: prompt },
      ],
      max_tokens: 1000,
    });

    const itinerary = response.choices[0].message.content;

    res.json({ itinerary });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to generate itinerary' });
  }
});


=======
>>>>>>> 9e9cadd91467a37f41aa099c2b8791bb0f88c70f
// Start server after DB connects
connectDB().then(() => {
  const PORT = process.env.PORT || 5000; // ✅ dynamic port for Azure
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
});
