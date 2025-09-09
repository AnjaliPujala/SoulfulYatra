const mongoose = require('mongoose');
const savedTripSchema = new mongoose.Schema({
  email: { type: String, required: true },
  destination: { type: String, required: true },
  days: { type: Number, required: true },
  interests: { type: [String], default: [] }, // <- change here
  tripData: { type: Array, required: true },
  savedAt: { type: Date, default: Date.now },
  notified: { type: Boolean, default: false },
});

module.exports = mongoose.model('SavedTrip', savedTripSchema);
