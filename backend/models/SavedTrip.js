const mongoose = require('mongoose');

const SavedTripSchema = new mongoose.Schema({
  email: { type: String, required: true },
  destination: { type: String, required: true },
  days: { type: Number },
  interests: [String],
  savedAt: { type: Date, default: Date.now },
  notified: { type: Boolean, default: false }, // track if notification sent
});

module.exports = mongoose.model('SavedTrip', SavedTripSchema);
