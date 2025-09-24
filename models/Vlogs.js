// models/Vlogs.js
const mongoose = require('mongoose');

const VlogSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    userName: { type: String, required: true },
    title: { type: String, required: true },
    description: String,
    tags: [String],

    // For Cloudinary
    imageUrl: { type: String, required: true }, // <-- Store Cloudinary URL
    // path: { type: String, required: true },   // <-- REMOVE or make optional if no longer used

    likeCount: { type: Number, default: 0 },
    commentCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Vlog', VlogSchema);
