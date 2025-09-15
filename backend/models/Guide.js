// models/Guide.js
const mongoose = require("mongoose");

const Guide = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    }, // Reference to the User's email
    places: {
        type: [String],
        required: true
    }, // Places/cities the guide covers
    rating: {
        type: Number,
        default: 0
    }, // Average rating
    description: {
        type: String
    }, // Optional description or bio
}, { timestamps: true });

module.exports = mongoose.model("Guide", Guide);
