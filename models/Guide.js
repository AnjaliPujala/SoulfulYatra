const mongoose = require("mongoose");

const Guide = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    places: {
        type: [String],
        required: true
    },
    rating: {
        type: Number,
        default: 0
    },
    description: {
        type: String
    },
    baseFare: {
        type: Number,
        required: true,
        default: 1000 // in INR
    },
    govtCertificateUrl: {
        type: String,
        required: false
    },
    reviewLinks: {
        type: [String],
        default: []
    },
    isApproved: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

module.exports = mongoose.model("Guide", Guide);
