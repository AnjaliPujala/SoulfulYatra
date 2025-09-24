const mongoose = require("mongoose");

const Guide = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        phone: {
            type: String,
            required: true,
            trim: true,
        },
        places: {
            type: [String],
            required: true,
        },
        languages: {
            type: [String],
            default: [],
        },
        rating: {
            type: Number,
            default: 0,
        },
        description: {
            type: String,
        },
        baseFare: {
            type: Number,
            required: true,
            default: 1000, // in INR
        },
        fareType: {
            type: String,
            enum: ["per_day", "half_day", "per_person"],
            default: "per_day",
        },
        govtCertificateUrl: {
            type: String,
            required: false,
        },
        reviewLinks: {
            type: [String],
            default: [],
        },
        isApproved: {
            type: Boolean,
            default: false,
        },
    },
    { timestamps: true }
);

module.exports = mongoose.model("Guide", Guide);
