// models/Bookings.js
const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema(
    {
        guideEmail: {
            type: String,
            required: true,
            index: true, // helps to fetch bookings for a guide
        },
        userEmail: {
            type: String,
            required: true,
        },
        userName: {
            type: String,
            required: true,
        },
        date: {
            type: Date,
            required: true,
        },
        status: {
            type: String,
            enum: ["Pending", "Confirmed", "Rejected", "Completed"],
            default: "Pending",
        },
        notes: {
            type: String,
            default: "",
        },
        price: {
            type: Number,
            default: 0,
        },
    },
    { timestamps: true }
);

// Use CommonJS export
module.exports = mongoose.model("Booking", bookingSchema);
