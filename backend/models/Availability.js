// models/Availability.js
const mongoose = require('mongoose');

const availabilitySchema = new mongoose.Schema(
    {
        guideEmail: {
            type: String,
            required: true,
            index: true, // helps to fetch availability for a specific guide
        },
        availableDates: {
            type: [Date], // array of dates
            default: [],
        },
    },
    { timestamps: true }
);

module.exports = mongoose.model('Availability', availabilitySchema);
