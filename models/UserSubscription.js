// models/UserSubscription.js
const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    subscription: { type: Object, required: true }, // The push subscription object
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('UserSubscription', subscriptionSchema);
