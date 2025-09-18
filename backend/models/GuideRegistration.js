const mongoose = require("mongoose");

const guideRegistrationSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true }, // store hashed password
    places: { type: [String], required: true },
    description: { type: String },
    baseFare: { type: Number, required: true, default: 1000 },
    govtCertificateUrl: { type: String }, // optional
    aadhaarCardUrl: { type: String, required: true },
    isApproved: { type: Boolean, default: false }, // admin decision
}, { timestamps: true });

module.exports = mongoose.model("GuideRegistration", guideRegistrationSchema);
