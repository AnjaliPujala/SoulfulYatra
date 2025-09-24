const mongoose = require("mongoose");

const guideRegistrationSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    places: { type: [String], required: true },
    description: { type: String },
    languages: { type: [String], default: [] },
    reviewLinks: { type: [String], default: [] },
    baseFare: { type: Number, required: true, default: 1000 },
    fareType: { type: String, enum: ["per_day", "half_day", "per_person"], default: "per_day" },
    govtCertificatePublicId: { type: String },
    // aadhaarCardPublicId: { type: String, required: true }, // REMOVE THIS
    isApproved: { type: Boolean, default: false },
}, { timestamps: true });

module.exports = mongoose.model("GuideRegistration", guideRegistrationSchema);
