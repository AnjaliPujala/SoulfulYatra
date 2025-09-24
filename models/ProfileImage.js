const mongoose = require("mongoose");

const ProfileImageSchema = new mongoose.Schema({
    userEmail: { type: String, required: true, unique: true },
    profileImageUrl: { type: String, required: true } // Cloudinary URL
}, { timestamps: true });

module.exports = mongoose.model("ProfileImage", ProfileImageSchema);
