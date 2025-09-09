const mongoose = require('mongoose');

const VlogSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    title: { type: String, required: true },
    description: String,
    tags: [String],
    fileId: { type: mongoose.Schema.Types.ObjectId, required: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Vlog', VlogSchema);
