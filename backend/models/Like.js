const mongoose = require('mongoose');

const LikeSchema = new mongoose.Schema({
    vlogId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vlog', required: true },
    userEmail: { type: String, required: true },
    userName: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Like', LikeSchema);
