const mongoose = require('mongoose');

const CommentSchema = new mongoose.Schema({
    vlogId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vlog', required: true },
    userEmail: { type: String, required: true },
    userName: { type: String, required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Comment', CommentSchema);
