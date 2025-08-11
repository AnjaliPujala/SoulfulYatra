const mongoose = require('mongoose');
// User schema & model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  phone: { type: String, required: true },

  password: String, // hashed password
});

const User = mongoose.model('User', userSchema);

module.exports = User;
