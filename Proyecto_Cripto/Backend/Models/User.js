// server/models/User.js
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  idPersonalizado: {
    type: String,
    required: true,
    unique: true, // Evita IDs duplicados
  },
  pass: {
    type: String,
    required: true,
  },
  money: {
    type: Number,
    required: true,
  },
  fechaCreacion: {
    type: Date,
    default: Date.now,
  },
  Clave: {
    type: String,
    default: "",
  },
});

// Esto creará la colección 'users' en MongoDB Atlas
module.exports = mongoose.model("User", UserSchema);
