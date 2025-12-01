const mongoose = require("mongoose");

const NonceSchema = new mongoose.Schema({
  valor: {
    type: String,
    required: true,
    unique: true,
  },
  usuarioId: {
    type: String,
    required: true,
  },
  fechaCreacion: {
    type: Date,
    default: Date.now,
    expires: 300, // TTL: El documento se autodestruye en 300 segundos (5 min)
  },
});

module.exports = mongoose.model("Nonce", NonceSchema);
