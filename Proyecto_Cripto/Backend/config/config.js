// server/config/db.js
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    // Lee la variable del archivo .env
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`✅ MongoDB Conectado: ${conn.connection.host}`);
  } catch (error) {
    console.error(`❌ Error conectando a Mongo: ${error.message}`);
    process.exit(1); // Detiene la app si no hay base de datos
  }
};

module.exports = connectDB;
