// /server/index.js
const express = require("express");
const cors = require("cors"); // Permite que React se comunique con este servidor
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// LA CLAVE SECRETA (Nunca sale de este archivo)
const SECRET_KEY = "mi_secreto_super_seguro_banco_123";

app.post("/api/validar", (req, res) => {
  const { mensaje, hmacRecibido } = req.body;

  console.log("Recibido:", mensaje);

  // 1. El servidor calcula SU propio hash con el mensaje que llegó
  const hmacCalculado = crypto
    .createHmac("sha256", SECRET_KEY)
    .update(mensaje)
    .digest("hex");

  // 2. Compara el calculado con el que envió el cliente
  if (hmacCalculado === hmacRecibido) {
    res.json({
      status: "success",
      texto: "✅ Transacción Aprobada: Integridad Correcta",
    });
  } else {
    res.json({
      status: "error",
      texto: "❌ ALERTA: Los datos fueron modificados (Ataque Detectado)",
    });
  }
});

app.listen(3001, () => {
  console.log("Servidor del Banco corriendo en puerto 3001");
});
