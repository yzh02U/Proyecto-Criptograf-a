require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const http = require("http"); // 1. Importamos HTTP nativo
const { Server } = require("socket.io"); // 2. Importamos Socket.io

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// 3. Crear el servidor HTTP envolviendo a Express
const server = http.createServer(app);

// 4. Configurar Socket.io
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"],
  },
});

// 5. Manejar conexiones de Socket
io.on("connection", (socket) => {
  console.log(` Atacante conectado: ${socket.id}`);

  socket.on("disconnect", () => {
    console.log(` Atacante desconectado: ${socket.id}`);
  });
});

// 6. Inyectar 'io' en las rutas (Middleware)
// Esto permite que tus rutas en 'userRoutes.js' puedan usar req.io.emit()
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Rutas
app.use("/api/users", require("./Routes/userRoutes"));

// Conexión a Mongo
const MONGO_URI = process.env.MONGO_URI;
mongoose
  .connect(MONGO_URI)
  .then(() => console.log(" Conectado a MongoDB"))
  .catch((err) => console.error(" Error de conexión:", err));

const PORT = 3001;
server.listen(PORT, () => {
  console.log(` Servidor (HTTP + WebSockets) corriendo en puerto ${PORT}`);
});
