const express = require("express");
const router = express.Router();
const User = require("../models/User");
const Nonce = require("../Models/Nonce"); // Modelo para guardar nonces usados
const CryptoJS = require("crypto-js");

// --- ESTADOS EN MEMORIA (Control de Ataques) ---
let MODO_SUPRESION = false;

// ==========================================
// RUTAS DE CONTROL DEL ATACANTE
// ==========================================
router.post("/configurar-ataque", (req, res) => {
  const { supresionActiva } = req.body;
  MODO_SUPRESION = supresionActiva;
  console.log(
    ` MODO SUPRESIÓN: ${MODO_SUPRESION ? "ACTIVADO" : "DESACTIVADO"}`
  );
  res.json({ msg: `Supresión ${MODO_SUPRESION ? "Activada" : "Desactivada"}` });
});

router.get("/estado-ataque", (req, res) => {
  res.json({ supresion: MODO_SUPRESION });
});

// ==========================================
// 1. RUTA: CREAR USUARIO (Registro)
// ==========================================
router.post("/crear", async (req, res) => {
  const { id, password, money } = req.body;
  if (!id || !password) return res.status(400).json({ msg: "Faltan datos" });

  try {
    const existe = await User.findOne({ idPersonalizado: id });
    if (existe) return res.status(400).json({ msg: "Usuario ya existe" });

    // Generamos clave única para firma HMAC
    const claveUnica = require("crypto").randomBytes(16).toString("hex");
    const nuevo = new User({
      idPersonalizado: id,
      pass: password,
      money: money || 1000,
      Clave: claveUnica,
    });
    await nuevo.save();
    res.json({ msg: "Usuario creado", usuario: nuevo });
  } catch (e) {
    res.status(500).json({ msg: "Error server" });
  }
});

// ==========================================
// 2. RUTA: LOGIN (Ingreso)
// ==========================================
router.post("/login", async (req, res) => {
  const { id, password } = req.body;
  try {
    const user = await User.findOne({ idPersonalizado: id });
    if (!user || user.pass !== password)
      return res.status(400).json({ msg: "Credenciales inválidas" });

    // Enviamos la clave al frontend para que pueda firmar
    res.json({
      msg: "Login OK",
      usuario: {
        idPersonalizado: user.idPersonalizado,
        money: user.money,
        Clave: user.Clave,
      },
    });
  } catch (e) {
    res.status(500).json({ msg: "Error server" });
  }
});

// ==========================================
// 3. RUTA: AGREGAR DINERO
// ==========================================
router.put("/agregar-dinero", async (req, res) => {
  const { id, monto } = req.body;
  try {
    const user = await User.findOne({ idPersonalizado: id });
    if (!user) return res.status(404).json({ msg: "Usuario no existe" });
    user.money = Number(user.money) + Number(monto);
    await user.save();
    res.json({ msg: "Saldo actualizado", nuevoSaldo: user.money });
  } catch (e) {
    res.status(500).json({ msg: "Error server" });
  }
});

// ==========================================
// 4. RUTA: TRANSFERIR (CORE DE SEGURIDAD)
// ==========================================
router.post("/transferir", async (req, res) => {
  const { idEmisor, datosJson, hmacRecibido, algoritmo, esAtacante } = req.body;

  try {
    // A. WEBSOCKET
    // Siempre avisamos a los atacantes conectados antes de decidir si procesamos
    if (req.io) {
      req.io.emit("paquete_interceptado", {
        idEmisor,
        datosJson,
        hmacRecibido,
        algoritmo,
        timestamp: new Date().toISOString(),
      });
    }

    // B. SUPRESIÓN DE PAQUETES (DoS Selectivo)
    // Si la supresión está activa y NO eres el atacante, bloqueamos.
    if (MODO_SUPRESION && !esAtacante) {
      console.log(` PAQUETE SUPRIMIDO de: ${idEmisor}`);
      return res.status(503).json({
        msg: "Error de Red: El servidor no respondió (Supresión MITM).",
      });
    }

    // Validación Básica de Integridad del JSON
    if (!datosJson || typeof datosJson !== "string") {
      return res.status(400).json({ msg: "Paquete corrupto (Payload vacío)." });
    }

    // Parseamos los datos del mensaje
    const datosObj = JSON.parse(datosJson);
    const { para, cantidad, time, nonce } = datosObj;

    console.log(
      ` Procesando: ${idEmisor} -> ${para} ($${cantidad}) | Nonce: ${
        nonce ? "SÍ" : "NO"
      }`
    );

    // --- C. DEFENSA ANTI-REPLAY: NONCE EN MONGODB ---
    if (nonce) {
      // 1. Buscamos si este nonce ya se usó antes
      const nonceUsado = await Nonce.findOne({ valor: nonce });

      if (nonceUsado) {
        console.log(` REPLAY ATTACK DETECTADO: Nonce ${nonce} reutilizado.`);
        return res.status(403).json({
          msg: "ALERTA CRÍTICA: Transacción duplicada (Nonce ya utilizado).",
        });
      }

      // 2. Si es nuevo, lo guardamos para el futuro
      // (El modelo tiene TTL, se borrará solo en 5 min)
      await new Nonce({ valor: nonce, usuarioId: idEmisor }).save();
    }

    // --- D. VALIDACIONES LÓGICAS ---
    if (idEmisor === para)
      return res
        .status(400)
        .json({ msg: "No puedes transferirte a ti mismo." });

    // --- E. VALIDACIÓN TIMESTAMP ---
    const ahora = Date.now();
    if (ahora - time > 0.5 * 60 * 1000)
      return res
        .status(401)
        .json({ msg: "Solicitud expirada (Timestamp antiguo)." });
    if (time > ahora + 60000)
      return res.status(401).json({ msg: "Timestamp del futuro inválido." });

    // --- F. VALIDACIÓN HMAC ---
    const emisor = await User.findOne({ idPersonalizado: idEmisor });
    if (!emisor) return res.status(404).json({ msg: "Emisor desconocido." });

    const claveSecreta = emisor.Clave || "secreto123";
    let hmacCalculado;

    switch (algoritmo) {
      case "SHA2-256":
        hmacCalculado = CryptoJS.HmacSHA256(datosJson, claveSecreta);
        break;
      case "SHA2-512":
        hmacCalculado = CryptoJS.HmacSHA512(datosJson, claveSecreta);
        break;
      case "SHA3-256":
        hmacCalculado = CryptoJS.HmacSHA3(datosJson, claveSecreta, {
          outputLength: 256,
        });
        break;
      case "SHA3-512":
        hmacCalculado = CryptoJS.HmacSHA3(datosJson, claveSecreta, {
          outputLength: 512,
        });
        break;
      case "MD5":
        hmacCalculado = CryptoJS.HmacMD5(datosJson, claveSecreta);
        break;
      case "SHA-1":
        hmacCalculado = CryptoJS.HmacSHA1(datosJson, claveSecreta);
        break;
      case "WHIRLPOOL":
        hmacCalculado =
          "SIMULACION_WHIRLPOOL_" +
          CryptoJS.HmacSHA512(datosJson, claveSecreta);
        break;
      default:
        hmacCalculado = CryptoJS.HmacSHA256(datosJson, claveSecreta);
    }

    if (hmacCalculado.toString() !== hmacRecibido) {
      return res
        .status(401)
        .json({ msg: "ALERTA: Integridad Comprometida (HMAC Inválido)." });
    }

    // --- G. TRANSFERENCIA DE FONDOS ---
    if (Number(emisor.money) < Number(cantidad))
      return res.status(400).json({ msg: "Fondos insuficientes." });

    const destinatario = await User.findOne({ idPersonalizado: para });
    if (!destinatario)
      return res.status(404).json({ msg: "Destinatario no existe." });

    emisor.money -= Number(cantidad);
    destinatario.money += Number(cantidad);
    await emisor.save();
    await destinatario.save();

    res.json({
      msg: "Transferencia Exitosa y Verificada.",
      nuevoSaldo: emisor.money,
    });
  } catch (error) {
    console.error("Error en transferencia:", error);
    // Manejo de error específico de Mongo por duplicidad (race condition)
    if (error.code === 11000) {
      return res
        .status(403)
        .json({ msg: "ALERTA: Replay Attack (Nonce duplicado concurrente)." });
    }
    res.status(500).json({ msg: "Error interno del servidor." });
  }
});

// Ruta auxiliar
router.get("/sniff", (req, res) => res.json({ msg: "OK" }));

module.exports = router;
