import { useState } from "react";
import { useNavigate } from "react-router-dom";
import CryptoJS from "crypto-js";
import "./Sidebar.css";

const Sidebar = () => {
  const navigate = useNavigate();

  // Recuperamos el usuario del localStorage
  const usuarioGuardado =
    JSON.parse(localStorage.getItem("usuarioActivo")) || {};

  // --- ESTADOS DE LA BARRA LATERAL (DINERO) ---
  const [saldo, setSaldo] = useState(usuarioGuardado.money || 0);

  // --- ESTADOS DEL PANEL CENTRAL (HMAC) ---
  const [algoritmo, setAlgoritmo] = useState("SHA2-256");
  const [destinatario, setDestinatario] = useState("");
  const [montoTransferir, setMontoTransferir] = useState("");

  // Estado de la clave y su visibilidad
  const [clave, setClave] = useState(usuarioGuardado.Clave || "secreto123");
  const [mostrarClave, setMostrarClave] = useState(false);

  // Estado para activar/desactivar Nonce
  const [usarNonce, setUsarNonce] = useState(false);

  const [hmacResultado, setHmacResultado] = useState("");
  const [datosFirmados, setDatosFirmados] = useState("");

  // --- FUNCIONES DEL SIDEBAR (IZQUIERDA) ---
  const cerrarSesion = () => {
    localStorage.removeItem("usuarioActivo");
    navigate("/");
  };

  const aumentarFondos = async () => {
    try {
      const respuesta = await fetch(
        "http://localhost:3001/api/users/agregar-dinero",
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            id: usuarioGuardado.idPersonalizado,
            monto: 100,
          }),
        }
      );
      const data = await respuesta.json();

      if (respuesta.ok) {
        setSaldo(data.nuevoSaldo);
        usuarioGuardado.money = data.nuevoSaldo;
        localStorage.setItem("usuarioActivo", JSON.stringify(usuarioGuardado));
      } else {
        alert("Error: " + data.msg);
      }
    } catch (error) {
      console.error("Error de conexión:", error);
    }
  };

  // --- FUNCIÓN: Redirigir al Atacante ---
  const toggleSpoofing = () => {
    navigate("/atacante");
  };

  // --- FUNCIONES DEL PANEL CENTRAL (DERECHA) ---
  const calcularHMAC = () => {
    if (!destinatario || !montoTransferir) {
      alert("Por favor completa el destinatario y el monto.");
      return;
    }

    const time = Date.now();
    const op = "AUTH";

    // 1. GENERACIÓN DE NONCE (Si el botón está activo)
    let nonceGenerado = undefined;
    if (usarNonce) {
      // Generamos 16 bytes aleatorios hexadecimales (32 caracteres)
      nonceGenerado = CryptoJS.lib.WordArray.random(16).toString();
      console.log("Nonce generado para unicidad:", nonceGenerado);
    }

    // 2. CONSTRUCCIÓN DEL OBJETO
    const datosObj = {
      para: destinatario,
      cantidad: montoTransferir,
      time: time,
      op: op,
    };

    // Solo agregamos el campo 'nonce' al JSON si el usuario lo activó
    if (nonceGenerado) {
      datosObj.nonce = nonceGenerado;
    }

    // 3. Serialización
    const datosString = JSON.stringify(datosObj);
    setDatosFirmados(datosString);

    console.log("Firmando payload:", datosString);

    // 4. Cálculo del Hash
    let resultado;
    switch (algoritmo) {
      case "SHA2-256":
        resultado = CryptoJS.HmacSHA256(datosString, clave);
        break;
      case "SHA2-512":
        resultado = CryptoJS.HmacSHA512(datosString, clave);
        break;
      case "SHA3-256":
        resultado = CryptoJS.HmacSHA3(datosString, clave, {
          outputLength: 256,
        });
        break;
      case "SHA3-512":
        resultado = CryptoJS.HmacSHA3(datosString, clave, {
          outputLength: 512,
        });
        break;
      case "SHA-1":
        resultado = CryptoJS.HmacSHA1(datosString, clave);
        break;
      case "MD5":
        resultado = CryptoJS.HmacMD5(datosString, clave);
        break;
      case "WHIRLPOOL":
        resultado =
          "SIMULACION_WHIRLPOOL_" + CryptoJS.HmacSHA512(datosString, clave);
        break;
      default:
        resultado = CryptoJS.HmacSHA256(datosString, clave);
    }

    setHmacResultado(resultado.toString());
  };

  const enviarAlServidor = async () => {
    if (!hmacResultado || !datosFirmados) {
      alert("Primero debes calcular el HMAC.");
      return;
    }

    try {
      const respuesta = await fetch(
        "http://localhost:3001/api/users/transferir",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            idEmisor: usuarioGuardado.idPersonalizado,
            datosJson: datosFirmados,
            hmacRecibido: hmacResultado,
            algoritmo: algoritmo,
          }),
        }
      );

      const data = await respuesta.json();

      if (respuesta.ok) {
        alert(` ÉXITO: ${data.msg}`);
        setSaldo(data.nuevoSaldo);
        usuarioGuardado.money = data.nuevoSaldo;
        localStorage.setItem("usuarioActivo", JSON.stringify(usuarioGuardado));

        // Limpiamos para evitar reenvíos accidentales
        setHmacResultado("");
        setDatosFirmados("");
      } else {
        alert(` ERROR DEL SERVIDOR: ${data.msg}`);
      }
    } catch (error) {
      console.error("Error enviando:", error);
      alert("Error de conexión con el servidor");
    }
  };

  return (
    <div className="dashboard-container">
      {/* --- SECCIÓN IZQUIERDA: SIDEBAR --- */}
      <div className="sidebar">
        <div className="perfil-info">
          <h3>👤 Perfil</h3>
          <p className="dato-label">Agente:</p>
          <p className="dato-valor">
            {usuarioGuardado.idPersonalizado || "Desconocido"}
          </p>

          <p className="dato-label">Saldo disponible:</p>
          <p className="dato-valor dinero">${saldo}</p>

          <button className="btn-recargar" onClick={aumentarFondos}>
            Ingresar +$100
          </button>
        </div>

        {/* --- SECCIÓN: ZONA DE ATAQUE --- */}
        <div
          className="menu-ataques"
          style={{
            marginTop: "30px",
            borderTop: "1px solid #333",
            paddingTop: "20px",
          }}
        >
          <h4
            style={{
              color: "#dc3545",
              margin: "0 0 10px 0",
              fontSize: "0.9rem",
              textTransform: "uppercase",
            }}
          >
            Zona de Ataque
          </h4>
          <button
            className="btn-spoofing"
            onClick={toggleSpoofing}
            style={{
              width: "100%",
              padding: "12px",
              backgroundColor: "#1a1a1a",
              color: "#dc3545",
              border: "1px solid #dc3545",
              borderRadius: "5px",
              cursor: "pointer",
              fontWeight: "bold",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "10px",
              transition: "0.3s",
            }}
            onMouseOver={(e) =>
              (e.currentTarget.style.backgroundColor = "#2c0b0e")
            }
            onMouseOut={(e) =>
              (e.currentTarget.style.backgroundColor = "#1a1a1a")
            }
          >
            Escuchar (Spoofing)
          </button>
        </div>

        {/* BOTÓN CERRAR SESIÓN */}
        <div className="menu-opciones" style={{ marginTop: "40px" }}>
          <button className="btn-logout" onClick={cerrarSesion}>
            Cerrar Sesión
          </button>
        </div>
      </div>

      {/* --- SECCIÓN CENTRAL: PANEL DE TRABAJO --- */}
      <div className="main-panel">
        <h1>Generador HMAC Seguro</h1>
        <p className="descripcion">
          Configura los parámetros criptográficos para firmar tu mensaje.
        </p>

        <div className="panel-card">
          <div className="form-row">
            <div className="input-group">
              <label>Nombre Destinatario:</label>
              <input
                type="text"
                placeholder="Ej: Juan Perez"
                value={destinatario}
                onChange={(e) => setDestinatario(e.target.value)}
              />
            </div>

            <div className="input-group">
              <label>Monto a Transferir ($):</label>
              <input
                type="number"
                placeholder="Ej: 500"
                value={montoTransferir}
                onChange={(e) => setMontoTransferir(e.target.value)}
              />
            </div>
          </div>

          <div className="input-group">
            <label>Clave Secreta (Key):</label>
            <div
              style={{
                position: "relative",
                display: "flex",
                alignItems: "center",
              }}
            >
              <input
                type={mostrarClave ? "text" : "password"}
                value={clave}
                onChange={(e) => setClave(e.target.value)}
                style={{
                  color: "#00d2ff",
                  fontWeight: "bold",
                  paddingRight: "40px",
                }}
              />
              <button
                type="button"
                onClick={() => setMostrarClave(!mostrarClave)}
                style={{
                  position: "absolute",
                  right: "10px",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  fontSize: "1.2rem",
                  color: "#888",
                }}
              >
                {mostrarClave ? "👁️" : "🔒"}
              </button>
            </div>
            <small
              style={{ color: "#555", marginTop: "5px", display: "block" }}
            >
              Clave de sesión generada por el servidor
            </small>
          </div>

          <div className="input-group">
            <label>Algoritmo de Hashing:</label>
            <select
              value={algoritmo}
              onChange={(e) => setAlgoritmo(e.target.value)}
              className="select-hash"
            >
              <option value="SHA2-256">SHA-2 (256 bits)</option>
              <option value="SHA2-512">SHA-2 (512 bits)</option>
              <option value="SHA3-256">SHA-3 (256 bits)</option>
              <option value="SHA3-512">SHA-3 (512 bits)</option>
              <option value="SHA-1">SHA-1 (Obsoleto)</option>
              <option value="MD5">MD5 (Inseguro)</option>
              <option value="WHIRLPOOL">Whirlpool</option>
            </select>
          </div>

          {/* --- NUEVO BOTÓN NONCE --- */}
          <div className="input-group" style={{ marginTop: "10px" }}>
            <button
              type="button"
              onClick={() => setUsarNonce(!usarNonce)}
              style={{
                width: "100%",
                padding: "10px",
                backgroundColor: usarNonce ? "#28a745" : "#333",
                color: "white",
                border: "1px solid #555",
                borderRadius: "5px",
                cursor: "pointer",
                fontWeight: "bold",
                transition: "0.3s",
              }}
            >
              {usarNonce
                ? " Nonce (Aleatoriedad): ACTIVADO"
                : " Nonce (Aleatoriedad): DESACTIVADO"}
            </button>
            <small
              style={{ color: "#666", display: "block", marginTop: "5px" }}
            >
              * Activar para evitar ataques de repetición exactos mediante base
              de datos.
            </small>
          </div>

          <button className="btn-action btn-calcular" onClick={calcularHMAC}>
            Calcular HMAC
          </button>

          {hmacResultado && (
            <div className="resultado-container">
              <label>HMAC Generado ({algoritmo}):</label>
              <div className="hash-display">{hmacResultado}</div>
              <small
                style={{ color: "#666", marginTop: "5px", display: "block" }}
              >
                Firma generada para transacción autorizada
              </small>
            </div>
          )}

          <button
            className="btn-action btn-enviar"
            onClick={enviarAlServidor}
            disabled={!hmacResultado}
          >
            Enviar al Servidor
          </button>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
