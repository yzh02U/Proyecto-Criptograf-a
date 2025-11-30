import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import CryptoJS from "crypto-js";
import io from "socket.io-client";
import "./Sidebar.css";

// Conexión WebSocket
const socket = io("http://localhost:3001");

const Atacante = () => {
  const navigate = useNavigate();

  // --- ESTADOS DE CONEXIÓN ---
  const [conectado, setConectado] = useState(false);
  const [logActividad, setLogActividad] = useState("Esperando tráfico...");

  // --- ESTADO: SUPRESIÓN ---
  const [supresionActiva, setSupresionActiva] = useState(false);

  // --- DATOS VISUALES (MONITOR) ---
  const [datosInterceptados, setDatosInterceptados] = useState(null);
  const [hmacInterceptado, setHmacInterceptado] = useState("");
  const [idEmisor, setIdEmisor] = useState("");
  const [jsonRaw, setJsonRaw] = useState("");

  // --- INPUTS MANUALES (ATAQUE) ---
  const [destinatario, setDestinatario] = useState("");
  const [monto, setMonto] = useState("");
  const [timestampSpoof, setTimestampSpoof] = useState("");
  const [nonceSpoof, setNonceSpoof] = useState(""); // Campo Nonce

  const [claveAtacante, setClaveAtacante] = useState("clave_del_hacker");
  const [algoritmo, setAlgoritmo] = useState("SHA2-256");

  const [hmacFinal, setHmacFinal] = useState("");

  // --- INICIALIZACIÓN ---
  useEffect(() => {
    fetch("http://localhost:3001/api/users/estado-ataque")
      .then((res) => res.json())
      .then((data) => setSupresionActiva(data.supresion))
      .catch((err) => console.error(err));

    socket.on("connect", () => {
      setConectado(true);
      setLogActividad("Conectado al nodo de intercepción (MITM)");
    });

    socket.on("paquete_interceptado", (data) => {
      console.log(" Paquete recibido:", data);
      setLogActividad(
        ` ¡PAQUETE CAPTURADO! [${new Date().toLocaleTimeString()}]`
      );

      // Actualizar Monitor Superior
      setHmacInterceptado(data.hmacRecibido);
      setIdEmisor(data.idEmisor);
      setAlgoritmo(data.algoritmo);
      setJsonRaw(data.datosJson);

      try {
        const contenido = JSON.parse(data.datosJson);
        setDatosInterceptados(contenido);
      } catch (e) {
        console.error(e);
      }

      if (navigator.vibrate) navigator.vibrate(200);
    });

    socket.on("disconnect", () => setConectado(false));

    return () => {
      socket.off("connect");
      socket.off("paquete_interceptado");
      socket.off("disconnect");
    };
  }, []);

  // --- TOGGLE SUPRESIÓN ---
  const toggleSupresion = async () => {
    const nuevoEstado = !supresionActiva;
    setSupresionActiva(nuevoEstado);
    try {
      await fetch("http://localhost:3001/api/users/configurar-ataque", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ supresionActiva: nuevoEstado }),
      });
      setLogActividad(
        nuevoEstado ? "BLOQUEO DE PAQUETES ACTIVADO" : "RED NORMAL RESTAURADA"
      );
    } catch (error) {
      console.error(error);
    }
  };

  // --- CÁLCULO HMAC FALSO ---
  const calcularHMACFalso = () => {
    if (!destinatario || !monto || !timestampSpoof) {
      alert("Faltan datos en los cuadros de texto manuales.");
      return;
    }

    const time = Number(timestampSpoof);
    const op = "AUTH";

    // Construcción del objeto JSON base
    const payloadObj = {
      para: destinatario,
      cantidad: monto,
      time: time,
      op: op,
    };

    // Lógica Condicional: Solo agregamos 'nonce' si el campo tiene texto
    if (nonceSpoof && nonceSpoof.trim() !== "") {
      payloadObj.nonce = nonceSpoof;
    }

    const datosString = JSON.stringify(payloadObj);
    console.log("Calculando hash para:", datosString);

    let resultado;
    switch (algoritmo) {
      case "SHA2-256":
        resultado = CryptoJS.HmacSHA256(datosString, claveAtacante);
        break;
      case "SHA2-512":
        resultado = CryptoJS.HmacSHA512(datosString, claveAtacante);
        break;
      case "SHA3-256":
        resultado = CryptoJS.HmacSHA3(datosString, claveAtacante, {
          outputLength: 256,
        });
        break;
      case "SHA3-512":
        resultado = CryptoJS.HmacSHA3(datosString, claveAtacante, {
          outputLength: 512,
        });
        break;
      case "SHA-1":
        resultado = CryptoJS.HmacSHA1(datosString, claveAtacante);
        break;
      case "MD5":
        resultado = CryptoJS.HmacMD5(datosString, claveAtacante);
        break;
      case "WHIRLPOOL":
        resultado =
          "SIMULACION_WHIRLPOOL_" +
          CryptoJS.HmacSHA512(datosString, claveAtacante);
        break;
      default:
        resultado = CryptoJS.HmacSHA256(datosString, claveAtacante);
    }
    setHmacFinal(resultado.toString());
  };

  // --- EJECUTAR SPOOFING ---
  const lanzarAtaque = async () => {
    if (!hmacFinal) {
      alert("Falta el HMAC. Calcúlalo o escríbelo.");
      return;
    }
    if (!destinatario || !monto || !timestampSpoof) {
      alert("Faltan datos del payload.");
      return;
    }

    // Reconstrucción exacta del paquete según inputs
    const payloadObj = {
      para: destinatario,
      cantidad: monto,
      time: Number(timestampSpoof),
      op: "AUTH",
    };

    // Lógica Condicional: Agregar nonce solo si existe
    if (nonceSpoof && nonceSpoof.trim() !== "") {
      payloadObj.nonce = nonceSpoof;
      console.log("Enviando ataque CON Nonce:", nonceSpoof);
    } else {
      console.log("Enviando ataque SIN Nonce");
    }

    const payloadReal = JSON.stringify(payloadObj);

    try {
      const respuesta = await fetch(
        "http://localhost:3001/api/users/transferir",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            idEmisor: idEmisor, // Suplantación de identidad
            datosJson: payloadReal,
            hmacRecibido: hmacFinal,
            algoritmo: algoritmo,
            esAtacante: true, // Bypass de supresión
          }),
        }
      );

      const data = await respuesta.json();

      if (respuesta.ok) alert(`ATAQUE EXITOSO: ${data.msg}`);
      else alert(`ATAQUE FALLIDO: ${data.msg}`);
    } catch (error) {
      console.error(error);
      alert("Error de conexión");
    }
  };

  // Generar un nonce aleatorio nuevo
  const generarNuevoNonce = () => {
    setNonceSpoof(CryptoJS.lib.WordArray.random(16).toString());
  };

  return (
    <div
      className="dashboard-container"
      style={{ justifyContent: "center", backgroundColor: "#050505" }}
    >
      <div
        className="main-panel"
        style={{
          maxWidth: "900px",
          border: "2px solid #dc3545",
          borderRadius: "15px",
          margin: "20px",
          padding: "20px",
          boxShadow: "0 0 50px rgba(220, 53, 69, 0.15)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "20px",
          }}
        >
          <h1
            style={{
              color: "#dc3545",
              margin: 0,
              fontSize: "1.5rem",
              textTransform: "uppercase",
            }}
          >
            Consola MITM
          </h1>

          {/* CONTROL DE SUPRESIÓN */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              backgroundColor: "#1a1a1a",
              padding: "10px",
              borderRadius: "8px",
              border: supresionActiva ? "1px solid #dc3545" : "1px solid #333",
            }}
          >
            <span
              style={{ color: "#fff", fontSize: "0.9rem", fontWeight: "bold" }}
            >
              Supresión:
            </span>
            <label
              className="switch"
              style={{
                position: "relative",
                display: "inline-block",
                width: "50px",
                height: "24px",
              }}
            >
              <input
                type="checkbox"
                checked={supresionActiva}
                onChange={toggleSupresion}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span
                style={{
                  position: "absolute",
                  cursor: "pointer",
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  backgroundColor: supresionActiva ? "#dc3545" : "#ccc",
                  transition: ".4s",
                  borderRadius: "34px",
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    content: "",
                    height: "16px",
                    width: "16px",
                    left: "4px",
                    bottom: "4px",
                    backgroundColor: "white",
                    transition: ".4s",
                    borderRadius: "50%",
                    transform: supresionActiva
                      ? "translateX(26px)"
                      : "translateX(0)",
                  }}
                ></span>
              </span>
            </label>
          </div>
        </div>

        {/* LOG */}
        <div
          style={{
            backgroundColor: "#111",
            color: supresionActiva ? "#dc3545" : "#00d2ff",
            padding: "15px",
            borderRadius: "5px",
            margin: "20px 0",
            fontFamily: "monospace",
            border: "1px solid #333",
            textAlign: "center",
          }}
        >
          {supresionActiva
            ? "MODO SUPRESIÓN ACTIVO: TRÁFICO BLOQUEADO PARA LA VÍCTIMA"
            : logActividad}
        </div>

        {/* --- MONITOR DE TRÁFICO --- */}
        <div
          style={{
            backgroundColor: "#0f0f0f",
            border: "1px solid #444",
            borderRadius: "8px",
            padding: "15px",
            marginBottom: "25px",
          }}
        >
          <h3
            style={{
              color: "#00d2ff",
              marginTop: 0,
              fontSize: "1rem",
              borderBottom: "1px solid #333",
              paddingBottom: "5px",
            }}
          >
            Monitor de Tráfico (Sniffer)
          </h3>

          {!datosInterceptados ? (
            <div
              style={{ color: "#666", textAlign: "center", padding: "20px" }}
            >
              Esperando paquetes...
            </div>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "15px",
                fontSize: "0.9rem",
              }}
            >
              <div>
                <span style={{ color: "#888", display: "block" }}>
                  Víctima:
                </span>
                <span style={{ color: "#fff", fontFamily: "monospace" }}>
                  {idEmisor}
                </span>
              </div>
              <div>
                <span style={{ color: "#888", display: "block" }}>
                  Timestamp:
                </span>
                <span style={{ color: "#ffc107", fontFamily: "monospace" }}>
                  {datosInterceptados.time}
                </span>
              </div>
              <div>
                <span style={{ color: "#888", display: "block" }}>Para:</span>
                <span style={{ color: "#fff" }}>{datosInterceptados.para}</span>
              </div>
              <div>
                <span style={{ color: "#888", display: "block" }}>Monto:</span>
                <span style={{ color: "#00d2ff", fontWeight: "bold" }}>
                  ${datosInterceptados.cantidad}
                </span>
              </div>

              <div
                style={{
                  gridColumn: "1 / -1",
                  borderTop: "1px solid #333",
                  paddingTop: "5px",
                  marginTop: "5px",
                }}
              >
                <span style={{ color: "#888", marginRight: "10px" }}>
                  Nonce Detectado:
                </span>
                {datosInterceptados.nonce ? (
                  <span style={{ color: "#28a745", fontFamily: "monospace" }}>
                    {datosInterceptados.nonce}
                  </span>
                ) : (
                  <span style={{ color: "#666", fontStyle: "italic" }}>
                    No utilizado
                  </span>
                )}
              </div>

              <div style={{ gridColumn: "1 / -1" }}>
                <span style={{ color: "#888", display: "block" }}>HMAC:</span>
                <div
                  style={{
                    color: "#dc3545",
                    fontFamily: "monospace",
                    wordBreak: "break-all",
                    background: "#1a1a1a",
                    padding: "5px",
                    borderRadius: "4px",
                    marginTop: "3px",
                  }}
                >
                  {hmacInterceptado}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* --- CONSOLA DE INYECCIÓN (MANUAL) --- */}
        <div
          className="panel-card"
          style={{ borderColor: "#dc3545", backgroundColor: "#0a0a0a" }}
        >
          <h3
            style={{
              color: "#dc3545",
              borderBottom: "1px solid #dc3545",
              paddingBottom: "10px",
              marginTop: 0,
            }}
          >
            💉 Inyección Manual (Escribe para atacar)
          </h3>

          <div className="form-row">
            <div className="input-group">
              <label style={{ color: "#dc3545" }}>Destinatario:</label>
              <input
                type="text"
                value={destinatario}
                onChange={(e) => setDestinatario(e.target.value)}
                style={{ borderColor: "#dc3545", color: "#fff" }}
                placeholder="Destino..."
              />
            </div>
            <div className="input-group">
              <label style={{ color: "#dc3545" }}>Monto:</label>
              <input
                type="number"
                value={monto}
                onChange={(e) => setMonto(e.target.value)}
                style={{ borderColor: "#dc3545", color: "#fff" }}
                placeholder="0"
              />
            </div>
          </div>

          <div className="input-group">
            <label style={{ color: "#dc3545" }}>Timestamp (ms):</label>
            <div style={{ display: "flex", gap: "10px" }}>
              <input
                type="number"
                value={timestampSpoof}
                onChange={(e) => setTimestampSpoof(e.target.value)}
                style={{
                  borderColor: "#dc3545",
                  color: "#fff",
                  fontFamily: "monospace",
                }}
                placeholder="Ej: 1701234567890"
              />
              <button
                onClick={() => setTimestampSpoof(Date.now())}
                style={{
                  backgroundColor: "#333",
                  color: "#fff",
                  border: "1px solid #555",
                  cursor: "pointer",
                  borderRadius: "5px",
                  padding: "0 15px",
                }}
              >
                Actual
              </button>
            </div>
          </div>

          <div className="input-group">
            <label style={{ color: "#dc3545" }}>Nonce (Aleatoriedad):</label>
            <div style={{ display: "flex", gap: "10px" }}>
              <input
                type="text"
                value={nonceSpoof}
                onChange={(e) => setNonceSpoof(e.target.value)}
                style={{
                  borderColor: "#dc3545",
                  color: "#fff",
                  fontFamily: "monospace",
                }}
                placeholder="Vacío o hash único..."
              />
              <button
                onClick={generarNuevoNonce}
                style={{
                  backgroundColor: "#333",
                  color: "#fff",
                  border: "1px solid #555",
                  cursor: "pointer",
                  borderRadius: "5px",
                  padding: "0 15px",
                }}
                title="Generar nuevo nonce"
              ></button>
            </div>
          </div>

          <div className="input-group">
            <label style={{ color: "#dc3545" }}>Clave Falsa:</label>
            <input
              type="text"
              value={claveAtacante}
              onChange={(e) => setClaveAtacante(e.target.value)}
              style={{
                borderColor: "#dc3545",
                color: "#dc3545",
                fontWeight: "bold",
              }}
            />
          </div>

          <div className="input-group">
            <label style={{ color: "#dc3545" }}>Algoritmo:</label>
            <select
              value={algoritmo}
              onChange={(e) => setAlgoritmo(e.target.value)}
              className="select-hash"
              style={{
                borderColor: "#dc3545",
                color: "#fff",
                backgroundColor: "#1a1a1a",
              }}
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

          <div className="input-group">
            <button
              className="btn-action"
              onClick={calcularHMACFalso}
              style={{ backgroundColor: "#333" }}
            >
              1. Calcular
            </button>
          </div>

          <div className="input-group" style={{ marginTop: "15px" }}>
            <label style={{ color: "#ff8888" }}>HMAC Final:</label>
            <input
              type="text"
              value={hmacFinal}
              onChange={(e) => setHmacFinal(e.target.value)}
              style={{
                borderColor: "#ff8888",
                color: "#ff8888",
                backgroundColor: "#2a0a0a",
                fontFamily: "monospace",
                fontSize: "0.9rem",
              }}
              placeholder="Hash a enviar..."
            />
          </div>

          <div className="input-group" style={{ marginTop: "10px" }}>
            <button
              className="btn-action"
              onClick={lanzarAtaque}
              style={{
                backgroundColor: "#dc3545",
                color: "white",
                fontWeight: "900",
              }}
            >
              2. EJECUTAR ATAQUE (SPOOF)
            </button>
          </div>
        </div>

        <div style={{ textAlign: "center", marginTop: "30px" }}>
          <button
            onClick={() => navigate("/simulador")}
            style={{
              background: "none",
              border: "none",
              color: "#666",
              cursor: "pointer",
              textDecoration: "underline",
            }}
          >
            ← Volver al modo normal
          </button>
        </div>
      </div>
    </div>
  );
};

export default Atacante;
