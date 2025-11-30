// client/src/components/Registro.jsx
import { useState } from "react";
import "./Registro.css"; // Importaremos los estilos en el paso 2

const Registro = () => {
  // Estados para guardar lo que escribe el usuario
  const [idUsuario, setIdUsuario] = useState("");
  const [password, setPassword] = useState("");
  const [mensaje, setMensaje] = useState("");

  // Función que se ejecuta al dar clic en el botón
  const manejarRegistro = async (e) => {
    e.preventDefault(); // Evita que la página se recargue

    console.log("🔵 CLICK DETECTADO: Intentando enviar datos..."); // <--- AGREGA ESTO
    console.log("Datos a enviar:", { id: idUsuario, password: password }); // <--- Y ESTO
    try {
      // Petición al Backend (Puerto 3001)
      const respuesta = await fetch("http://localhost:3001/api/users/crear", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          id: idUsuario,
          password: password,
          money: 0,
        }),
      });

      const data = await respuesta.json();

      if (respuesta.ok) {
        setMensaje("✅ ¡Usuario creado con éxito en MongoDB!");
        // Limpiamos los campos
        setIdUsuario("");
        setPassword("");
      } else {
        setMensaje("❌ Error: " + data.msg);
      }
    } catch (error) {
      console.error(error);
      setMensaje("❌ Error de conexión con el servidor");
    }
  };

  return (
    <div className="registro-container">
      <div className="card">
        <h2>Crear Cuenta</h2>
        <form onSubmit={manejarRegistro}>
          <div className="form-group">
            <label>ID de Usuario:</label>
            <input
              type="text"
              value={idUsuario}
              onChange={(e) => setIdUsuario(e.target.value)}
              placeholder="Ej: usuario01"
              required
            />
          </div>

          <div className="form-group">
            <label>Contraseña:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="******"
              required
            />
          </div>

          <button type="submit" className="btn-crear">
            Crear Usuario
          </button>
        </form>

        {/* Mensaje de feedback (éxito o error) */}
        {mensaje && <p className="mensaje-feedback">{mensaje}</p>}
      </div>
    </div>
  );
};

export default Registro;
