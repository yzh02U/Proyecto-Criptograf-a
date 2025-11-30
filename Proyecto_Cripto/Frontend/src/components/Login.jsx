// client/src/components/Login.jsx
import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import "./Registro.css";

const Login = () => {
  const [idUsuario, setIdUsuario] = useState("");
  const [password, setPassword] = useState("");
  const [mensaje, setMensaje] = useState("");

  const navigate = useNavigate();

  const manejarLogin = async (e) => {
    e.preventDefault();

    try {
      const respuesta = await fetch("http://localhost:3001/api/users/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: idUsuario, password: password }),
      });

      const data = await respuesta.json();

      if (respuesta.ok) {
        console.log("Login OK, redirigiendo...");
        localStorage.setItem("usuarioActivo", JSON.stringify(data.usuario));
        navigate("/simulador");
      } else {
        setMensaje("Error: " + data.msg);
      }
    } catch (error) {
      setMensaje("Error de conexión con el servidor");
    }
  };

  return (
    <div className="registro-container">
      <div className="card">
        <h2>Iniciar Sesión</h2>
        <form onSubmit={manejarLogin}>
          <div className="form-group">
            <label>ID de Usuario:</label>
            <input
              type="text"
              value={idUsuario}
              onChange={(e) => setIdUsuario(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label>Contraseña:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button type="submit" className="btn-crear">
            Ingresar
          </button>
        </form>

        {mensaje && <p className="mensaje-feedback">{mensaje}</p>}

        <p style={{ marginTop: "20px", color: "#ccc" }}>
          ¿No tienes cuenta? <br />
          <Link to="/registro" style={{ color: "#00d2ff" }}>
            Regístrate aquí
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Login;
