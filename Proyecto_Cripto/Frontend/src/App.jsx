import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./components/Login";
import Registro from "./components/Registro";
import Sidebar from "./components/Sidebar";
import Atacante from "./components/Atacante"; // <--- IMPORTAR
import "./App.css";

function App() {
  return (
    <BrowserRouter>
      <div className="App">
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/registro" element={<Registro />} />
          <Route path="/simulador" element={<Sidebar />} />
          {/* NUEVA RUTA */}
          <Route path="/atacante" element={<Atacante />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;

// --- FUNCIÓN ACTUALIZADA ---
const toggleSpoofing = () => {
  // Redirigimos a la pantalla del atacante
  navigate("/atacante");
};
