import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

const racine = document.getElementById("root");
if (racine === null) {
  throw new Error("Element racine #root absent du document.");
}

ReactDOM.createRoot(racine).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
