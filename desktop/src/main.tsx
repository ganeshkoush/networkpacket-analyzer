import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { Startup } from "./components/layout/Startup";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <Startup><App /></Startup>
  </React.StrictMode>,
);
