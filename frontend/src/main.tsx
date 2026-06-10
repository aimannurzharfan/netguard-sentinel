import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

// Self-hosted fonts so the bundle works offline and under the app's strict CSP.
import "@fontsource/chakra-petch/500.css"
import "@fontsource/chakra-petch/600.css"
import "@fontsource/chakra-petch/700.css"
import "@fontsource/ibm-plex-mono/400.css"
import "@fontsource/ibm-plex-mono/500.css"
import "@fontsource/ibm-plex-mono/600.css"

import "./index.css"
import App from "./App.tsx"

document.documentElement.classList.add("dark")

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
)
