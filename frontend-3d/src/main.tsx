import React from 'react'
import { createRoot, Root } from 'react-dom/client'
import { NetworkTube } from './NetworkTube'

const ROOT_ID = '3d-tube-root'

let root: Root | null = null

function show3DTube() {
  const el = document.getElementById(ROOT_ID)
  if (!el) return

  // Show the overlay first so Canvas gets real dimensions
  el.style.display = 'block'

  // Mount React only once
  if (!root) {
    root = createRoot(el)
    root.render(<NetworkTube />)
  }
}

// Expose globally so the React sidebar can call it
;(window as any).__show3DTube = show3DTube
