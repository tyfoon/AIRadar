import React from 'react'
import { createRoot } from 'react-dom/client'
import { NetworkTube } from './NetworkTube'

const ROOT_ID = '3d-tube-root'

function mount() {
  const el = document.getElementById(ROOT_ID)
  if (!el) return
  const root = createRoot(el)
  root.render(<NetworkTube />)
}

// Mount immediately if DOM is ready, otherwise wait
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mount)
} else {
  mount()
}
