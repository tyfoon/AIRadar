import React from 'react'
import { createRoot, Root } from 'react-dom/client'
import { NetworkTube, NetworkTubeCard } from './NetworkTube'

/* ------------------------------------------------------------------ */
/*  Fullscreen overlay (sidebar button)                                */
/* ------------------------------------------------------------------ */

const OVERLAY_ID = '3d-tube-root'
let overlayRoot: Root | null = null

function show3DTube() {
  const el = document.getElementById(OVERLAY_ID)
  if (!el) return
  el.style.display = 'block'
  if (!overlayRoot) {
    overlayRoot = createRoot(el)
    overlayRoot.render(<NetworkTube />)
  }
}

/* ------------------------------------------------------------------ */
/*  Inline dashboard card                                              */
/* ------------------------------------------------------------------ */

const CARD_ID = '3d-tube-card'
let cardRoot: Root | null = null

function mountCard() {
  const el = document.getElementById(CARD_ID)
  if (!el || cardRoot) return
  cardRoot = createRoot(el)
  cardRoot.render(<NetworkTubeCard />)
}

// Mount card when DOM is ready
function init() {
  mountCard()
  // Also watch for the element appearing later (SPA navigation)
  const observer = new MutationObserver(() => {
    if (!cardRoot && document.getElementById(CARD_ID)) {
      mountCard()
      observer.disconnect()
    }
  })
  observer.observe(document.body, { childList: true, subtree: true })
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init)
} else {
  init()
}

// Expose globally
;(window as any).__show3DTube = show3DTube
