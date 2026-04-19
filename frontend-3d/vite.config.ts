import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: resolve(__dirname, 'src/main.tsx'),
      output: {
        format: 'iife',
        entryFileNames: '3d-tube.bundle.js',
        assetFileNames: '3d-tube.[ext]',
      },
    },
    outDir: '../static/react',
    emptyOutDir: false, // don't nuke screentime.bundle.js
  },
})
