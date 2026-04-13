import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: resolve(__dirname, 'src/main.tsx'),
      output: {
        // IIFE format prevents leaking globals that conflict with app.js
        format: 'iife',
        entryFileNames: 'screentime.bundle.js',
        assetFileNames: 'screentime.[ext]',
      },
    },
    outDir: '../static/react',
    emptyOutDir: true,
  },
})
