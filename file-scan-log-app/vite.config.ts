import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    cors: {
      origin: ['https://localhost:3000', 'https://yourdomain.com'],
      credentials: true,
    },
    strictPort: true,
  },
  build: {
    target: 'esnext',
    outDir: 'dist',
    sourcemap: false,
    cssCodeSplit: true,
    minify: 'esbuild',
  },
  define: {
    'process.env': process.env,
  },
});
