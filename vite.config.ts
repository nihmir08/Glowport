import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

// Fixed address, because Tauri loads exactly this one in development mode.
export default defineConfig({
  plugins: [svelte()],
  define: { __APP_VERSION__: JSON.stringify(version) },
  clearScreen: false,
  server: { host: '127.0.0.1', port: 1420, strictPort: true },
  envPrefix: ['VITE_', 'TAURI_ENV_'],
  build: { target: 'chrome120', outDir: 'dist', emptyOutDir: true },
});
