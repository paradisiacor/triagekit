import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwind from '@tailwindcss/vite';

// Release build goes straight into the .NET project (embedded into TriageKit.exe).
// `vite build --mode preview` builds a design preview with the sample backend into ./preview.
export default defineConfig(({ mode }) => ({
  base: './',
  plugins: [react(), tailwind()],
  define: { __PREVIEW__: JSON.stringify(mode === 'preview' || mode === 'development') },
  build: {
    outDir: mode === 'preview' ? 'preview' : '../src/TriageKit.Cli/Ui/web',
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1500,
    target: 'chrome110',
  },
}));
