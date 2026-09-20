import { resolve } from 'node:path';
import { defineConfig } from 'vite';

export default defineConfig(({ command }) => {
  const isServe = command === 'serve';
  return {
    root: 'frontend',
    build: isServe
      ? {}
      : {
          outDir: resolve(__dirname, 'dist'),
          emptyOutDir: true,
        },
    resolve: {
      alias: {
        '@': resolve(__dirname, 'frontend'),
      },
    },
    server: {
      port: 5173,
      host: true,
      proxy: {
        '/ui/config': 'http://localhost:8080',
        '/health': 'http://localhost:8080',
        '/ready': 'http://localhost:8080',
        '/metrics': 'http://localhost:8080',
        '/v1': 'http://localhost:8080',
        '/docs': 'http://localhost:8080',
        '/openapi': 'http://localhost:8080',
        '/openapi.json': 'http://localhost:8080',
        '/openapi.yaml': 'http://localhost:8080',
        '/schemas': 'http://localhost:8080',
      },
    },
  };
});
