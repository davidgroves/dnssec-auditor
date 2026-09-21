import { resolve } from 'node:path';
import { defineConfig, type Connect, type Plugin } from 'vite';

/** Serve index.html for app routes so FQDN paths are not treated as static files. */
function spaAppRoutes(): Plugin {
  const rewrite: Connect.NextHandleFunction = (req, _res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      next();
      return;
    }
    const accept = req.headers.accept ?? '';
    if (accept && !accept.includes('text/html') && !accept.includes('*/*')) {
      next();
      return;
    }
    const path = (req.url ?? '').split('?')[0];
    if (path === '/zones' || path === '/catalogs' || path.startsWith('/zones/')) {
      req.url = '/index.html';
    }
    next();
  };
  return {
    name: 'spa-app-routes',
    configureServer(server) {
      server.middlewares.use(rewrite);
    },
    configurePreviewServer(server) {
      server.middlewares.use(rewrite);
    },
  };
}

export default defineConfig(({ command }) => {
  const isServe = command === 'serve';
  return {
    root: 'frontend',
    appType: 'spa',
    plugins: [spaAppRoutes()],
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
      allowedHosts: true,
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
    preview: {
      allowedHosts: true,
    },
  };
});
