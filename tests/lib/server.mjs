// Static server over the local Hugo build (public/). Directory URLs serve
// index.html; a missing file serves the nearest 404.html up the tree (what
// Cloudflare Pages does), so /it/missing/ shows the Italian 404 page.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.json': 'application/json', '.xml': 'application/xml', '.txt': 'text/plain', '.png': 'image/png',
  '.webp': 'image/webp', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.avif': 'image/avif',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.wasm': 'application/wasm',
  '.mp3': 'audio/mpeg', '.pdf': 'application/pdf', '.heic': 'image/heic',
};

function nearest404(root, urlPath) {
  let dir = path.dirname(path.join(root, urlPath.endsWith('/') ? urlPath + 'x' : urlPath));
  while (dir.startsWith(root)) {
    const f = path.join(dir, '404.html');
    if (fs.existsSync(f)) return f;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

export function serve(root = path.resolve('public'), port = 0) {
  root = path.resolve(root);
  if (!fs.existsSync(path.join(root, 'index.html'))) throw new Error(`no build in ${root}: run hugo --gc --minify first`);
  const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    let f = path.join(root, urlPath);
    if (!f.startsWith(root)) { res.writeHead(403); return res.end(); }
    try { if (fs.statSync(f).isDirectory()) f = path.join(f, 'index.html'); } catch {}
    fs.readFile(f, (err, data) => {
      if (err) {
        const nf = nearest404(root, urlPath);
        res.writeHead(404, { 'content-type': TYPES['.html'] });
        return res.end(nf ? fs.readFileSync(nf) : 'Not found');
      }
      res.writeHead(200, { 'content-type': TYPES[path.extname(f).toLowerCase()] || 'application/octet-stream' });
      res.end(data);
    });
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => {
    resolve({ origin: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) });
  }));
}

// Every request that isn't to the local server is aborted: tests must never
// reach production, ad networks or analytics.
export async function blockExternal(context, origin) {
  await context.route('**/*', (route) => {
    const u = route.request().url();
    return u.startsWith(origin) || u.startsWith('data:') || u.startsWith('blob:') ? route.continue() : route.abort();
  });
}

// Console noise caused by blockExternal itself, not by our code.
export const BLOCKED_NOISE = /Failed to load resource|net::ERR_FAILED|net::ERR_BLOCKED|adsbygoogle|googlesyndication|fundingchoices|umami/i;
