/**
 * Seminar Scan Worker
 *
 * SETUP (eenmalig, gratis):
 * 1. Ga naar https://dash.cloudflare.com → Workers & Pages → Create Worker
 * 2. Plak deze code, klik Deploy
 * 3. Ga naar de worker → Settings → Variables:
 *    - ADMIN_KEY = zelf te kiezen wachtwoord (bijv. "seminar2024")
 * 4. Ga naar Workers → KV → Create namespace:
 *    - naam: SCANS → bind aan worker als "SCANS"
 * 5. Noteer je worker URL: https://<naam>.workers.dev
 *    → Vul deze in bij ⚙️ Instellingen in de seminar app
 *    → En in het admin portaal onder ⚙️ Instellingen
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    if (pathname === '/scan' && request.method === 'POST') {
      return handleScanPost(request, env);
    }
    if (pathname === '/scans' && request.method === 'GET') {
      return handleScansGet(request, env);
    }
    if (pathname.startsWith('/scan/') && request.method === 'DELETE') {
      return handleScanDelete(pathname.slice(6), request, env);
    }

    return new Response('Not Found', { status: 404, headers: CORS });
  },
};

async function handleScanPost(request, env) {
  const scan = await request.json();
  const key = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  await env.SCANS.put(key, JSON.stringify({ ...scan, _key: key }), { expirationTtl: 60 * 60 * 24 * 90 });
  return new Response(JSON.stringify({ id: key }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

async function handleScansGet(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (auth !== `Bearer ${env.ADMIN_KEY}`) {
    return new Response('Unauthorized', { status: 401, headers: CORS });
  }
  const { keys } = await env.SCANS.list();
  const scans = (await Promise.all(
    keys.map(async ({ name }) => {
      const v = await env.SCANS.get(name);
      return v ? JSON.parse(v) : null;
    })
  )).filter(Boolean).sort((a, b) => b.time - a.time);
  return new Response(JSON.stringify(scans), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

async function handleScanDelete(key, request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (auth !== `Bearer ${env.ADMIN_KEY}`) {
    return new Response('Unauthorized', { status: 401, headers: CORS });
  }
  await env.SCANS.delete(`scan-${key}`);
  return new Response('OK', { headers: CORS });
}
