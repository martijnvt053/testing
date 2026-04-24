/**
 * Seminar Push Notification Worker
 *
 * SETUP (eenmalig, gratis):
 * 1. Ga naar https://dash.cloudflare.com → Workers & Pages → Create Worker
 * 2. Plak deze code, klik Deploy
 * 3. Ga naar de worker → Settings → Variables:
 *    - ADMIN_KEY   = zelf te kiezen wachtwoord (bijv. "seminar2024")
 *    - VAPID_PUB   = BNP__rx43zkGmdtX7HCc6f3U0Cx8e0vwxRNqrawuGPpJZporDj2hUtUBQ4Y4sHa14vAAD-NJslma2D3I8brmy_Q
 *    - VAPID_PRIV  = IJ3XVUujDqBXaGtGFKhnSMsQ-SKI3Nmz4ScMG9655V8
 * 4. Ga naar Workers → KV → Create namespace:
 *    - naam: SUBS  → bind aan worker als "SUBS"
 *    - naam: MSG   → bind aan worker als "MSG"
 * 5. Noteer je worker URL: https://<naam>.workers.dev
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    if (pathname === '/subscribe' && request.method === 'POST') {
      return handleSubscribe(request, env);
    }
    if (pathname === '/message' && request.method === 'GET') {
      return handleGetMessage(env);
    }
    if (pathname === '/notify' && request.method === 'POST') {
      return handleNotify(request, env);
    }

    return new Response('Not Found', { status: 404, headers: CORS });
  },
};

async function handleSubscribe(request, env) {
  const sub = await request.json();
  const key = b64url(new TextEncoder().encode(sub.endpoint)).slice(-24);
  await env.SUBS.put(key, JSON.stringify(sub), { expirationTtl: 60 * 60 * 24 * 30 });
  return new Response('OK', { headers: CORS });
}

async function handleGetMessage(env) {
  const msg = (await env.MSG.get('latest')) || '';
  return new Response(JSON.stringify({ message: msg }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

async function handleNotify(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (auth !== `Bearer ${env.ADMIN_KEY}`) {
    return new Response('Unauthorized', { status: 401, headers: CORS });
  }

  const { message } = await request.json();
  await env.MSG.put('latest', message);

  const { keys } = await env.SUBS.list();
  let sent = 0, failed = 0;

  await Promise.allSettled(
    keys.map(async ({ name }) => {
      const raw = await env.SUBS.get(name);
      if (!raw) return;
      try {
        await sendPush(JSON.parse(raw), env);
        sent++;
      } catch (_) {
        failed++;
      }
    })
  );

  return new Response(JSON.stringify({ sent, failed }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

async function sendPush(subscription, env) {
  const { endpoint } = subscription;
  const { origin } = new URL(endpoint);
  const jwt = await createVapidJwt(origin, env);

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `vapid t=${jwt},k=${env.VAPID_PUB}`,
      TTL: '86400',
      'Content-Length': '0',
    },
  });

  if (!res.ok && res.status !== 201) {
    throw new Error(`Push HTTP ${res.status}`);
  }
}

async function createVapidJwt(audience, env) {
  const pubBytes = b64urlDecode(env.VAPID_PUB);
  const x = b64url(pubBytes.slice(1, 33));
  const y = b64url(pubBytes.slice(33, 65));

  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', d: env.VAPID_PRIV, x, y, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const now = Math.floor(Date.now() / 1000);
  const header = b64url(enc(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64url(enc(JSON.stringify({ aud: audience, exp: now + 43200, sub: 'mailto:admin@seminar.app' })));
  const input = `${header}.${payload}`;

  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    enc(input)
  );

  return `${input}.${b64url(new Uint8Array(sig))}`;
}

const enc = s => new TextEncoder().encode(s);
const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const b64urlDecode = s => {
  const p = s + '='.repeat((4 - s.length % 4) % 4);
  return new Uint8Array([...atob(p.replace(/-/g, '+').replace(/_/g, '/'))].map(c => c.charCodeAt(0)));
};
