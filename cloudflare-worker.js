/**
 * Seminar Worker — push notificaties + document scans
 *
 * SETUP (eenmalig, gratis):
 * 1. Ga naar https://dash.cloudflare.com → Workers & Pages → Create Worker
 * 2. Plak deze code, klik Deploy
 * 3. Ga naar de worker → Settings → Variables:
 *    - ADMIN_KEY      = zelf te kiezen wachtwoord (bijv. "seminar2024")
 *    - VAPID_PUB      = BDuanFLTbpWrUdysn2CYIfiy0pqk2NU1BCOmwLJ0xVjHCmMTi45JQDxeAguFIdcwcEqqELyuozmg1w1WdVSx8j0
 *    - VAPID_PRIV     = pavZg9M7A617XKposwc2b8U7TAwEqzT0TDnV9gg8gvk
 *    - AZURE_ENDPOINT = https://jouw-resource.cognitiveservices.azure.com  (optioneel)
 *    - AZURE_KEY      = jouw Azure Computer Vision sleutel                 (optioneel)
 * 4. Ga naar Workers → KV → Create namespace:
 *    - naam: SUBS → bind aan worker als "SUBS"
 *    - naam: MSG  → bind aan worker als "MSG"
 * 5. Noteer je worker URL: https://<naam>.workers.dev
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

    if (pathname === '/subscribe' && request.method === 'POST') {
      return handleSubscribe(request, env);
    }
    if (pathname === '/message' && request.method === 'GET') {
      return handleGetMessage(env);
    }
    if (pathname === '/notify' && request.method === 'POST') {
      return handleNotify(request, env);
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
    if (pathname === '/azure-ocr' && request.method === 'POST') {
      return handleAzureOcr(request, env);
    }
    if (pathname === '/azure-read' && request.method === 'POST') {
      return handleAzureRead(request, env);
    }

    return new Response('Not Found', { status: 404, headers: CORS });
  },
};

// ─── Push subscriptions ───────────────────────────────────────────────────────

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
  try {
    const auth = request.headers.get('Authorization') || '';
    if (auth !== `Bearer ${env.ADMIN_KEY}`) {
      return new Response('Unauthorized', { status: 401, headers: CORS });
    }

    const { message } = await request.json();
    await env.MSG.put('latest', message);

    const { keys } = await env.SUBS.list();
    const subKeys = keys.filter(k => !k.name.startsWith('scan-'));
    let sent = 0;
    const errors = [];

    await Promise.allSettled(
      subKeys.map(async ({ name }) => {
        const raw = await env.SUBS.get(name);
        if (!raw) return;
        let sub;
        try {
          sub = JSON.parse(raw);
          await sendPush(sub, message, env);
          sent++;
        } catch (e) {
          errors.push(`[${sub?.endpoint?.slice(-20) ?? name}] ${e.message}`);
        }
      })
    );

    return new Response(JSON.stringify({ sent, failed: errors.length, errors }), {
      headers: { ...CORS, 'Content-Type': 'application/json' },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { ...CORS, 'Content-Type': 'application/json' },
    });
  }
}

// ─── Web Push (RFC 8291 + RFC 8188 encrypted payload) ────────────────────────

async function sendPush(subscription, message, env) {
  const { endpoint, keys } = subscription;
  const { origin } = new URL(endpoint);
  const jwt = await createVapidJwt(origin, env);

  const headers = {
    Authorization: `vapid t=${jwt},k=${env.VAPID_PUB}`,
    TTL: '86400',
  };

  let body = null;
  if (keys?.p256dh && keys?.auth) {
    body = await encryptPayload(keys.p256dh, keys.auth, message);
    headers['Content-Type'] = 'application/octet-stream';
    headers['Content-Encoding'] = 'aes128gcm';
  } else {
    headers['Content-Length'] = '0';
  }

  const res = await fetch(endpoint, { method: 'POST', headers, body });
  if (!res.ok && res.status !== 201) {
    const txt = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${txt}`);
  }
}

async function encryptPayload(p256dhB64, authB64, message) {
  const uaPubBytes = b64urlDecode(p256dhB64);
  const authBytes  = b64urlDecode(authB64);
  const plaintext  = new TextEncoder().encode(message);

  const uaPub = await crypto.subtle.importKey('raw', uaPubBytes, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const asKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ecdhBits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaPub }, asKeys.privateKey, 256));
  const asPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', asKeys.publicKey));
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const prkKey = new Uint8Array(await hmac(authBytes, ecdhBits));
  const authInfo = concat(enc('WebPush: info\x00'), uaPubBytes, asPubRaw);
  const ikm = (await hmac(prkKey, concat(authInfo, new Uint8Array([1])))).slice(0, 32);
  const prk = new Uint8Array(await hmac(salt, new Uint8Array(ikm)));
  const cek   = (await hmac(prk, concat(enc('Content-Encoding: aes128gcm\x00'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc('Content-Encoding: nonce\x00'),      new Uint8Array([1])))).slice(0, 12);

  const padded = concat(plaintext, new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded));

  const rs = new ArrayBuffer(4);
  new DataView(rs).setUint32(0, padded.length + 16, false);
  return concat(salt, new Uint8Array(rs), new Uint8Array([65]), asPubRaw, ciphertext);
}

async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', k, data);
}

// ─── VAPID JWT ────────────────────────────────────────────────────────────────

async function createVapidJwt(audience, env) {
  const privBytes = b64urlDecode(env.VAPID_PRIV);

  const pkcs8Prefix = new Uint8Array([
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
  ]);

  const key = await crypto.subtle.importKey(
    'pkcs8',
    concat(pkcs8Prefix, privBytes),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const now = Math.floor(Date.now() / 1000);
  const header  = b64url(enc(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64url(enc(JSON.stringify({ aud: audience, exp: now + 43200, sub: 'mailto:admin@seminar.app' })));
  const input   = `${header}.${payload}`;

  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc(input));
  return `${input}.${b64url(new Uint8Array(sig))}`;
}

// ─── Scan endpoints ───────────────────────────────────────────────────────────

async function handleScanPost(request, env) {
  const scan = await request.json();
  const key = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  await env.SUBS.put(key, JSON.stringify({ ...scan, _key: key }), { expirationTtl: 60 * 60 * 24 * 90 });
  return new Response(JSON.stringify({ id: key }), {
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

async function handleScansGet(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (auth !== `Bearer ${env.ADMIN_KEY}`) {
    return new Response('Unauthorized', { status: 401, headers: CORS });
  }
  const { keys } = await env.SUBS.list({ prefix: 'scan-' });
  const scans = (await Promise.all(
    keys.map(async ({ name }) => {
      const v = await env.SUBS.get(name);
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
  await env.SUBS.delete(`scan-${key}`);
  return new Response('OK', { headers: CORS });
}

// ─── Azure OCR proxy ─────────────────────────────────────────────────────────

async function handleAzureOcr(request, env) {
  if (!env.AZURE_ENDPOINT || !env.AZURE_KEY) {
    return new Response(JSON.stringify({ error: 'Azure niet geconfigureerd. Voeg AZURE_ENDPOINT en AZURE_KEY toe als variabelen in de Cloudflare Worker.' }), {
      status: 503, headers: { ...CORS, 'Content-Type': 'application/json' },
    });
  }

  const imageBytes = await request.arrayBuffer();
  const endpoint = env.AZURE_ENDPOINT.replace(/\/$/, '');

  const azureResp = await fetch(`${endpoint}/vision/v3.2/ocr?language=nl&detectOrientation=true`, {
    method: 'POST',
    headers: {
      'Ocp-Apim-Subscription-Key': env.AZURE_KEY,
      'Content-Type': 'application/octet-stream',
    },
    body: imageBytes,
  });

  const data = await azureResp.json();
  return new Response(JSON.stringify(data), {
    status: azureResp.status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ─── Azure Read API (handschrift + gedrukt) ───────────────────────────────────

async function handleAzureRead(request, env) {
  if (!env.AZURE_ENDPOINT || !env.AZURE_KEY) {
    return new Response(JSON.stringify({ error: 'Azure niet geconfigureerd. Voeg AZURE_ENDPOINT en AZURE_KEY toe als variabelen in de Cloudflare Worker.' }), {
      status: 503, headers: { ...CORS, 'Content-Type': 'application/json' },
    });
  }

  const imageBytes = await request.arrayBuffer();
  const endpoint = env.AZURE_ENDPOINT.replace(/\/$/, '');

  const startResp = await fetch(`${endpoint}/vision/v3.2/read/analyze`, {
    method: 'POST',
    headers: {
      'Ocp-Apim-Subscription-Key': env.AZURE_KEY,
      'Content-Type': 'application/octet-stream',
    },
    body: imageBytes,
  });

  if (!startResp.ok) {
    const errData = await startResp.json().catch(() => ({}));
    return new Response(JSON.stringify(errData), {
      status: startResp.status,
      headers: { ...CORS, 'Content-Type': 'application/json' },
    });
  }

  const operationUrl = startResp.headers.get('Operation-Location');
  if (!operationUrl) {
    return new Response(JSON.stringify({ error: 'Geen Operation-Location header ontvangen van Azure' }), {
      status: 502, headers: { ...CORS, 'Content-Type': 'application/json' },
    });
  }

  // Poll for result — max 15 × 1.5s = 22.5s
  for (let i = 0; i < 15; i++) {
    await new Promise(r => setTimeout(r, 1500));
    const pollResp = await fetch(operationUrl, {
      headers: { 'Ocp-Apim-Subscription-Key': env.AZURE_KEY },
    });
    const data = await pollResp.json();
    if (data.status === 'succeeded' || data.status === 'failed') {
      return new Response(JSON.stringify(data), {
        headers: { ...CORS, 'Content-Type': 'application/json' },
      });
    }
  }

  return new Response(JSON.stringify({ error: 'Azure Read API time-out na 22 seconden' }), {
    status: 504, headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const enc = s => new TextEncoder().encode(s);

const b64url = bytes =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

const b64urlDecode = s => {
  const p = s + '='.repeat((4 - s.length % 4) % 4);
  return new Uint8Array([...atob(p.replace(/-/g, '+').replace(/_/g, '/'))].map(c => c.charCodeAt(0)));
};

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
