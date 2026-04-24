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
  try {
    const auth = request.headers.get('Authorization') || '';
    if (auth !== `Bearer ${env.ADMIN_KEY}`) {
      return new Response('Unauthorized', { status: 401, headers: CORS });
    }

    const { message } = await request.json();
    await env.MSG.put('latest', message);

    const { keys } = await env.SUBS.list();
    let sent = 0;
    const errors = [];

    await Promise.allSettled(
      keys.map(async ({ name }) => {
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
    const body = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${body}`);
  }
}

async function encryptPayload(p256dhB64, authB64, message) {
  const uaPubBytes = b64urlDecode(p256dhB64);
  const authBytes  = b64urlDecode(authB64);
  const plaintext  = new TextEncoder().encode(message);

  // Import user-agent public key
  const uaPub = await crypto.subtle.importKey(
    'raw', uaPubBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );

  // Generate ephemeral server key pair
  const asKeys = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveBits']
  );

  // ECDH shared secret
  const ecdhBits = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: uaPub }, asKeys.privateKey, 256)
  );

  // Export server public key (uncompressed, 65 bytes)
  const asPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', asKeys.publicKey));

  // Random 16-byte salt
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // RFC 8291 § 3.3 – IKM derivation
  // PRK_key = HKDF-Extract(salt=auth, IKM=ecdh_secret)
  const prkKey = new Uint8Array(await hmac(authBytes, ecdhBits));

  // IKM = HKDF-Expand(PRK_key, info="WebPush: info\0" + ua_pub + as_pub, L=32)
  const authInfo = concat(enc('WebPush: info\x00'), uaPubBytes, asPubRaw);
  const ikm = (await hmac(prkKey, concat(authInfo, new Uint8Array([1])))).slice(0, 32);

  // RFC 8188 – CEK + NONCE from IKM
  // PRK = HKDF-Extract(salt=salt, IKM=ikm)
  const prk = new Uint8Array(await hmac(salt, new Uint8Array(ikm)));

  const cek   = (await hmac(prk, concat(enc('Content-Encoding: aes128gcm\x00'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc('Content-Encoding: nonce\x00'),      new Uint8Array([1])))).slice(0, 12);

  // Encrypt: plaintext + 0x02 (last-record delimiter)
  const padded = concat(plaintext, new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded)
  );

  // RFC 8188 content-coding header: salt(16) + rs(4, BE) + idlen(1) + keyid(65) + ciphertext
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
  const header  = b64url(enc(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64url(enc(JSON.stringify({ aud: audience, exp: now + 43200, sub: 'mailto:admin@seminar.app' })));
  const input   = `${header}.${payload}`;

  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    enc(input)
  );

  return `${input}.${b64url(new Uint8Array(sig))}`;
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
