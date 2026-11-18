// Minimal GitHub OAuth shim for app.meemoo.org gist saving.
// Flow: app -> /login?redirect=<app url> -> GitHub -> /oauth/callback -> app?token=...
//
// Env vars (Netlify site settings): GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
// Optional: ALLOWED_ORIGINS (comma-separated), defaults below.

const DEFAULT_ORIGINS = ['https://app.meemoo.org'];
const COOKIE = 'gist_oauth';

export const config = {
  path: ['/login', '/oauth/callback'],
};

function env(name) {
  return globalThis.Netlify?.env.get(name) ?? process.env[name];
}

function allowedOrigins() {
  const raw = env('ALLOWED_ORIGINS');
  return raw ? raw.split(',').map((s) => s.trim()).filter(Boolean) : DEFAULT_ORIGINS;
}

// Only send tokens back to known origins (or localhost for dev).
function safeRedirect(value) {
  const fallback = allowedOrigins()[0];
  if (!value) return fallback;
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const isLocal =
    url.protocol === 'http:' &&
    (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
  return isLocal || allowedOrigins().includes(url.origin) ? url.toString() : null;
}

function text(body, status) {
  return new Response(body, {
    status,
    headers: {'Content-Type': 'text/plain; charset=utf-8'},
  });
}

function redirect(location, extraHeaders = {}) {
  return new Response(null, {
    status: 302,
    headers: {Location: location, 'Cache-Control': 'no-store', ...extraHeaders},
  });
}

function readCookie(request, name) {
  const header = request.headers.get('cookie') || '';
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}

const cookieAttrs = 'Path=/oauth/callback; HttpOnly; Secure; SameSite=Lax';

export default async (request) => {
  const clientId = env('GITHUB_CLIENT_ID');
  const clientSecret = env('GITHUB_CLIENT_SECRET');
  if (!clientId || !clientSecret) return text('Server not configured', 500);

  const url = new URL(request.url);

  if (url.pathname === '/login') {
    const target = safeRedirect(url.searchParams.get('redirect'));
    if (!target) return text('Redirect not allowed', 400);

    const state = crypto.randomUUID();
    const gh = new URL('https://github.com/login/oauth/authorize');
    gh.searchParams.set('client_id', clientId);
    gh.searchParams.set('redirect_uri', `${url.origin}/oauth/callback`);
    gh.searchParams.set('scope', 'gist');
    gh.searchParams.set('state', state);

    const cookieValue = encodeURIComponent(JSON.stringify({state, target}));
    return redirect(gh.toString(), {
      'Set-Cookie': `${COOKIE}=${cookieValue}; Max-Age=600; ${cookieAttrs}`,
    });
  }

  if (url.pathname === '/oauth/callback') {
    let saved;
    try {
      saved = JSON.parse(readCookie(request, COOKIE) || 'null');
    } catch {
      saved = null;
    }
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!saved || !state || saved.state !== state) {
      return text('Login expired or invalid state, please try again', 400);
    }
    const target = safeRedirect(saved.target);
    if (!target) return text('Redirect not allowed', 400);
    if (!code) return text(url.searchParams.get('error_description') || 'No code provided', 400);

    let tokenData;
    try {
      const res = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {Accept: 'application/json', 'Content-Type': 'application/json'},
        body: JSON.stringify({client_id: clientId, client_secret: clientSecret, code}),
      });
      tokenData = await res.json();
    } catch (error) {
      return text(`Authentication failed: ${error.message}`, 502);
    }
    if (!tokenData.access_token) {
      return text(`Authentication failed: ${tokenData.error_description || tokenData.error || 'no token'}`, 400);
    }

    // App reads ?token= then strips it (see meemooapp src/plugins/github-api.js).
    const back = new URL(target);
    back.search = `?token=${encodeURIComponent(tokenData.access_token)}`;
    return redirect(back.toString(), {
      'Set-Cookie': `${COOKIE}=; Max-Age=0; ${cookieAttrs}`,
      'Referrer-Policy': 'no-referrer',
    });
  }

  return text('Not Found', 404);
};
