import crypto from 'crypto';
import { URL } from 'url';
import {
  buildGoogleAuthUrl,
  exchangeGoogleCode,
  getGoogleConfig,
  refreshGoogleToken,
  resolveGoogleScopes,
} from './providers/google.js';
import {
  buildGitHubAuthUrl,
  exchangeGitHubCode,
  getGitHubConfig,
  resolveGitHubScopes,
} from './providers/github.js';
import {
  buildMcpAuthUrl,
  exchangeMcpCode,
  refreshMcpToken,
  resolveMcpServerUrl,
} from './providers/mcp.js';

const SESSION_TTL_MS = 10 * 60 * 1000;
const HANDOFF_TTL_MS = 5 * 60 * 1000;
const DEFAULT_BASE_PATH = '/api/v1/rework/oauth';
const PROVIDERS = new Set(['google', 'github', 'slack', 'notion']);

function resolveConfig() {
  const publicCallbackUrl = process.env.PUBLIC_CALLBACK_URL?.trim();
  if (!publicCallbackUrl) {
    return {
      enabled: false,
      error: 'PUBLIC_CALLBACK_URL is required to enable the OAuth broker.',
      basePath: DEFAULT_BASE_PATH,
      callbackUrl: null,
      paths: {
        basePath: DEFAULT_BASE_PATH,
        callback: `${DEFAULT_BASE_PATH}/callback`,
        start: `${DEFAULT_BASE_PATH}/start`,
        handoff: `${DEFAULT_BASE_PATH}/handoff`,
        refresh: `${DEFAULT_BASE_PATH}/refresh`,
      },
    };
  }

  let callbackUrl;
  try {
    callbackUrl = new URL(publicCallbackUrl);
  } catch {
    throw new Error('PUBLIC_CALLBACK_URL is invalid.');
  }

  if (!callbackUrl.pathname.endsWith('/callback')) {
    throw new Error('PUBLIC_CALLBACK_URL must end with /callback.');
  }

  const basePath = callbackUrl.pathname.slice(0, -'/callback'.length);
  if (basePath !== DEFAULT_BASE_PATH) {
    throw new Error(`PUBLIC_CALLBACK_URL must use ${DEFAULT_BASE_PATH}/callback.`);
  }

  return {
    enabled: true,
    error: null,
    basePath,
    callbackUrl,
    paths: {
      basePath,
      callback: callbackUrl.pathname,
      start: `${basePath}/start`,
      handoff: `${basePath}/handoff`,
      refresh: `${basePath}/refresh`,
    },
  };
}

function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

function generateHandoffCode() {
  return crypto.randomBytes(24).toString('hex');
}

function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(32));
}

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64UrlEncode(hash);
}

function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html' });
  res.end(html);
}

async function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function normalizeScopes(input) {
  if (!input) return [];
  if (Array.isArray(input)) {
    return input.map((scope) => String(scope).trim()).filter(Boolean);
  }
  if (typeof input === 'string') {
    return input
      .split(/[\s,]+/)
      .map((scope) => scope.trim())
      .filter(Boolean);
  }
  return [];
}

function isProvider(value) {
  return PROVIDERS.has(value);
}

function requireAuth(req, res, apiKey) {
  if (!apiKey) return true;
  const header = req.headers.authorization;
  if (header !== `Bearer ${apiKey}`) {
    sendJson(res, 401, { error: 'unauthorized' });
    return false;
  }
  return true;
}

function validateLocalRedirectUri(raw) {
  if (typeof raw !== 'string') {
    throw new Error('localRedirectUri must be a string');
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('localRedirectUri is invalid');
  }

  if (url.protocol !== 'http:') {
    throw new Error('localRedirectUri must use http');
  }
  const host = url.hostname.toLowerCase();
  if (host !== 'localhost' && host !== '127.0.0.1' && host !== '::1') {
    throw new Error('localRedirectUri must point to localhost');
  }
  if (url.pathname !== '/callback') {
    throw new Error('localRedirectUri must end with /callback');
  }
  return url;
}

function redirectToLocal(res, localRedirectUri, params) {
  const target = new URL(localRedirectUri);
  for (const [key, value] of Object.entries(params)) {
    target.searchParams.set(key, value);
  }
  const body = `
    <html>
      <body style="font-family: system-ui; text-align: center; padding: 40px;">
        <h1>Authorization Complete</h1>
        <p>You can return to the app.</p>
      </body>
    </html>
  `;
  res.writeHead(302, { Location: target.toString(), 'Content-Type': 'text/html' });
  res.end(body);
}

export function createOAuthBroker() {
  const config = resolveConfig();
  const apiKey = process.env.BROKER_API_KEY?.trim();
  const sessions = new Map();
  const handoffs = new Map();

  function cleanupMaps() {
    const now = Date.now();
    for (const [state, session] of sessions.entries()) {
      if (now - session.createdAt > SESSION_TTL_MS) {
        sessions.delete(state);
      }
    }
    for (const [code, record] of handoffs.entries()) {
      if (now - record.createdAt > HANDOFF_TTL_MS) {
        handoffs.delete(code);
      }
    }
  }

  if (config.enabled) {
    setInterval(cleanupMaps, 60 * 1000).unref();
  }

  async function handleStart(req, res) {
    if (!requireAuth(req, res, apiKey)) return;

    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      sendJson(res, 400, { error: 'invalid_json' });
      return;
    }

    if (!isProvider(body.provider)) {
      sendJson(res, 400, { error: 'invalid_provider' });
      return;
    }

    let localRedirectUri;
    try {
      localRedirectUri = validateLocalRedirectUri(body.localRedirectUri);
    } catch (error) {
      sendJson(res, 400, { error: error.message });
      return;
    }

    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const scopesInput = normalizeScopes(body.scopes);

    try {
      let authUrl;
      let scopes = scopesInput;
      let serverUrl = body.serverUrl;

      switch (body.provider) {
        case 'google': {
          const googleConfig = getGoogleConfig();
          scopes = resolveGoogleScopes(scopesInput);
          authUrl = buildGoogleAuthUrl({
            clientId: googleConfig.clientId,
            redirectUri: config.callbackUrl.toString(),
            scopes,
            state,
            codeChallenge,
          });
          break;
        }
        case 'github': {
          const githubConfig = getGitHubConfig();
          scopes = resolveGitHubScopes(scopesInput);
          authUrl = buildGitHubAuthUrl({
            clientId: githubConfig.clientId,
            redirectUri: config.callbackUrl.toString(),
            scopes,
            state,
            codeChallenge,
          });
          break;
        }
        case 'slack':
        case 'notion': {
          serverUrl = resolveMcpServerUrl(body.provider, body.serverUrl);
          authUrl = await buildMcpAuthUrl({
            provider: body.provider,
            serverUrl,
            redirectUri: config.callbackUrl.toString(),
            scopes,
            state,
            codeChallenge,
          });
          break;
        }
        default:
          sendJson(res, 400, { error: 'unsupported_provider' });
          return;
      }

      const session = {
        provider: body.provider,
        codeVerifier,
        localRedirectUri: localRedirectUri.toString(),
        scopes,
        serverUrl,
        createdAt: Date.now(),
      };
      sessions.set(state, session);

      sendJson(res, 200, {
        authUrl,
        state,
        expiresAt: Date.now() + SESSION_TTL_MS,
      });
    } catch (error) {
      sendJson(res, 500, { error: error.message });
    }
  }

  async function exchangeForTokens(session, code) {
    switch (session.provider) {
      case 'google': {
        const googleConfig = getGoogleConfig();
        return exchangeGoogleCode({
          clientId: googleConfig.clientId,
          clientSecret: googleConfig.clientSecret,
          redirectUri: config.callbackUrl.toString(),
          code,
          codeVerifier: session.codeVerifier,
        });
      }
      case 'github': {
        const githubConfig = getGitHubConfig();
        return exchangeGitHubCode({
          clientId: githubConfig.clientId,
          clientSecret: githubConfig.clientSecret,
          redirectUri: config.callbackUrl.toString(),
          code,
          codeVerifier: session.codeVerifier,
        });
      }
      case 'slack':
      case 'notion': {
        const serverUrl = resolveMcpServerUrl(session.provider, session.serverUrl);
        return exchangeMcpCode({
          provider: session.provider,
          serverUrl,
          redirectUri: config.callbackUrl.toString(),
          code,
          codeVerifier: session.codeVerifier,
        });
      }
      default:
        throw new Error('Unsupported provider');
    }
  }

  async function handleCallback(req, res) {
    const requestUrl = new URL(req.url || '', `http://${req.headers.host ?? 'localhost'}`);
    const state = requestUrl.searchParams.get('state');
    const error = requestUrl.searchParams.get('error');
    const errorDescription = requestUrl.searchParams.get('error_description');
    const code = requestUrl.searchParams.get('code');

    const session = state ? sessions.get(state) : null;

    if (error) {
      if (session) {
        sessions.delete(state);
        redirectToLocal(res, session.localRedirectUri, {
          error: errorDescription ? `${error}: ${errorDescription}` : error,
          state: state ?? '',
        });
        return;
      }
      sendHtml(
        res,
        400,
        `<html><body><h1>Authorization Failed</h1><p>${error}</p></body></html>`
      );
      return;
    }

    if (!code || !state || !session) {
      sendHtml(
        res,
        400,
        '<html><body><h1>Invalid callback</h1><p>Missing or invalid state.</p></body></html>'
      );
      return;
    }

    try {
      const tokens = await exchangeForTokens(session, code);
      const handoffCode = generateHandoffCode();
      handoffs.set(handoffCode, { tokens, createdAt: Date.now() });
      sessions.delete(state);
      redirectToLocal(res, session.localRedirectUri, { code: handoffCode, state });
    } catch (error) {
      sessions.delete(state);
      redirectToLocal(res, session.localRedirectUri, {
        error: error.message,
        state,
      });
    }
  }

  async function handleHandoff(req, res) {
    if (!requireAuth(req, res, apiKey)) return;
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      sendJson(res, 400, { error: 'invalid_json' });
      return;
    }

    const code = body.code;
    if (!code || typeof code !== 'string') {
      sendJson(res, 400, { error: 'missing_code' });
      return;
    }

    const record = handoffs.get(code);
    if (!record) {
      sendJson(res, 404, { error: 'handoff_not_found' });
      return;
    }

    handoffs.delete(code);
    sendJson(res, 200, { tokens: record.tokens });
  }

  async function handleRefresh(req, res) {
    if (!requireAuth(req, res, apiKey)) return;
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      sendJson(res, 400, { error: 'invalid_json' });
      return;
    }

    if (!isProvider(body.provider)) {
      sendJson(res, 400, { error: 'invalid_provider' });
      return;
    }
    if (!body.refreshToken) {
      sendJson(res, 400, { error: 'missing_refresh_token' });
      return;
    }

    if (body.provider === 'github') {
      sendJson(res, 400, { error: 'refresh_not_supported' });
      return;
    }

    try {
      let tokens;
      if (body.provider === 'google') {
        const googleConfig = getGoogleConfig();
        tokens = await refreshGoogleToken({
          clientId: googleConfig.clientId,
          clientSecret: googleConfig.clientSecret,
          refreshToken: body.refreshToken,
        });
      } else {
        const serverUrl = resolveMcpServerUrl(body.provider, body.serverUrl);
        tokens = await refreshMcpToken({
          provider: body.provider,
          serverUrl,
          redirectUri: config.callbackUrl.toString(),
          refreshToken: body.refreshToken,
        });
      }

      sendJson(res, 200, { tokens });
    } catch (error) {
      sendJson(res, 500, { error: error.message });
    }
  }

  async function handle(req, res) {
    const method = req.method ?? 'GET';
    const requestUrl = new URL(req.url || '', `http://${req.headers.host ?? 'localhost'}`);

    if (!requestUrl.pathname.startsWith(config.paths.basePath)) {
      return false;
    }

    if (!config.enabled) {
      sendJson(res, 503, { error: config.error });
      return true;
    }

    if (method === 'GET' && requestUrl.pathname === config.paths.callback) {
      await handleCallback(req, res);
      return true;
    }

    if (method === 'POST' && requestUrl.pathname === config.paths.start) {
      await handleStart(req, res);
      return true;
    }

    if (method === 'POST' && requestUrl.pathname === config.paths.handoff) {
      await handleHandoff(req, res);
      return true;
    }

    if (method === 'POST' && requestUrl.pathname === config.paths.refresh) {
      await handleRefresh(req, res);
      return true;
    }

    sendJson(res, 404, { error: 'not_found' });
    return true;
  }

  return {
    handle,
    enabled: config.enabled,
    paths: config.paths,
  };
}
