import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const MCP_USER_AGENT = 'Rework-OAuth-Broker/0.1.0';
const DEFAULT_MCP_URLS = {
  slack: 'https://mcp.slack.com/mcp',
  notion: 'https://mcp.notion.com/mcp',
};

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function normalize(value) {
  if (!value) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeServerUrl(serverUrl) {
  return serverUrl.endsWith('/') ? serverUrl.slice(0, -1) : serverUrl;
}

export function resolveMcpServerUrl(provider, serverUrl) {
  const fromRequest = normalize(serverUrl);
  const fromEnv = normalize(
    provider === 'slack' ? process.env.MCP_SLACK_URL : process.env.MCP_NOTION_URL
  );
  const resolved = fromRequest ?? fromEnv ?? DEFAULT_MCP_URLS[provider];
  if (!resolved) {
    throw new Error(`Missing MCP server URL for ${provider}.`);
  }
  return normalizeServerUrl(resolved);
}

function getEnvClient(provider) {
  const clientId = normalize(
    provider === 'slack' ? process.env.MCP_SLACK_CLIENT_ID : process.env.MCP_NOTION_CLIENT_ID
  );
  if (!clientId) return null;
  const clientSecret = normalize(
    provider === 'slack'
      ? process.env.MCP_SLACK_CLIENT_SECRET
      : process.env.MCP_NOTION_CLIENT_SECRET
  );
  return { clientId, clientSecret };
}

function getClientStorePath() {
  const custom = normalize(process.env.MCP_CLIENT_STORE_PATH);
  if (custom) {
    return path.resolve(custom);
  }
  if (process.env.VERCEL) {
    return '/tmp/mcp-clients.json';
  }
  return path.resolve(__dirname, '..', 'data', 'mcp-clients.json');
}

function loadClientStore() {
  const clientStorePath = getClientStorePath();
  try {
    if (!fs.existsSync(clientStorePath)) return {};
    const raw = fs.readFileSync(clientStorePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return parsed ?? {};
  } catch {
    return {};
  }
}

function saveClientStore(store) {
  const clientStorePath = getClientStorePath();
  const dir = path.dirname(clientStorePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(clientStorePath, JSON.stringify(store, null, 2));
}

function getStoreKey(provider, serverUrl) {
  return `${provider}:${serverUrl}`;
}

function parseResourceMetadataHeader(header) {
  if (!header) return null;
  const match = header.match(/resource_metadata="?([^",\s]+)"?/i);
  return match ? match[1] : null;
}

function resolveResourceMetadataUrl(baseUrl, metadataUrl) {
  try {
    return new URL(metadataUrl, baseUrl).toString();
  } catch {
    return metadataUrl;
  }
}

function getResourceMetadataCandidates(serverUrl) {
  const url = new URL(serverUrl);
  const origin = url.origin;
  const pathSegment = url.pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  const normalizedServer = normalizeServerUrl(serverUrl);
  const candidates = [];

  candidates.push(`${normalizedServer}/.well-known/oauth-protected-resource`);
  if (pathSegment.length > 0) {
    candidates.push(`${origin}/.well-known/oauth-protected-resource/${pathSegment}`);
  }
  candidates.push(`${origin}/.well-known/oauth-protected-resource`);

  return Array.from(new Set(candidates));
}

async function tryGetResourceMetadataUrlFromServer(serverUrl) {
  try {
    const response = await fetch(serverUrl, {
      headers: { Accept: 'application/json', 'User-Agent': MCP_USER_AGENT },
    });
    const header = response.headers.get('www-authenticate');
    const resourceMetadata = parseResourceMetadataHeader(header);
    return resourceMetadata ? resolveResourceMetadataUrl(serverUrl, resourceMetadata) : null;
  } catch {
    return null;
  }
}

async function resolveProtectedResourceMetadata(serverUrl) {
  const queue = [];
  const seen = new Set();

  const headerUrl = await tryGetResourceMetadataUrlFromServer(serverUrl);
  if (headerUrl) {
    queue.push(headerUrl);
  }

  for (const candidate of getResourceMetadataCandidates(serverUrl)) {
    queue.push(candidate);
  }

  while (queue.length > 0) {
    const url = queue.shift();
    if (!url || seen.has(url)) continue;
    seen.add(url);

    try {
      const response = await fetch(url, {
        headers: { Accept: 'application/json', 'User-Agent': MCP_USER_AGENT },
      });

      if (response.ok) {
        return await response.json();
      }

      if (response.status === 401 || response.status === 403) {
        const header = response.headers.get('www-authenticate');
        const resourceMetadata = parseResourceMetadataHeader(header);
        if (resourceMetadata) {
          queue.push(resolveResourceMetadataUrl(url, resourceMetadata));
        }
      }
    } catch {
      // ignore and try next
    }
  }

  throw new Error('Failed to fetch MCP OAuth metadata');
}

async function discoverOAuthMetadata(serverUrl) {
  const protectedMetadata = await resolveProtectedResourceMetadata(serverUrl);
  const authServer = protectedMetadata.authorization_servers?.[0] ?? new URL(serverUrl).origin;
  const authServerUrl = new URL('/.well-known/oauth-authorization-server', authServer);

  const authResponse = await fetch(authServerUrl.toString(), {
    headers: { Accept: 'application/json', 'User-Agent': MCP_USER_AGENT },
  });

  if (!authResponse.ok) {
    throw new Error(`Failed to fetch OAuth authorization metadata (${authResponse.status})`);
  }

  return await authResponse.json();
}

async function ensureMcpClient(params) {
  const provider = params.provider;
  const envClient = getEnvClient(provider);
  if (envClient?.clientId) {
    return envClient;
  }

  const store = loadClientStore();
  const key = getStoreKey(params.provider, params.serverUrl);
  const cached = store[key];
  if (cached?.clientId) {
    return cached;
  }

  if (!params.metadata.registration_endpoint) {
    throw new Error('MCP server does not support dynamic client registration.');
  }

  const response = await fetch(params.metadata.registration_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': MCP_USER_AGENT,
    },
    body: JSON.stringify({
      client_name: 'Rework OAuth Broker',
      redirect_uris: [params.redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  });

  if (!response.ok) {
    throw new Error(`MCP client registration failed (${response.status})`);
  }

  const data = await response.json();
  const clientInfo = {
    clientId: data.client_id,
    clientSecret: data.client_secret ?? null,
  };

  store[key] = clientInfo;
  saveClientStore(store);

  return clientInfo;
}

export async function buildMcpAuthUrl(params) {
  const metadata = await discoverOAuthMetadata(params.serverUrl);
  const client = await ensureMcpClient({
    provider: params.provider,
    serverUrl: params.serverUrl,
    metadata,
    redirectUri: params.redirectUri,
  });

  const authUrl = new URL(metadata.authorization_endpoint);
  authUrl.searchParams.set('client_id', client.clientId);
  authUrl.searchParams.set('redirect_uri', params.redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('state', params.state);
  authUrl.searchParams.set('code_challenge', params.codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  if (params.scopes.length > 0) {
    authUrl.searchParams.set('scope', params.scopes.join(' '));
  }

  return authUrl.toString();
}

async function readJsonResponse(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}

export async function exchangeMcpCode(params) {
  const metadata = await discoverOAuthMetadata(params.serverUrl);
  const client = await ensureMcpClient({
    provider: params.provider,
    serverUrl: params.serverUrl,
    metadata,
    redirectUri: params.redirectUri,
  });

  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      'User-Agent': MCP_USER_AGENT,
    },
    body: new URLSearchParams({
      client_id: client.clientId,
      ...(client.clientSecret ? { client_secret: client.clientSecret } : {}),
      code: params.code,
      grant_type: 'authorization_code',
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    }),
  });

  const data = await readJsonResponse(response);
  if (!response.ok) {
    const detail = data?.error_description || data?.error || response.statusText;
    throw new Error(`MCP token exchange failed (${response.status}): ${detail}`);
  }
  if (data.error) {
    throw new Error(data.error_description || data.error);
  }

  const expiresIn = Number(data.expires_in ?? 3600);

  return {
    accessToken: data.access_token ?? '',
    refreshToken: data.refresh_token ?? '',
    expiresAt: Date.now() + expiresIn * 1000,
    tokenType: data.token_type ?? 'Bearer',
  };
}

export async function refreshMcpToken(params) {
  const metadata = await discoverOAuthMetadata(params.serverUrl);
  const client = await ensureMcpClient({
    provider: params.provider,
    serverUrl: params.serverUrl,
    metadata,
    redirectUri: params.redirectUri,
  });

  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      'User-Agent': MCP_USER_AGENT,
    },
    body: new URLSearchParams({
      client_id: client.clientId,
      ...(client.clientSecret ? { client_secret: client.clientSecret } : {}),
      refresh_token: params.refreshToken,
      grant_type: 'refresh_token',
    }),
  });

  const data = await readJsonResponse(response);
  if (!response.ok) {
    const detail = data?.error_description || data?.error || response.statusText;
    throw new Error(`MCP token refresh failed (${response.status}): ${detail}`);
  }
  if (data.error) {
    throw new Error(data.error_description || data.error);
  }

  const expiresIn = Number(data.expires_in ?? 3600);

  return {
    accessToken: data.access_token ?? '',
    refreshToken: data.refresh_token ?? params.refreshToken,
    expiresAt: Date.now() + expiresIn * 1000,
    tokenType: data.token_type ?? 'Bearer',
  };
}
