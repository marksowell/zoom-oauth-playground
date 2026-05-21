import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const publicDir = join(__dirname, "public");
const port = Number(process.env.PORT || 3000);
const sessionCookieName = "zoom_oauth_lab_sid";
const sessionTtlMs = 15 * 60 * 1000;
const oauthAuthorizeEndpoint = "https://zoom.us/oauth/authorize";
const sessions = new Map();

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

function json(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload, null, 2));
}

function writeJson(res, statusCode, payload, headers = {}) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  });
  res.end(JSON.stringify(payload, null, 2));
}

async function readRequestBody(req) {
  return await new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function buildBasicAuthHeader(clientId, clientSecret = "") {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

function buildStateToken(mode, label = "") {
  return `${mode}:${label || "default"}:${randomUUID().slice(0, 8)}`;
}

function buildAuthorizeUrl({ clientId, redirectUri, scope, stateToken, codeChallenge }) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: stateToken
  });

  if (scope?.trim()) {
    params.set("scope", scope.trim());
  }

  if (codeChallenge) {
    params.set("code_challenge", codeChallenge);
    params.set("code_challenge_method", "S256");
  }

  return `${oauthAuthorizeEndpoint}?${params.toString()}`;
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return {};
  }

  return Object.fromEntries(
    cookieHeader
      .split(";")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => {
        const separatorIndex = entry.indexOf("=");
        if (separatorIndex === -1) {
          return [entry, ""];
        }

        const key = entry.slice(0, separatorIndex);
        const value = entry.slice(separatorIndex + 1);
        return [key, decodeURIComponent(value)];
      })
  );
}

function buildSessionCookie(sessionId, maxAgeMs = sessionTtlMs) {
  const maxAgeSeconds = Math.max(0, Math.floor(maxAgeMs / 1000));
  return `${sessionCookieName}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function getSession(req) {
  const cookies = parseCookies(req);
  const sessionId = cookies[sessionCookieName];

  if (!sessionId) {
    return null;
  }

  const session = sessions.get(sessionId);
  if (!session) {
    return null;
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }

  return { sessionId, session };
}

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(sessionId);
    }
  }
}

async function exchangeCode({
  clientId,
  clientSecret = "",
  code,
  codeVerifier,
  redirectUri,
  usePkce
}) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri
  });

  if (usePkce) {
    params.set("code_verifier", codeVerifier);
  }

  const response = await fetch("https://zoom.us/oauth/token", {
    method: "POST",
    headers: {
      Authorization: buildBasicAuthHeader(clientId, clientSecret)
    },
    body: params
  });

  const text = await response.text();
  let body;

  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }

  return {
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    body
  };
}

async function handleSessionStart(req, res) {
  try {
    cleanupExpiredSessions();
    const rawBody = await readRequestBody(req);
    const payload = JSON.parse(rawBody || "{}");
    const isPkce = payload.mode === "pkce";
    const requiredFields = isPkce
      ? ["clientId", "redirectUri", "codeVerifier", "codeChallenge"]
      : ["clientId", "clientSecret", "redirectUri"];

    for (const field of requiredFields) {
      if (!payload[field]) {
        return json(res, 400, { error: `Missing required field: ${field}` });
      }
    }

    const sessionId = randomUUID();
    const stateToken = buildStateToken(payload.mode, payload.stateLabel);
    const authorizeUrl = buildAuthorizeUrl({
      clientId: payload.clientId,
      redirectUri: payload.redirectUri,
      scope: payload.scope,
      stateToken,
      codeChallenge: payload.codeChallenge
    });

    const session = {
      mode: payload.mode,
      clientId: payload.clientId,
      clientSecret: payload.clientSecret || "",
      redirectUri: payload.redirectUri,
      codeVerifier: payload.codeVerifier || "",
      stateToken,
      authorizeUrl,
      scope: payload.scope || "",
      createdAt: Date.now(),
      expiresAt: Date.now() + sessionTtlMs
    };

    sessions.set(sessionId, session);

    return writeJson(
      res,
      200,
      {
        ok: true,
        mode: payload.mode,
        stateToken,
        authorizeUrl,
        expiresAt: new Date(session.expiresAt).toISOString()
      },
      { "Set-Cookie": buildSessionCookie(sessionId) }
    );
  } catch (error) {
    return json(res, 500, {
      error: "Unable to start OAuth session.",
      details: error instanceof Error ? error.message : String(error)
    });
  }
}

async function handleTokenExchange(req, res, usePkce) {
  try {
    cleanupExpiredSessions();
    const activeSession = getSession(req);
    if (!activeSession) {
      return json(res, 401, {
        error: "No active OAuth session found. Start the flow from this page first."
      });
    }

    const rawBody = await readRequestBody(req);
    const payload = JSON.parse(rawBody || "{}");
    if (!payload.code) {
      return json(res, 400, { error: "Missing required field: code" });
    }

    if (payload.state && payload.state !== activeSession.session.stateToken) {
      return json(res, 400, {
        error: "State mismatch. The callback did not match the active test session."
      });
    }

    if ((activeSession.session.mode === "pkce") !== usePkce) {
      return json(res, 400, {
        error: `Active session is ${activeSession.session.mode}, but this endpoint expects ${
          usePkce ? "pkce" : "confidential"
        }.`
      });
    }

    const result = await exchangeCode({
      clientId: activeSession.session.clientId,
      clientSecret: activeSession.session.clientSecret,
      code: payload.code,
      codeVerifier: activeSession.session.codeVerifier,
      redirectUri: activeSession.session.redirectUri,
      usePkce
    });

    return json(res, result.ok ? 200 : 502, {
      mode: usePkce ? "pkce" : "confidential",
      requestedAt: new Date().toISOString(),
      ...result
    });
  } catch (error) {
    return json(res, 500, {
      error: "Token exchange failed.",
      details: error instanceof Error ? error.message : String(error)
    });
  }
}

async function handleSessionClear(req, res) {
  const activeSession = getSession(req);
  if (activeSession) {
    sessions.delete(activeSession.sessionId);
  }

  return writeJson(
    res,
    200,
    { ok: true },
    { "Set-Cookie": buildSessionCookie("", 0) }
  );
}

async function handleSessionCurrent(req, res) {
  cleanupExpiredSessions();
  const activeSession = getSession(req);
  if (!activeSession) {
    return json(res, 200, { ok: true, session: null });
  }

  return json(res, 200, {
    ok: true,
    session: {
      mode: activeSession.session.mode,
      clientId: activeSession.session.clientId,
      redirectUri: activeSession.session.redirectUri,
      scope: activeSession.session.scope,
      stateToken: activeSession.session.stateToken,
      createdAt: new Date(activeSession.session.createdAt).toISOString(),
      expiresAt: new Date(activeSession.session.expiresAt).toISOString()
    }
  });
}

async function serveStaticFile(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
  const safePath = normalize(pathname).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(publicDir, safePath);

  try {
    const file = await readFile(filePath);
    const contentType = contentTypes[extname(filePath)] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(file);
  } catch {
    json(res, 404, { error: "Not found" });
  }
}

const server = createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/api/session/start") {
    return handleSessionStart(req, res);
  }

  if (req.method === "POST" && req.url === "/api/session/clear") {
    return handleSessionClear(req, res);
  }

  if (req.method === "GET" && req.url === "/api/session/current") {
    return handleSessionCurrent(req, res);
  }

  if (req.method === "POST" && req.url === "/api/exchange/confidential") {
    return handleTokenExchange(req, res, false);
  }

  if (req.method === "POST" && req.url === "/api/exchange/pkce") {
    return handleTokenExchange(req, res, true);
  }

  if (req.method === "GET" && req.url === "/api/health") {
    return json(res, 200, {
      ok: true,
      redirectSuggestion: `http://localhost:${port}/`
    });
  }

  return serveStaticFile(req, res);
});

server.listen(port, () => {
  console.log(`Zoom OAuth test app running at http://localhost:${port}`);
});
