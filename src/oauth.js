/**
 * OAuth login for the Converly CLI.
 *
 * Flow (standard RFC 8252 native-app pattern):
 *  1. Fetch the origin's OAuth discovery document.
 *  2. Start a loopback HTTP server on 127.0.0.1 (ephemeral port).
 *  3. Dynamically register a public PKCE client whose redirect_uri is
 *     that exact loopback URL (Converly allows anonymous registration,
 *     and loopback http redirects are explicitly permitted).
 *  4. Open the browser at the authorize URL. The person logs in (or
 *     signs up — new accounts get a free trial automatically) and
 *     approves the consent screen.
 *  5. Catch the redirect, exchange the code (PKCE) for tokens, store
 *     them in ~/.converly/config.json.
 *
 * The access token is a Converly sk_live_* credential scoped to exactly
 * the agent-safe permission set (no billing, no destination credential
 * writes, no site deletion). Refresh tokens keep the login alive.
 */

import crypto from "node:crypto";
import http from "node:http";
import { spawn } from "node:child_process";
import {
  getStoredCredentials,
  setStoredCredentials,
} from "./config.js";

/** Scopes requested at login — must stay within the server's DCR ceiling. */
export const LOGIN_SCOPES = [
  "openid",
  "profile",
  "offline_access",
  "account:read",
  "sites:read",
  "sites:write",
  "flows:read",
  "flows:write",
  "destinations:read",
  "destinations:disconnect",
  "events:read",
  "handoffs:create",
  "internal_traffic:write",
].join(" ");

const LOGIN_TIMEOUT_MS = 5 * 60 * 1000;

function b64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function makePkce() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(
    crypto.createHash("sha256").update(verifier).digest()
  );
  return { verifier, challenge };
}

export async function discover(origin) {
  const res = await fetch(`${origin}/.well-known/oauth-authorization-server`);
  if (!res.ok) {
    throw new Error(
      `Could not load OAuth configuration from ${origin} (HTTP ${res.status}).`
    );
  }
  const doc = await res.json();
  for (const field of [
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
  ]) {
    if (!doc[field]) {
      throw new Error(`OAuth discovery document is missing ${field}.`);
    }
  }
  return doc;
}

async function registerClient(registrationEndpoint, redirectUri) {
  const res = await fetch(registrationEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Converly CLI",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: LOGIN_SCOPES,
    }),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || !body?.client_id) {
    const detail = body?.error_description ?? body?.error ?? `HTTP ${res.status}`;
    throw new Error(`Client registration failed: ${detail}`);
  }
  return body.client_id;
}

function openBrowser(url) {
  const command =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "start"
        : "xdg-open";
  try {
    const child = spawn(command, [url], {
      stdio: "ignore",
      detached: true,
      shell: process.platform === "win32",
    });
    child.on("error", () => {});
    child.unref();
  } catch {
    // Fine — the URL is printed for manual opening.
  }
}

const SUCCESS_HTML = `<!doctype html><html><head><title>Converly CLI</title>
<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#0b0d12;color:#e7e9ee}
main{text-align:center}h1{font-size:1.4rem}p{color:#9aa1ad}</style></head>
<body><main><h1>You're logged in</h1><p>You can close this tab and return to the terminal.</p></main></body></html>`;

function failureHtml(reason) {
  return SUCCESS_HTML.replace("You're logged in", "Login didn't complete")
    .replace(
      "You can close this tab and return to the terminal.",
      `${reason} You can close this tab and re-run the command.`
    );
}

/**
 * Wait for exactly one OAuth redirect on a loopback server.
 * Resolves { code } or rejects on error/timeout/denial.
 */
function waitForCallback(server, expectedState) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Timed out waiting for the browser login (5 minutes)."));
    }, LOGIN_TIMEOUT_MS);

    server.on("request", (req, res) => {
      const url = new URL(req.url, "http://127.0.0.1");
      if (url.pathname !== "/callback") {
        res.writeHead(404).end();
        return;
      }
      const fail = (message) => {
        res
          .writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
          .end(failureHtml(message));
        clearTimeout(timer);
        reject(new Error(message));
      };
      const err = url.searchParams.get("error");
      if (err) {
        fail(
          err === "access_denied"
            ? "The authorization was declined."
            : `The authorization server returned: ${err}.`
        );
        return;
      }
      if (url.searchParams.get("state") !== expectedState) {
        fail("State mismatch — possible cross-request interference.");
        return;
      }
      const code = url.searchParams.get("code");
      if (!code) {
        fail("No authorization code was returned.");
        return;
      }
      res
        .writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
        .end(SUCCESS_HTML);
      clearTimeout(timer);
      resolve({ code });
    });
  });
}

async function exchangeToken(tokenEndpoint, params) {
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || !body?.access_token) {
    const detail = body?.error_description ?? body?.error ?? `HTTP ${res.status}`;
    throw new Error(`Token request failed: ${detail}`);
  }
  return body;
}

function storeTokens(origin, clientId, tokens) {
  const creds = {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? null,
    expires_at:
      typeof tokens.expires_in === "number"
        ? Date.now() + tokens.expires_in * 1000
        : null,
    scope: tokens.scope ?? LOGIN_SCOPES,
    client_id: clientId,
    obtained_at: new Date().toISOString(),
  };
  setStoredCredentials(origin, creds);
  return creds;
}

/**
 * Interactive browser login. progress() receives human-facing status
 * lines (callers send them to stderr so stdout stays machine-readable).
 */
export async function loginFlow({ origin, signup = false, progress = () => {} }) {
  const doc = await discover(origin);

  const server = http.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  try {
    const { port } = server.address();
    const redirectUri = `http://127.0.0.1:${port}/callback`;

    progress("Registering the CLI with Converly...");
    const clientId = await registerClient(doc.registration_endpoint, redirectUri);

    const { verifier, challenge } = makePkce();
    const state = b64url(crypto.randomBytes(16));

    const authorizeUrl = new URL(doc.authorization_endpoint);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("scope", LOGIN_SCOPES);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");
    if (signup) authorizeUrl.searchParams.set("prompt", "create");

    progress("Opening your browser to log in to Converly...");
    progress(`If it doesn't open, visit:\n\n  ${authorizeUrl}\n`);
    openBrowser(authorizeUrl.toString());

    const { code } = await waitForCallback(server, state);
    progress("Exchanging the authorization code for credentials...");

    const tokens = await exchangeToken(doc.token_endpoint, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    const creds = storeTokens(origin, clientId, tokens);
    return {
      origin,
      scope: creds.scope,
      expires_at: creds.expires_at,
      has_refresh_token: Boolean(creds.refresh_token),
    };
  } finally {
    server.close();
  }
}

/**
 * Refresh the stored token for an origin. Returns the new credentials,
 * or throws if there is nothing to refresh / the server refuses.
 */
export async function refreshCredentials(origin) {
  const stored = getStoredCredentials(origin);
  if (!stored?.refresh_token || !stored?.client_id) {
    throw new Error(`No refreshable login for ${origin}.`);
  }
  const doc = await discover(origin);
  const tokens = await exchangeToken(doc.token_endpoint, {
    grant_type: "refresh_token",
    refresh_token: stored.refresh_token,
    client_id: stored.client_id,
  });
  // Some servers rotate refresh tokens; keep the old one if none returned.
  if (!tokens.refresh_token) tokens.refresh_token = stored.refresh_token;
  return storeTokens(origin, stored.client_id, tokens);
}
