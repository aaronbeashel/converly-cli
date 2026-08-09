/**
 * OAuth login for the Converly CLI.
 *
 * Flow (standard RFC 8252 native-app pattern):
 *  1. Fetch the origin's OAuth discovery document.
 *  2. Start a loopback HTTP server on 127.0.0.1 (ephemeral port) and
 *     attach the callback listener BEFORE the browser opens, so a fast
 *     redirect can never be missed.
 *  3. Dynamically register a public PKCE client whose redirect_uri is
 *     that exact loopback URL (Converly allows anonymous registration,
 *     and loopback http redirects are explicitly permitted).
 *  4. Open the browser at the authorize URL. The person logs in (or
 *     signs up — new accounts get a free trial automatically) and
 *     approves the consent screen.
 *  5. Catch the redirect, exchange the code (PKCE) for tokens, store
 *     them in ~/.converly/config.json. The browser page deliberately
 *     says "return to the terminal" rather than claiming success —
 *     the terminal is the source of truth, because the token exchange
 *     happens after the redirect.
 *
 * The access token is a Converly sk_live_* credential scoped to exactly
 * the agent-safe permission set (no billing, no destination credential
 * writes, no site deletion). Refresh tokens keep the login alive.
 *
 * Note: this flow requires the browser and the CLI to be on the SAME
 * machine — the redirect lands on the CLI's loopback listener. For
 * remote/headless environments, set CONVERLY_API_KEY instead.
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

// Generous on purpose: a brand-new user creates an account mid-login
// (email, password, consent), which comfortably exceeds a short window.
const LOGIN_TIMEOUT_MS = 10 * 60 * 1000;

/** Bounded network calls — a hung endpoint should fail, not freeze. */
const FETCH_TIMEOUT_MS = 30_000;

function fetchWithTimeout(url, init = {}) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
}

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

export function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export async function discover(origin) {
  const res = await fetchWithTimeout(
    `${origin}/.well-known/oauth-authorization-server`
  );
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
  const res = await fetchWithTimeout(registrationEndpoint, {
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

/**
 * Open a URL in the platform browser WITHOUT a shell, so URL metacharacters
 * (& is in every OAuth URL) can never be interpreted as commands.
 */
export function openBrowser(url) {
  const launcher =
    process.platform === "darwin"
      ? { command: "open", args: [url] }
      : process.platform === "win32"
        ? { command: "rundll32", args: ["url.dll,FileProtocolHandler", url] }
        : { command: "xdg-open", args: [url] };
  try {
    const child = spawn(launcher.command, launcher.args, {
      stdio: "ignore",
      detached: true,
    });
    child.on("error", () => {});
    child.unref();
  } catch {
    // Fine — the URL is printed for manual opening.
  }
}

function page(title, body) {
  return `<!doctype html><html><head><title>Converly CLI</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#0b0d12;color:#e7e9ee}
main{text-align:center;max-width:28rem;padding:0 1rem}h1{font-size:1.4rem}p{color:#9aa1ad}</style></head>
<body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p></main></body></html>`;
}

// Deliberately neutral: the token exchange hasn't happened yet when this
// renders, so this page must not claim the login succeeded.
const RETURN_PAGE = page(
  "Almost done",
  "Return to the terminal to finish logging in. You can close this tab."
);

/**
 * Wait for the one OAuth redirect that carries our state value.
 * Requests without a matching state (stray probes, favicons, other apps
 * hitting the port) are ignored with a 404 — they can neither cancel nor
 * complete the login. Resolves { code } or rejects on denial/timeout.
 */
function waitForCallback(server, expectedState) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new Error(
          "Timed out waiting for the browser login (10 minutes). Run `converly login` again when you're ready."
        )
      );
    }, LOGIN_TIMEOUT_MS);

    server.on("request", (req, res) => {
      const url = new URL(req.url, "http://127.0.0.1");
      // State is validated FIRST: only our own redirect gets any further.
      if (
        url.pathname !== "/callback" ||
        url.searchParams.get("state") !== expectedState
      ) {
        res.writeHead(404).end();
        return;
      }
      const finish = (html, outcome) => {
        res
          .writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
          })
          .end(html);
        clearTimeout(timer);
        outcome();
      };
      const err = url.searchParams.get("error");
      if (err) {
        const message =
          err === "access_denied"
            ? "The authorization was declined."
            : `The authorization server returned: ${err}.`;
        finish(page("Login didn't complete", message), () =>
          reject(new Error(message))
        );
        return;
      }
      const code = url.searchParams.get("code");
      if (!code) {
        const message = "No authorization code was returned.";
        finish(page("Login didn't complete", message), () =>
          reject(new Error(message))
        );
        return;
      }
      finish(RETURN_PAGE, () => resolve({ code }));
    });
  });
}

async function exchangeToken(tokenEndpoint, params) {
  const res = await fetchWithTimeout(tokenEndpoint, {
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

function credsFromTokens(clientId, tokens, previousScope) {
  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? null,
    expires_at:
      typeof tokens.expires_in === "number"
        ? Date.now() + tokens.expires_in * 1000
        : null,
    // On refresh, an omitted scope means "unchanged" (RFC 6749 §6) — keep
    // what was stored rather than assuming this CLI build's scope list.
    scope: tokens.scope ?? previousScope,
    client_id: clientId,
    obtained_at: new Date().toISOString(),
  };
}

/**
 * Interactive browser login. progress() receives human-facing status
 * lines (callers send them to stderr so stdout stays machine-readable).
 * Set noOpen to print the URL without spawning a browser.
 */
export async function loginFlow({
  origin,
  signup = false,
  noOpen = false,
  progress = () => {},
}) {
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

    // Listener first, browser second — a fast redirect can't be missed.
    const callback = waitForCallback(server, state);

    progress(
      "Log in using the browser on THIS machine (the login hands its result back to the CLI here)."
    );
    progress(`If a browser doesn't open, visit:\n\n  ${authorizeUrl}\n`);
    if (!noOpen) openBrowser(authorizeUrl.toString());

    const { code } = await callback;
    progress("Exchanging the authorization code for credentials...");

    const tokens = await exchangeToken(doc.token_endpoint, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    const creds = credsFromTokens(clientId, tokens, LOGIN_SCOPES);
    // A deliberate login selects this origin as the default deployment.
    setStoredCredentials(origin, creds, { makeDefault: true });
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

// One in-flight refresh per origin. Concurrent 401s (parallel requests
// after expiry) must not race each other: with refresh-token rotation,
// the second refresh attempt would use a consumed token and fail.
const refreshInFlight = new Map();

/**
 * Refresh the stored token for an origin. Returns the new credentials,
 * or throws if there is nothing to refresh / the server refuses.
 */
export function refreshCredentials(origin) {
  const existing = refreshInFlight.get(origin);
  if (existing) return existing;

  const task = (async () => {
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
    const creds = credsFromTokens(stored.client_id, tokens, stored.scope);
    // A background refresh must not change which deployment is default.
    setStoredCredentials(origin, creds, { makeDefault: false });
    return creds;
  })().finally(() => refreshInFlight.delete(origin));

  refreshInFlight.set(origin, task);
  return task;
}
