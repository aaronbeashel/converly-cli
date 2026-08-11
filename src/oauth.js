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
  commitRefreshedCredentials,
  withRefreshLock,
  isSameTrustedOrigin,
} from "./config.js";
import { readTextCapped } from "./net.js";

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
  return fetch(url, {
    ...init,
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    // These are all credential-bearing OAuth calls (discovery, DCR, token
    // exchange, refresh). A 307/308 forwards the POST body (PKCE verifier /
    // refresh token) to the redirect target — Node strips Authorization but
    // NOT the body — so a malicious/misconfigured endpoint could exfiltrate
    // it. None of these endpoints legitimately redirects, so refuse.
    redirect: "error",
  });
}

/** Cap a credential/metadata response so a hostile endpoint can't exhaust
 *  memory. OAuth docs are tiny; 1 MB is already generous. */
const OAUTH_MAX_BYTES = 1_000_000;
async function readJsonCapped(res, maxBytes = OAUTH_MAX_BYTES) {
  // Streaming cap so an absent/lying Content-Length can't exhaust memory.
  const read = await readTextCapped(res, maxBytes);
  if (read.overLimit) throw new Error("Response too large.");
  if (read.unreadable) throw new Error("Could not read the response.");
  try {
    return JSON.parse(read.text);
  } catch {
    // Clean, consistent error for the one caller (discover) that doesn't
    // wrap this in .catch — a raw SyntaxError would leak as an ugly crash.
    throw new Error("Response was not valid JSON.");
  }
}

/** Constant-time string compare (equal-length first). */
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
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
  const doc = await readJsonCapped(res);
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error("OAuth discovery document was not a JSON object.");
  }
  for (const field of [
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
  ]) {
    if (typeof doc[field] !== "string" || !doc[field]) {
      throw new Error(`OAuth discovery document is missing ${field}.`);
    }
    // CRITICAL trust boundary: every endpoint the discovery doc names must
    // live on the SAME origin we chose. Otherwise a compromised/hostile
    // origin could point token_endpoint at attacker.example and the CLI
    // would POST the refresh token / PKCE verifier straight to it.
    // redirect:"error" does NOT help here — this is the primary URL, not a
    // redirect. Metadata must never widen the trust boundary.
    if (!isSameTrustedOrigin(doc[field], origin)) {
      throw new Error(
        `OAuth ${field} (${doc[field]}) is not on ${origin}. ` +
          `Refusing to send credentials to a different host than the one you selected.`
      );
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
  const body = await readJsonCapped(res).catch(() => null);
  if (!res.ok || typeof body?.client_id !== "string" || !body.client_id.trim()) {
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
    const childEnv = { ...process.env };
    delete childEnv.CONVERLY_API_KEY;
    const child = spawn(launcher.command, launcher.args, {
      stdio: "ignore",
      detached: true,
      env: childEnv,
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
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(
        new Error(
          "Timed out waiting for the browser login (10 minutes). Run `converly login` again when you're ready."
        )
      );
    }, LOGIN_TIMEOUT_MS);

    server.on("request", (req, res) => {
      // Once we've resolved/rejected, ignore any further hits on the port.
      if (settled) {
        res.writeHead(409).end();
        return;
      }
      // A malformed request target makes `new URL` throw — inside this
      // event callback that would be an uncaught crash, not a clean error.
      let url;
      try {
        url = new URL(req.url, "http://127.0.0.1");
      } catch {
        res.writeHead(400).end();
        return;
      }
      // Only GET /callback with OUR state gets any further; state is
      // compared constant-time. Everything else (probes, favicons, other
      // apps on the port) gets a 404 and cannot cancel or complete login.
      if (
        req.method !== "GET" ||
        url.pathname !== "/callback" ||
        !safeEqual(url.searchParams.get("state") ?? "", expectedState)
      ) {
        res.writeHead(404).end();
        return;
      }
      const finish = (html, outcome) => {
        settled = true;
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
  const body = await readJsonCapped(res).catch(() => null);
  if (!res.ok || typeof body?.access_token !== "string" || !body.access_token.trim()) {
    const detail = body?.error_description ?? body?.error ?? `HTTP ${res.status}`;
    throw new Error(`Token request failed: ${detail}`);
  }
  // Validate the optional fields BEFORE they can be persisted — a
  // non-string refresh_token / scope would later be sent back to the
  // server or stored as junk, and a non-number expires_in would corrupt
  // the expiry math.
  if (
    body.refresh_token !== undefined &&
    body.refresh_token !== null &&
    typeof body.refresh_token !== "string"
  ) {
    throw new Error("Token response had a non-string refresh_token.");
  }
  if (body.scope !== undefined && typeof body.scope !== "string") {
    throw new Error("Token response had a non-string scope.");
  }
  if (
    body.expires_in !== undefined &&
    (typeof body.expires_in !== "number" ||
      !Number.isFinite(body.expires_in) ||
      body.expires_in < 0)
  ) {
    throw new Error("Token response had an invalid expires_in.");
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
    // Tag this login session. A refresh preserves the generation; a NEW
    // login (possibly a different account) gets a new one. In-flight
    // requests compare it before replaying so a concurrent login can't make
    // a write replay under a different account's token.
    creds.login_generation = b64url(crypto.randomBytes(8));
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

// One in-flight refresh per origin WITHIN this process. Concurrent 401s
// (parallel requests after expiry) collapse to a single refresh here; the
// cross-process refresh LOCK (withRefreshLock) handles other processes.
const refreshInFlight = new Map();

/**
 * Refresh the stored token for an origin. Returns the credentials to use
 * (freshly refreshed, or another process's if it beat us), or throws if
 * there's nothing to refresh / the server refuses.
 *
 * `opts.rejectedToken` is the access token that just got a 401; if, after
 * taking the cross-process lock, the stored access token is no longer that
 * value, another process already refreshed — we adopt its result instead
 * of refreshing again (which could trip refresh-token reuse revocation).
 */
export function refreshCredentials(origin, opts = {}) {
  const existing = refreshInFlight.get(origin);
  if (existing) return existing;

  const task = withRefreshLock(async () => {
    // Re-read AFTER acquiring the cross-process lock.
    const current = getStoredCredentials(origin);
    if (!current?.access_token) {
      throw new Error(`No login for ${origin} to refresh.`);
    }
    // Another process refreshed while we waited — use its token, don't
    // burn ours on a second (reuse-detectable) refresh.
    if (opts.rejectedToken && current.access_token !== opts.rejectedToken) {
      return current;
    }
    if (!current.refresh_token || !current.client_id) {
      throw new Error(`No refreshable login for ${origin}.`);
    }
    const usedRefreshToken = current.refresh_token;
    // The full credential this refresh is based on — the CAS requires ALL
    // of these to be unchanged at commit time (login_generation included,
    // so a concurrent login is caught even in the impossible case it kept
    // the same tokens).
    const expected = {
      access_token: current.access_token,
      refresh_token: usedRefreshToken,
      client_id: current.client_id,
      login_generation: current.login_generation ?? null,
    };
    const doc = await discover(origin);
    const tokens = await exchangeToken(doc.token_endpoint, {
      grant_type: "refresh_token",
      refresh_token: usedRefreshToken,
      client_id: current.client_id,
    });
    // Some servers rotate refresh tokens; keep the old one if none returned.
    if (!tokens.refresh_token) tokens.refresh_token = usedRefreshToken;
    const creds = credsFromTokens(current.client_id, tokens, current.scope);
    // A refresh stays within the SAME login session — carry the generation
    // forward EXACTLY, including its ABSENCE for a legacy credential. (Do
    // NOT mint a new one here: a normal legacy refresh would then differ
    // from the null start-generation and be wrongly rejected as a login
    // change. A real concurrent login stamps a non-null generation, which
    // the null-normalized comparison in http.js still catches.)
    creds.login_generation = current.login_generation;
    // Compare-and-swap commit: don't resurrect a credential a logout
    // cleared, and don't clobber a newer one a login/refresh just wrote.
    const result = commitRefreshedCredentials(origin, creds, expected);
    if (result.ok) return creds;
    if (result.current?.access_token) return result.current;
    throw new Error(`Login for ${origin} was cleared during refresh.`);
  }).finally(() => refreshInFlight.delete(origin));

  refreshInFlight.set(origin, task);
  return task;
}
