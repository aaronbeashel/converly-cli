/**
 * Google OAuth for the `converly gtm` commands.
 *
 * Same RFC 8252 native-app shape as src/oauth.js (loopback listener on
 * 127.0.0.1, PKCE, state, listener attached BEFORE the browser opens), but
 * pointed at Google instead of Converly, and using a DESKTOP APP OAuth
 * client rather than dynamic registration — Google does not support DCR.
 *
 * What is NOT here, on purpose:
 *   - No client secret is embedded, and none is ever written to the repo.
 *     Google still issues a "client secret" for Desktop app clients; it is
 *     not a real secret (it ships inside every installed copy, which is why
 *     RFC 8252 classes these as PUBLIC clients and why PKCE is mandatory
 *     here). If Google's token endpoint demands it for this client, supply
 *     it through CONVERLY_GTM_CLIENT_SECRET — see README.
 *   - No scope beyond the four in GTM_SCOPES. In particular there is no
 *     email/profile scope, so `gtm status` can report the Google user ID
 *     but NOT the email address. That is a deliberate trade: an email scope
 *     would widen the consent screen for a cosmetic gain.
 *   - tagmanager.delete.containers is deliberately absent. Nothing here
 *     deletes a container, it is the scope a verification reviewer is most
 *     likely to challenge, and it puts "delete your containers" on the
 *     consent screen every user reads.
 */

import crypto from "node:crypto";
import http from "node:http";
import {
  getGoogleCredentials,
  setGoogleCredentials,
  commitRefreshedGoogleCredentials,
  withRefreshLock,
} from "./config.js";
import { makePkce, openBrowser, escapeHtml } from "./oauth.js";
import { readTextCapped } from "./net.js";
import { usageError, authError } from "./gtm-errors.js";

/**
 * Exactly the scopes the read + write + publish commands need, and no more.
 * Adding one here widens the consent screen for every user, so each must
 * earn its place:
 *   manage.accounts        — list accounts and containers
 *   edit.containers        — read/write tags, triggers, variables, workspaces
 *   edit.containerversions — create and read container versions
 *   publish                — push a version live (gated, see commands/gtm.js)
 */
export const GTM_SCOPES = [
  "https://www.googleapis.com/auth/tagmanager.manage.accounts",
  "https://www.googleapis.com/auth/tagmanager.edit.containers",
  "https://www.googleapis.com/auth/tagmanager.edit.containerversions",
  "https://www.googleapis.com/auth/tagmanager.publish",
];

const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke";
const TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo";

/**
 * The Desktop app OAuth client ID.
 *
 * A client ID is an IDENTIFIER, not a credential — it is safe to ship in
 * source, which is why this is a plain constant rather than an env var.
 * It is empty because this repo's owner must create the client first (see
 * README "Google Cloud Console setup"); paste the ID here and it becomes
 * the default for every user. CONVERLY_GTM_CLIENT_ID overrides it, which
 * is how you test a second client without editing source.
 */
const DEFAULT_CLIENT_ID = "";

export function resolveClientId(env = process.env) {
  const fromEnv = env.CONVERLY_GTM_CLIENT_ID;
  const clientId = (fromEnv ?? DEFAULT_CLIENT_ID).trim();
  if (!clientId) {
    throw usageError(
      "no_oauth_client",
      "No Google OAuth client is configured. Create a Desktop app OAuth client " +
        "in Google Cloud Console (APIs & Services > Credentials > Create " +
        "credentials > OAuth client ID > Application type: Desktop app), enable " +
        "the Tag Manager API on the same project, then set CONVERLY_GTM_CLIENT_ID " +
        "to the client ID. See the README section \"Google Cloud Console setup\"."
    );
  }
  return clientId;
}

/**
 * Google's Desktop app clients are issued a client secret that is not
 * secret in any meaningful sense, but the token endpoint may still require
 * it. Read it from the environment; never from source, and never from a
 * file in the repo.
 */
function resolveClientSecret(env = process.env) {
  const secret = env.CONVERLY_GTM_CLIENT_SECRET;
  return typeof secret === "string" && secret.trim() ? secret.trim() : null;
}

const LOGIN_TIMEOUT_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 30_000;
const OAUTH_MAX_BYTES = 1_000_000;

function fetchWithTimeout(url, init = {}) {
  return fetch(url, {
    ...init,
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    // Every call here carries a credential (auth code, PKCE verifier or
    // refresh token). A 307/308 forwards the POST body to the redirect
    // target — Node strips Authorization but NOT the body. Google's token
    // endpoint never legitimately redirects, so refuse.
    redirect: "error",
  });
}

async function readJsonCapped(res) {
  const read = await readTextCapped(res, OAUTH_MAX_BYTES);
  if (read.overLimit) throw new Error("Response too large.");
  if (read.unreadable) throw new Error("Could not read the response.");
  if (!read.text) return null;
  try {
    return JSON.parse(read.text);
  } catch {
    throw new Error("Response was not valid JSON.");
  }
}

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

function page(title, body) {
  return `<!doctype html><html><head><title>Converly CLI</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#0b0d12;color:#e7e9ee}
main{text-align:center;max-width:28rem;padding:0 1rem}h1{font-size:1.4rem}p{color:#9aa1ad}</style></head>
<body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p></main></body></html>`;
}

// The token exchange has not happened when this renders, so it must not
// claim success — the terminal is the source of truth.
const RETURN_PAGE = page(
  "Almost done",
  "Return to the terminal to finish connecting Google Tag Manager. You can close this tab."
);

/**
 * Wait for the one redirect carrying our state. Anything else (probes,
 * favicons, another app on the port) gets a 404 and can neither cancel nor
 * complete the login.
 */
function waitForCallback(server, expectedState) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(
        new Error(
          "Timed out waiting for the Google login (10 minutes). Run `converly gtm login` again when you're ready."
        )
      );
    }, LOGIN_TIMEOUT_MS);

    server.on("request", (req, res) => {
      if (settled) {
        res.writeHead(409).end();
        return;
      }
      let url;
      try {
        url = new URL(req.url, "http://127.0.0.1");
      } catch {
        res.writeHead(400).end();
        return;
      }
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
            : `Google returned: ${err}.`;
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

/**
 * Google reports OAuth failures as {error, error_description}. Surface both
 * — "invalid_grant" alone sends people hunting, "invalid_grant: Token has
 * been expired or revoked" tells them to log in again.
 */
function tokenErrorDetail(body, status) {
  if (!body || typeof body !== "object") return `HTTP ${status}`;
  const code = typeof body.error === "string" ? body.error : null;
  const description =
    typeof body.error_description === "string" ? body.error_description : null;
  if (code && description) return `${code}: ${description}`;
  return code ?? description ?? `HTTP ${status}`;
}

async function exchangeToken(params) {
  const secret = resolveClientSecret();
  const form = { ...params };
  if (secret) form.client_secret = secret;

  const res = await fetchWithTimeout(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  const body = await readJsonCapped(res).catch(() => null);
  if (!res.ok || typeof body?.access_token !== "string" || !body.access_token.trim()) {
    const detail = tokenErrorDetail(body, res.status);
    // The single most common first-run failure is a Web application client
    // used where a Desktop one is required — name it rather than leaving
    // the operator to decode Google's wording.
    const hint =
      /client_secret|invalid_client/i.test(detail) && !secret
        ? " If this OAuth client requires a secret, set CONVERLY_GTM_CLIENT_SECRET. Confirm the client's Application type is \"Desktop app\", not \"Web application\"."
        : "";
    throw new Error(`Google token request failed: ${detail}.${hint}`);
  }
  // Validate optional fields BEFORE they can be persisted — a non-string
  // refresh_token would be sent back to Google as junk, and a bad
  // expires_in would corrupt the expiry maths.
  if (
    body.refresh_token !== undefined &&
    body.refresh_token !== null &&
    typeof body.refresh_token !== "string"
  ) {
    throw new Error("Google token response had a non-string refresh_token.");
  }
  if (body.scope !== undefined && typeof body.scope !== "string") {
    throw new Error("Google token response had a non-string scope.");
  }
  if (
    body.expires_in !== undefined &&
    (typeof body.expires_in !== "number" ||
      !Number.isFinite(body.expires_in) ||
      body.expires_in < 0)
  ) {
    throw new Error("Google token response had an invalid expires_in.");
  }
  return body;
}

function credsFromTokens(clientId, tokens, previousScope, previousRefresh) {
  return {
    access_token: tokens.access_token,
    // Google omits refresh_token on a refresh response — an omission means
    // "unchanged", not "revoked". Dropping it here would silently downgrade
    // the login to single-use.
    refresh_token: tokens.refresh_token ?? previousRefresh ?? null,
    expires_at:
      typeof tokens.expires_in === "number"
        ? Date.now() + tokens.expires_in * 1000
        : null,
    // RFC 6749 §6: an omitted scope on refresh means unchanged.
    scope: tokens.scope ?? previousScope ?? null,
    client_id: clientId,
    obtained_at: new Date().toISOString(),
  };
}

/**
 * Interactive Google login. progress() receives human-facing lines that
 * callers send to stderr, so stdout stays a single JSON document.
 */
export async function googleLoginFlow({ noOpen = false, progress = () => {} } = {}) {
  const clientId = resolveClientId();

  const server = http.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  try {
    const { port } = server.address();
    // Google permits any loopback port for Desktop app clients, so this
    // does NOT need registering as a redirect URI in Cloud Console.
    const redirectUri = `http://127.0.0.1:${port}/callback`;

    const { verifier, challenge } = makePkce();
    const state = b64url(crypto.randomBytes(16));

    const authorizeUrl = new URL(AUTH_ENDPOINT);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("scope", GTM_SCOPES.join(" "));
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");
    // Without access_type=offline Google returns no refresh token, and the
    // login silently dies an hour later. prompt=consent forces a refresh
    // token even on a repeat authorization, where Google would otherwise
    // omit it because the user already consented once.
    authorizeUrl.searchParams.set("access_type", "offline");
    authorizeUrl.searchParams.set("prompt", "consent");

    // Listener first, browser second — a fast redirect can't be missed.
    const callback = waitForCallback(server, state);

    progress(
      "Log in to Google using the browser on THIS machine (the login hands its result back to the CLI here)."
    );
    progress(`If a browser doesn't open, visit:\n\n  ${authorizeUrl}\n`);
    if (!noOpen) openBrowser(authorizeUrl.toString());

    const { code } = await callback;
    progress("Exchanging the authorization code for credentials...");

    const tokens = await exchangeToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    const creds = credsFromTokens(clientId, tokens, GTM_SCOPES.join(" "), null);
    setGoogleCredentials(creds);

    // A login with no refresh token expires in about an hour and then fails
    // in the middle of some later command. Say so now, while the person is
    // still here to act on it.
    const granted = (creds.scope ?? "").split(/\s+/).filter(Boolean);
    const missing = GTM_SCOPES.filter((s) => !granted.includes(s));
    return {
      scope: creds.scope,
      expires_at: creds.expires_at,
      has_refresh_token: Boolean(creds.refresh_token),
      ...(missing.length > 0 && { missing_scopes: missing }),
      ...(missing.length > 0 && {
        warning:
          "Some requested scopes were not granted. Commands needing them will fail with permission_denied. Re-run `converly gtm login` and approve every checkbox.",
      }),
      ...(!creds.refresh_token && {
        warning_no_refresh_token:
          "Google did not return a refresh token, so this login expires in about an hour. Re-run `converly gtm login` if commands start failing.",
      }),
    };
  } finally {
    server.close();
  }
}

/** Best-effort revoke at Google, then clear the local credential. */
export async function revokeGoogleToken(token) {
  if (!token) return false;
  try {
    const res = await fetchWithTimeout(REVOKE_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token }).toString(),
    });
    return res.ok;
  } catch {
    // Revocation is best effort — the local credential is cleared either
    // way, so a network failure must not leave the user still logged in.
    return false;
  }
}

/**
 * Ask Google what a token actually is. Used by `gtm status` to report the
 * GRANTED scopes (a user can untick one on the consent screen, and the
 * resulting 403 much later is baffling) and a stable account identifier.
 *
 * POST, not GET: the access token goes in the request body rather than a
 * query string, so it can't be captured by proxy or server logs.
 */
export async function tokenInfo(accessToken) {
  const res = await fetchWithTimeout(TOKENINFO_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ access_token: accessToken }).toString(),
  });
  if (!res.ok) return null;
  const body = await readJsonCapped(res).catch(() => null);
  return body && typeof body === "object" && !Array.isArray(body) ? body : null;
}

// One in-flight refresh within this process; the cross-process refresh lock
// handles other processes.
let refreshInFlight = null;

/** Refresh the stored Google token. Mirrors oauth.js refreshCredentials. */
export function refreshGoogleCredentials(opts = {}) {
  if (refreshInFlight) return refreshInFlight;

  const task = withRefreshLock(async () => {
    // Re-read AFTER taking the cross-process lock.
    const current = getGoogleCredentials();
    if (!current?.access_token) {
      throw authError("Not connected to Google. Run `converly gtm login`.");
    }
    // Another process refreshed while we waited — adopt its token rather
    // than burning ours on a second refresh.
    if (opts.rejectedToken && current.access_token !== opts.rejectedToken) {
      return current;
    }
    if (!current.refresh_token || !current.client_id) {
      throw authError(
        "The Google login has expired and has no refresh token. Run `converly gtm login` again."
      );
    }
    const expected = {
      access_token: current.access_token,
      refresh_token: current.refresh_token,
    };
    const tokens = await exchangeToken({
      grant_type: "refresh_token",
      refresh_token: current.refresh_token,
      client_id: current.client_id,
    });
    const creds = credsFromTokens(
      current.client_id,
      tokens,
      current.scope,
      current.refresh_token
    );
    const result = commitRefreshedGoogleCredentials(creds, expected);
    if (result.ok) return creds;
    if (result.current?.access_token) return result.current;
    throw authError("The Google login was cleared during refresh.");
  }).finally(() => {
    refreshInFlight = null;
  });

  refreshInFlight = task;
  return task;
}

/** Treat a token expiring within this window as already expired. */
const EXPIRY_SKEW_MS = 60_000;

/**
 * The access token to use for a GTM call, refreshing proactively when it is
 * expired or about to be. Throws an auth error (exit 3) when there is no
 * usable login, so an agent can tell "log in first" apart from every other
 * failure.
 */
export async function getGoogleAccessToken() {
  const creds = getGoogleCredentials();
  if (!creds?.access_token) {
    throw authError(
      "Not connected to Google Tag Manager. Run `converly gtm login` first."
    );
  }
  const expired =
    typeof creds.expires_at === "number" &&
    creds.expires_at - EXPIRY_SKEW_MS <= Date.now();
  if (!expired) return creds.access_token;
  if (!creds.refresh_token) {
    throw authError(
      "The Google login has expired and cannot be refreshed. Run `converly gtm login` again."
    );
  }
  const refreshed = await refreshGoogleCredentials({
    rejectedToken: creds.access_token,
  });
  return refreshed.access_token;
}
