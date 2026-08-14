/**
 * HTTP client for the Google Tag Manager API v2.
 *
 * Built on the same primitives as src/http.js (bounded timeout, capped
 * streaming body read, redirect:"error", explicit error classification)
 * rather than a Google SDK, so the whole CLI keeps one transport style and
 * stays dependency-free. Three GTM-specific behaviours it adds:
 *
 * 1. PACING. The API allows 0.25 QPS per project — 25 requests per 100
 *    seconds. That is a sliding window, not a fixed gap, so a short burst
 *    is legal and a naive one-request-per-4-seconds sleep would be four
 *    times slower than necessary. The limiter below models the real window.
 *
 * 2. PARTIAL RESPONSES. Under load the API returns malformed or truncated
 *    payloads with a 200 rather than a clean error. Every response is
 *    therefore checked for object-ness before use, and a collection that
 *    comes back as a non-array is treated as a failure, never silently
 *    coerced to "empty" — reporting "no tags" for a container that has
 *    tags is the single most damaging thing this tool could do.
 *
 * 3. QUOTA IS A 403, NOT A 429. Google returns 403 with a rateLimitExceeded
 *    reason when the per-project quota is spent. A plain 403 (genuinely no
 *    permission) must fail immediately, so the two are told apart by the
 *    error body's reason before deciding whether to retry.
 */

import { readTextCapped } from "./net.js";
import { refreshGoogleCredentials, getGoogleAccessToken } from "./gtm-auth.js";
import { refusedError, authError } from "./gtm-errors.js";

const API_ROOT = "https://tagmanager.googleapis.com/tagmanager/v2";
const REQUEST_TIMEOUT_MS = 30_000;
// GTM payloads are small; a container version is the largest thing here.
const MAX_RESPONSE_BYTES = 25_000_000;

// --- Rate limiting -------------------------------------------------------
//
// The documented quota is 25 requests per 100 seconds per project. Timestamps
// of recent requests are kept and a new request waits only if the window is
// genuinely full. A margin is left so a concurrently-running second CLI
// process does not immediately tip the shared project quota over.
const WINDOW_MS = 100_000;
const WINDOW_LIMIT = 20;

const recentRequests = [];

function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || String(raw).trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function throttle() {
  const limit = envInt("CONVERLY_GTM_WINDOW_LIMIT", WINDOW_LIMIT);
  for (;;) {
    const now = Date.now();
    while (recentRequests.length > 0 && now - recentRequests[0] >= WINDOW_MS) {
      recentRequests.shift();
    }
    if (recentRequests.length < limit) {
      recentRequests.push(now);
      return;
    }
    // Wait exactly until the oldest request leaves the window.
    await sleep(WINDOW_MS - (now - recentRequests[0]) + 50);
  }
}

/** Test seam: forget the pacing history between unit tests. */
export function resetRateLimiter() {
  recentRequests.length = 0;
}

// --- Error classification ------------------------------------------------

/**
 * Is this 403 a spent quota rather than a genuine permission problem?
 * Google signals quota through the error reason, not the status code.
 */
export function isQuotaError(status, body) {
  if (status !== 403 && status !== 429) return false;
  if (status === 429) return true;
  const errors = body?.error?.errors;
  const reasons = Array.isArray(errors)
    ? errors.map((e) => String(e?.reason ?? "").toLowerCase())
    : [];
  if (
    reasons.some((r) =>
      ["ratelimitexceeded", "userratelimitexceeded", "quotaexceeded"].includes(r)
    )
  ) {
    return true;
  }
  const message = String(body?.error?.message ?? "").toLowerCase();
  return /quota|rate limit/.test(message);
}

function errorDetail(body, status) {
  const message = body?.error?.message;
  if (typeof message === "string" && message.trim()) return message;
  return `HTTP ${status}`;
}

// --- Body reading --------------------------------------------------------

async function readBody(res) {
  const read = await readTextCapped(res, MAX_RESPONSE_BYTES);
  if (read.overLimit) return { kind: "oversize" };
  if (read.unreadable) return { kind: "unreadable" };
  const text = read.text;
  if (!text) return { kind: "json", value: null };
  try {
    return { kind: "json", value: JSON.parse(text) };
  } catch {
    // A truncated payload lands here — JSON.parse fails on the half object.
    return { kind: "unparseable", sample: text.slice(0, 300) };
  }
}

// --- Request -------------------------------------------------------------

const MAX_ATTEMPTS = 4;

/**
 * One GTM API call, paced, retried and validated.
 * `path` is relative to the API root and must already be escaped.
 */
export async function gtmRequest(method, path, { body, query } = {}) {
  const url = new URL(`${API_ROOT}${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  // Belt and braces: a caller that interpolated an unvalidated id must not
  // be able to steer the request off the API root.
  if (!url.href.startsWith(`${API_ROOT}/`)) {
    throw new Error(`Refusing to call ${url.href}, which is outside ${API_ROOT}.`);
  }

  let refreshedOnce = false;
  let lastQuotaDetail = null;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    await throttle();
    const token = await getGoogleAccessToken();

    let res;
    try {
      res = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          ...(body !== undefined && { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (cause) {
      // A transport failure on a read is safe to retry; on a write the
      // outcome is genuinely unknown, so only reads are retried here.
      if (attempt < MAX_ATTEMPTS && method === "GET") {
        await sleep(backoffMs(attempt));
        continue;
      }
      const err = new Error(
        `Request to the Tag Manager API failed: ${cause?.message ?? cause}.`
      );
      err.cause = cause;
      if (method !== "GET") {
        err.outcomeUncertain = true;
        err.retryHint =
          "The result is uncertain. List the workspace before retrying, in case the write landed.";
      }
      throw err;
    }

    const parsed = await readBody(res);

    // A 401 means the token was rejected. Refresh once, then retry.
    if (res.status === 401 && !refreshedOnce) {
      refreshedOnce = true;
      try {
        await refreshGoogleCredentials({ rejectedToken: token });
        continue;
      } catch {
        // Fall through to the normal error path below.
      }
    }

    if (!res.ok) {
      const errorBody = parsed.kind === "json" ? parsed.value : null;

      // A 401 that survived the refresh above means the login is genuinely
      // dead. Report it as an auth failure (exit 3) so the caller is told to
      // log in again, rather than as a generic API error it might retry.
      if (res.status === 401) {
        throw authError(
          `Google rejected the credential: ${errorDetail(errorBody, 401)}. ` +
            `The login may have been revoked. Run \`converly gtm login\` again.`
        );
      }

      if (isQuotaError(res.status, errorBody)) {
        lastQuotaDetail = errorDetail(errorBody, res.status);
        if (attempt < MAX_ATTEMPTS) {
          await sleep(backoffMs(attempt));
          continue;
        }
        throw refusedError(
          "quota_exhausted",
          `The Tag Manager API quota is exhausted (${lastQuotaDetail}). ` +
            `The API allows 25 requests per 100 seconds per project and returns ` +
            `403 (not 429) when that is spent. Wait a couple of minutes and retry; ` +
            `no change was made.`,
          { retryable: true, status: res.status }
        );
      }

      if (res.status === 403) {
        throw refusedError(
          "permission_denied",
          `Google refused the request: ${errorDetail(errorBody, 403)}. ` +
            `The signed-in Google account may not have access to this ` +
            `account/container, or the needed scope was not granted at login ` +
            `(check \`converly gtm status\`).`,
          { status: 403 }
        );
      }

      if (res.status === 404) {
        const err = new Error(
          `Not found: ${errorDetail(errorBody, 404)}. ` +
            `Check the ids. Workspace IDs in particular are NOT predictable and are ` +
            `rarely 1, so list workspaces before using one.`
        );
        err.code = "not_found";
        err.status = 404;
        throw err;
      }

      // 5xx is worth one more go on a read.
      if (res.status >= 500 && attempt < MAX_ATTEMPTS && method === "GET") {
        await sleep(backoffMs(attempt));
        continue;
      }

      const err = new Error(
        `Tag Manager API error (HTTP ${res.status}): ${errorDetail(errorBody, res.status)}`
      );
      err.code = "gtm_api_error";
      err.status = res.status;
      throw err;
    }

    // --- 2xx, but not necessarily usable ---
    if (parsed.kind === "oversize" || parsed.kind === "unreadable") {
      if (attempt < MAX_ATTEMPTS && method === "GET") {
        await sleep(backoffMs(attempt));
        continue;
      }
      throw new Error(
        `Could not read the Tag Manager API response (HTTP ${res.status}).`
      );
    }

    // The documented failure mode under load: a 200 carrying a truncated or
    // malformed payload. Retry it as the transient fault it is; never hand
    // a caller a half-parsed shape.
    if (parsed.kind === "unparseable") {
      if (attempt < MAX_ATTEMPTS && method === "GET") {
        await sleep(backoffMs(attempt));
        continue;
      }
      throw new Error(
        `The Tag Manager API returned a malformed response (HTTP ${res.status}). ` +
          `This is what quota pressure looks like on this API. ` +
          `First bytes: ${JSON.stringify(parsed.sample)}`
      );
    }

    const value = parsed.value;
    // An empty body is legitimate for DELETE and for a workspace with
    // nothing in it; callers normalise it.
    if (value === null) return {};

    if (typeof value !== "object" || Array.isArray(value)) {
      if (attempt < MAX_ATTEMPTS && method === "GET") {
        await sleep(backoffMs(attempt));
        continue;
      }
      throw new Error(
        `The Tag Manager API returned ${Array.isArray(value) ? "an array" : typeof value} ` +
          `where an object was expected (HTTP ${res.status}). Treating this as a ` +
          `partial response rather than trusting it.`
      );
    }

    return value;
  }

  // Reached only when the last attempt ended in a `continue` (for example a
  // 401 refresh on the final attempt). Report what actually happened rather
  // than blaming quota by default.
  if (lastQuotaDetail) {
    throw refusedError(
      "quota_exhausted",
      `The Tag Manager API quota is exhausted (${lastQuotaDetail}). ` +
        `Gave up after ${MAX_ATTEMPTS} attempts. Wait a couple of minutes and retry.`,
      { retryable: true }
    );
  }
  const err = new Error(
    `The Tag Manager API did not return a usable response after ${MAX_ATTEMPTS} attempts.`
  );
  err.code = "gtm_api_error";
  throw err;
}

function backoffMs(attempt) {
  // The unit is configurable so the retry paths can be exercised by tests
  // without waiting through a real 14-second backoff ladder, and so an
  // operator sharing a project quota can choose to be more patient.
  const unit = envInt("CONVERLY_GTM_BACKOFF_MS", 1000);
  const base = Math.min(2 ** attempt * unit, 32_000);
  // Jitter so two CLI processes sharing a project quota don't resynchronise.
  return base + Math.floor(Math.random() * Math.min(unit / 2, 500));
}

/**
 * Pull a collection out of a GTM list response.
 *
 * The raw REST API returns `{tag: [...]}`; Google's own client libraries wrap
 * the same payload as `{data: {tag: [...]}}`, and a couple of endpoints
 * (notably the live-version call) use yet another wrapper. Rather than
 * hard-coding which shape each endpoint uses, accept either and — crucially —
 * distinguish "the key is absent" (an empty collection, which is normal for a
 * fresh workspace) from "the key is present but not an array" (a partial
 * response, which must never be reported as empty).
 */
export function unwrapList(body, key) {
  const source =
    body && typeof body.data === "object" && body.data !== null && !Array.isArray(body.data)
      ? body.data
      : body;
  const value = source?.[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new Error(
      `The Tag Manager API returned "${key}" as ${typeof value} rather than a list. ` +
        `Refusing to report this as empty. Retry in a moment.`
    );
  }
  return value;
}

/**
 * Pull a single object out of a response that may or may not be wrapped.
 * `keys` are tried in order, then the body itself is used if it already
 * looks like the resource.
 */
export function unwrapObject(body, keys, marker) {
  const source =
    body && typeof body.data === "object" && body.data !== null && !Array.isArray(body.data)
      ? body.data
      : body;
  for (const key of keys) {
    const value = source?.[key];
    if (value && typeof value === "object" && !Array.isArray(value)) return value;
  }
  // Unwrapped already? Only accept it if the expected marker field is there,
  // so a stray error envelope can't be mistaken for a resource.
  if (source && typeof source === "object" && (!marker || marker in source)) {
    return source;
  }
  return null;
}
