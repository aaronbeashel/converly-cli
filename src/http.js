/**
 * Thin HTTP client for the Converly /v1 API.
 *
 * - Adds the Bearer token and an idempotency key on POSTs. The key is
 *   generated ONCE per logical operation (not per attempt), so the
 *   internal refresh-retry after a 401 replays the same key and cannot
 *   double-create anything. Callers can pin a key across separate CLI
 *   invocations with --idempotency-key.
 * - Surfaces API errors as ApiError carrying the server's error body.
 * - On a 401 with stored OAuth credentials, refreshes the token once
 *   (single-flight per origin) and retries. A rejected CONVERLY_API_KEY
 *   is reported as exactly that — it is never silently substituted.
 * - Public catalogue endpoints are called WITHOUT credentials, so a
 *   stale token can't break an endpoint that needs no auth at all.
 * - Every request has a bounded timeout; nothing hangs forever.
 */

import crypto from "node:crypto";
import { createRequire } from "node:module";
import { resolveAuth, getStoredCredentials } from "./config.js";
import { refreshCredentials } from "./oauth.js";
import { readTextCapped, assertSafePath } from "./net.js";

const require = createRequire(import.meta.url);
const { version: VERSION } = require("../package.json");

const REQUEST_TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  constructor(status, body) {
    const message =
      body?.error?.message ?? body?.error_description ?? `HTTP ${status}`;
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

export class AuthMissingError extends Error {
  constructor(origin) {
    super(
      `Not logged in to ${origin}. Run \`converly login\` (or set CONVERLY_API_KEY).`
    );
    this.name = "AuthMissingError";
  }
}

// Set once per CLI invocation from --idempotency-key, so retries of the
// same logical operation across separate invocations can share a key.
let defaultIdempotencyKey = null;
export function setDefaultIdempotencyKey(key) {
  defaultIdempotencyKey = key || null;
}

function buildUrl(origin, apiPath, query) {
  if (typeof apiPath !== "string" || !apiPath.startsWith("/")) {
    throw new Error(`API path must start with "/": ${apiPath}`);
  }
  // Reject traversal in the RAW path BEFORE new URL() silently normalizes
  // it. `new URL()` collapses `..` AND decodes percent-encoded dots/slashes
  // when deciding path segments, so a caller that interpolated an
  // attacker-supplied id like `../flows/x` OR `%2e%2e/flows/x` (or its
  // double-encoded `%252e%252e`) would otherwise still land on /api/v1
  // (passing the namespace check below) but at a DIFFERENT resource. One
  // shared, recursive-decode guard (net.js) covers this and the raw `api`
  // command identically.
  const rawPath = apiPath.split(/[?#]/, 1)[0];
  assertSafePath(rawPath);
  const url = new URL(`${origin}/api/v1${apiPath}`);
  // Catch-all: no path may resolve off the origin or out of the /api/v1
  // namespace (e.g. a `..` segment the caller didn't sanitise, or a
  // sibling like /api/v1evil). Bearer tokens only ever go to the
  // endpoints we intend. Segment-exact: "/api/v1" itself or "/api/v1/…".
  const inNamespace =
    url.pathname === "/api/v1" || url.pathname.startsWith("/api/v1/");
  if (url.origin !== origin || !inNamespace) {
    throw new Error(`Refusing to call ${url.href} — outside ${origin}/api/v1.`);
  }
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url;
}

// Generous for the largest legitimate payload (an events list caps at
// 100 rows). A hostile endpoint (only reachable if the user pointed
// --api at it) can't exhaust memory past this.
const MAX_RESPONSE_BYTES = 25_000_000;

/**
 * Read a response body into a tagged envelope so "the body had a problem"
 * is never confusable with "the body legitimately contained this key".
 * kind: "json" (value is the parsed JSON or null for empty) |
 *       "oversize" | "unreadable" | "unparseable" (sample is a prefix).
 * Streams with a hard byte cap so an absent/lying Content-Length can't
 * exhaust memory.
 */
async function readBody(res) {
  const read = await readTextCapped(res, MAX_RESPONSE_BYTES);
  if (read.overLimit) return { kind: "oversize" };
  if (read.unreadable) return { kind: "unreadable" };
  const text = read.text;
  if (!text) return { kind: "json", value: null };
  try {
    return { kind: "json", value: JSON.parse(text) };
  } catch {
    return { kind: "unparseable", sample: text.slice(0, 300) };
  }
}

/**
 * Perform one /v1 request.
 *
 * opts: { body, query, idempotencyKey, public }
 * `public: true` marks a no-auth catalogue endpoint — no credential is
 * attached and no login is required.
 */
export async function apiRequest(origin, method, apiPath, opts = {}) {
  const auth = opts.public ? null : resolveAuth(origin);

  // The login session this request is bound to, read from the SAME snapshot
  // as the token (resolveAuth), so a concurrent LOGIN can't swap the
  // credential between two separate reads. If it changes mid-request we must
  // NOT replay under the new (possibly different-account) token.
  const startGeneration = auth?.generation ?? null;

  // One key per logical operation — shared by every attempt below.
  const idempotencyKey =
    method === "POST"
      ? (opts.idempotencyKey ?? defaultIdempotencyKey ?? crypto.randomUUID())
      : null;

  // Classify a failure that MIGHT be transient, and give method-appropriate
  // machine-readable advice:
  //   - POST auto-carries an idempotency key → retryable, a retry with the
  //     key can't double-create;
  //   - GET / DELETE are idempotent → retryable, a plain retry is safe;
  //   - PATCH is NOT generally idempotent → do NOT mark it retryable (a
  //     machine consumer must not blindly repeat it); flag the uncertainty
  //     so the caller checks current state first.
  const CHECK_STATE_HINT =
    "The result is uncertain — check the current state before retrying.";
  const ambiguous = (err) => {
    if (method === "POST") {
      err.retryable = true;
      err.idempotencyKey = idempotencyKey;
      err.message = `${err.message} Safe to retry with --idempotency-key ${idempotencyKey}.`;
    } else if (method === "GET" || method === "DELETE") {
      err.retryable = true;
      err.message = `${err.message} Safe to retry.`;
    } else {
      err.outcomeUncertain = true;
      err.retryHint = CHECK_STATE_HINT;
      err.message = `${err.message} ${CHECK_STATE_HINT}`;
    }
    return err;
  };

  // Build the URL ONCE, up front and OUTSIDE the transport try/catch. A
  // bad path (off-origin, `..`, outside /api/v1) is a permanent input
  // error — it must propagate as-is, never be caught below and mislabelled
  // a transient/retryable transport failure that a watcher would retry.
  const url = buildUrl(origin, apiPath, opts.query);

  // GET/HEAD can't carry a body. Fetch rejects locally if we try, and that
  // local rejection would be caught below and mislabelled retryable. It's a
  // permanent input error — surface it as such.
  if ((method === "GET" || method === "HEAD") && opts.body !== undefined) {
    throw new Error(`${method} requests cannot include a request body.`);
  }

  const attempt = async (token) => {
    const headers = { "User-Agent": `converly-cli/${VERSION}` };
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    let res;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: payload,
        // A /v1 endpoint never legitimately 3xx-redirects. Refusing to
        // follow one stops a hostile/misconfigured origin from bouncing
        // the Bearer token (or a POST body) to a URL we didn't choose.
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (cause) {
      if (cause?.name === "TimeoutError" || cause?.name === "AbortError") {
        throw ambiguous(
          new Error(
            `Request to ${origin} timed out after ${REQUEST_TIMEOUT_MS / 1000}s.`
          )
        );
      }
      // Any other transport failure (connection reset, DNS, TLS) is
      // ambiguous — the write may or may not have landed.
      const err = ambiguous(
        new Error(`Request to ${origin} failed: ${cause?.message ?? cause}.`)
      );
      err.cause = cause;
      throw err;
    }
    return { res, body: await readBody(res) };
  };

  let { res, body } = await attempt(auth?.token ?? null);
  // The parsed JSON (or null) for building error bodies — never the
  // oversize/unparseable envelope, which isn't a real payload.
  const errorBody = () => (body.kind === "json" ? body.value : null);

  if (res.status === 401) {
    if (!auth) throw new AuthMissingError(origin);

    if (auth.source === "env") {
      // Never mask a bad environment key by falling back to another
      // credential — say exactly what was rejected and how to fix it.
      const err = new ApiError(401, errorBody());
      err.message = `CONVERLY_API_KEY was rejected by ${origin}. Unset it (to use \`converly login\`) or replace it with a valid key.`;
      throw err;
    }

    // Stored OAuth credential: refresh once (single-flight) and retry
    // with the SAME idempotency key.
    const stored = getStoredCredentials(origin);
    if (stored?.refresh_token) {
      let refreshed = null;
      let refreshErr = null;
      try {
        // Pass the rejected token so a concurrent refresh in another
        // process can be adopted instead of racing a second refresh.
        refreshed = await refreshCredentials(origin, {
          rejectedToken: auth.token,
        });
      } catch (e) {
        refreshErr = e;
      }
      if (refreshed?.access_token) {
        // Only replay under the SAME login. Compare UNCONDITIONALLY (both
        // sides null-normalized): a null start-generation is a legacy
        // credential, and a concurrent login (which stamps a non-null
        // generation) must still be caught, not waved through. A mismatch
        // means a concurrent login (possibly a different account) replaced
        // the credential — replaying the write under it would be wrong.
        if ((refreshed.login_generation ?? null) !== startGeneration) {
          const err = new ApiError(401, errorBody());
          err.code = "credentials_changed";
          err.message = `The login for ${origin} changed while this request was in flight (a different login is now active). Re-run the command.`;
          throw err;
        }
        ({ res, body } = await attempt(refreshed.access_token));
      } else if (refreshErr?.code === "lock_timeout") {
        // A stuck lock is actionable on its own — surface it rather than
        // masking it as a generic "login expired".
        throw refreshErr;
      }
      // Otherwise fall through to the reauth error below.
    }
    if (res.status === 401) {
      const err = new ApiError(401, errorBody());
      err.message = `Your login for ${origin} has expired and could not be refreshed. Run \`converly login\` again.`;
      err.code = "reauth_required";
      throw err;
    }
  }

  // 429 is a DEFINITE rejection (the request did not apply — it was rate
  // limited before processing), so it's safe to retry for ANY method. Mark
  // it retryable and, for a POST, carry the pinned key so the retry reuses
  // it. Surface the server's back-off timing if present.
  if (res.status === 429) {
    const err = new ApiError(429, errorBody());
    err.retryable = true;
    if (idempotencyKey) err.idempotencyKey = idempotencyKey;
    const retryAfter =
      res.headers.get("retry-after") ??
      (errorBody() && typeof errorBody() === "object"
        ? errorBody().retry_after
        : undefined);
    if (retryAfter !== undefined && retryAfter !== null) {
      err.retryAfter = retryAfter;
    }
    throw err;
  }

  // A 4xx is a DEFINITE rejection — the write did not happen — so classify
  // it from the STATUS before any body-read failure. Otherwise an
  // unreadable/oversize 4xx body would be mislabelled retryable, and a
  // watcher like `handoffs wait` would retry a permanent error (and keep
  // re-downloading a huge body) until its deadline. (401 already handled.)
  if (!res.ok && res.status < 500) {
    throw new ApiError(res.status, errorBody());
  }

  // From here the status is 2xx or 5xx. A body we couldn't read/size IS
  // genuinely ambiguous for a write — the headers arrived but we can't
  // confirm the outcome.
  if (body.kind === "oversize") {
    throw ambiguous(
      new Error(
        `Response from ${origin} exceeded ${MAX_RESPONSE_BYTES / 1_000_000}MB and was refused (HTTP ${res.status}).`
      )
    );
  }
  if (body.kind === "unreadable") {
    throw ambiguous(
      new Error(
        `Could not read the response body from ${origin} (HTTP ${res.status}).`
      )
    );
  }

  if (!res.ok) {
    // 5xx — ambiguous: the write may have landed before the server faulted.
    const err = ambiguous(new ApiError(res.status, errorBody()));
    throw err;
  }

  // A 2xx whose body wasn't JSON is not a success we can trust — a proxy
  // error page or captive portal can return 200 with HTML. Treat it as a
  // failure rather than handing back something bogus.
  if (body.kind === "unparseable") {
    throw ambiguous(
      new Error(
        `Response from ${origin} was not valid JSON (HTTP ${res.status}). ` +
          `First bytes: ${JSON.stringify(body.sample)}`
      )
    );
  }

  return body.value;
}
