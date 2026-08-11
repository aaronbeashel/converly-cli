/**
 * Destination commands: catalogue, connection state, connect (via a
 * Converly-hosted handoff URL a human opens), handoff polling, and the
 * conversion-action picker.
 *
 * Deliberately absent: paste-token connect. Ad platform credentials
 * should be entered by a human in the Converly-hosted connect popup
 * (the handoff URL), never passed through an agent or a shell history.
 */

import { ApiError, apiRequest } from "../http.js";
import { assertIdSegment } from "./ids.js";

/** `google-ads` → `dest_google-ads`; accepts either form. */
function destId(value, commandHint) {
  if (!value) {
    throw new Error(
      `Missing destination type. ${commandHint} (run \`converly destinations types\` for the list).`
    );
  }
  // A destination type is a single segment, interpolated into the path.
  assertIdSegment(value, "destination type");
  return value.startsWith("dest_") ? value : `dest_${value}`;
}

export async function list({ origin }) {
  return apiRequest(origin, "GET", "/destinations");
}

export async function get({ args, origin }) {
  return apiRequest(
    origin,
    "GET",
    `/destinations/${destId(args[0], "Usage: converly destinations get <type>")}`
  );
}

export async function types({ origin }) {
  return apiRequest(origin, "GET", "/destination-types", { public: true });
}

export async function connect({ args, flags, origin }) {
  if (!args[0]) {
    throw new Error(
      "Missing destination type. Usage: converly destinations connect <type> --site <site_id>."
    );
  }
  if (!flags.site) {
    throw new Error(
      "Missing --site. Pass the site id (from `converly sites list`) this connection is for."
    );
  }

  // Browser-side pixel destinations have no connect step at all — catch
  // the mistake here instead of sending a doomed handoff request.
  const catalogue = await apiRequest(origin, "GET", "/destination-types", {
    public: true,
  });
  const entry = (catalogue?.data ?? []).find((d) => d.type === args[0]);
  if (entry && (entry.connection_types ?? []).length === 0) {
    throw new Error(
      `${entry.display_label ?? args[0]} needs no connection — it fires browser side via the platform's own pixel. Skip straight to creating the flow.`
    );
  }

  const handoff = await apiRequest(origin, "POST", "/handoffs", {
    body: {
      purpose: "connect_destination",
      destination_type: args[0],
      site_id: flags.site,
      ...(flags["return-url"] && { return_url: flags["return-url"] }),
    },
  });
  return {
    ...handoff,
    next_step:
      "A human must open `url` in a browser and finish connecting the ad platform. " +
      "Then run `converly handoffs wait " +
      handoff.id +
      "` to confirm it completed.",
  };
}

/**
 * Catch the classic id mix-up BEFORE the request: the handoff's browser
 * URL ends in a raw UUID, but the API's id is the prefixed hdf_… form
 * returned at creation. An agent that lost the create output and lifted
 * the id from the URL gets told exactly what went wrong (round-2
 * role-play finding) instead of a bare not-found.
 */
function guardHandoffId(id, usage) {
  if (!id) throw new Error(`Usage: ${usage}`);
  if (/^https?:\/\//i.test(id) || /^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(id)) {
    throw new Error(
      "That looks like the handoff's browser URL (or the UUID from it). " +
        "The API needs the prefixed id (hdf_…) returned when the handoff was " +
        "created. If you no longer have it, create a new handoff — links can't " +
        "be revived from their URL."
    );
  }
  // Single path segment — never a path (guards traversal via a crafted id).
  return assertIdSegment(id, "handoff id");
}

export async function handoffGet({ args, origin }) {
  guardHandoffId(args[0], "converly handoffs get <handoff_id>");
  return apiRequest(origin, "GET", `/handoffs/${args[0]}`);
}

export async function handoffWait({ args, flags, origin }) {
  guardHandoffId(args[0], "converly handoffs wait <handoff_id>");
  // Ceiling so a huge (or `1e306`, which multiplies to Infinity) --timeout
  // can't turn `Date.now() < deadline` into a loop that never ends.
  const MAX_TIMEOUT_SECONDS = 3600;
  let timeoutSeconds = Number(flags.timeout ?? 600);
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new Error("--timeout must be a positive number of seconds.");
  }
  timeoutSeconds = Math.min(timeoutSeconds, MAX_TIMEOUT_SECONDS);
  const intervalMs = 4000;
  const deadline = Date.now() + timeoutSeconds * 1000;

  // Retry ONLY genuinely transient failures: a 5xx/429 API error, or a
  // transport-level error the HTTP client explicitly marked `retryable`
  // (timeout, connection reset, body-read failure). Everything else — a
  // 4xx (bad id, revoked auth), a missing login, a refused off-origin
  // call, a programming error — is permanent and must abort at once rather
  // than be hammered for the full window.
  const isTransient = (err) =>
    (err instanceof ApiError && (err.status >= 500 || err.status === 429)) ||
    err?.retryable === true;

  // Every fetch — including the first — sits inside the tolerant loop: a
  // watcher that dies on a platform blip while a human is mid-OAuth is
  // worse than useless.
  let handoff = null;
  let lastTransientError = null;
  while (Date.now() < deadline) {
    try {
      handoff = await apiRequest(origin, "GET", `/handoffs/${args[0]}`);
      lastTransientError = null;
      if (handoff.status !== "pending") break;
    } catch (err) {
      if (!isTransient(err)) throw err;
      lastTransientError = err;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  if (!handoff) {
    throw (
      lastTransientError ??
      new Error(`Could not reach ${origin} to check the handoff.`)
    );
  }

  if (handoff.status === "completed") return handoff;

  // Precise recovery advice: a pending-but-unexpired link is still
  // usable — resuming the wait beats minting a new link.
  let reason;
  if (handoff.status === "pending") {
    const stillValid =
      handoff.expires_at && new Date(handoff.expires_at) > new Date();
    reason = stillValid
      ? `Timed out after ${timeoutSeconds}s, but the link is still valid until ${handoff.expires_at}. Re-run \`converly handoffs wait ${args[0]}\` once the human has finished in the browser.`
      : `Timed out after ${timeoutSeconds}s and the link has expired. Create a fresh one with \`converly destinations connect\`.`;
  } else {
    reason = `Handoff ended with status "${handoff.status}". Create a fresh connect link with \`converly destinations connect\` if needed.`;
  }
  const err = new Error(reason);
  err.handoff = handoff;
  throw err;
}

export async function conversions({ args, flags, origin }) {
  return apiRequest(
    origin,
    "GET",
    `/destinations/${destId(args[0], "Usage: converly destinations conversions <type>")}/conversions`,
    { query: { refresh: flags.refresh ? "true" : undefined } }
  );
}
