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

/** `google-ads` → `dest_google-ads`; accepts either form. */
function destId(value, commandHint) {
  if (!value) {
    throw new Error(
      `Missing destination type. ${commandHint} (run \`converly destinations types\` for the list).`
    );
  }
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

export async function handoffGet({ args, origin }) {
  if (!args[0]) throw new Error("Usage: converly handoffs get <handoff_id>");
  return apiRequest(origin, "GET", `/handoffs/${args[0]}`);
}

export async function handoffWait({ args, flags, origin }) {
  if (!args[0]) throw new Error("Usage: converly handoffs wait <handoff_id>");
  const timeoutSeconds = Number(flags.timeout ?? 600);
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new Error("--timeout must be a positive number of seconds.");
  }
  const intervalMs = 4000;
  const deadline = Date.now() + timeoutSeconds * 1000;

  // A permanent client error (bad id, revoked auth) should fail fast; a
  // transient one (request timeout, 5xx, 429) must NOT abort a wait on a
  // half-finished human OAuth step — keep polling until the deadline.
  const isTransient = (err) =>
    !(err instanceof ApiError) || err.status >= 500 || err.status === 429;

  let handoff = await apiRequest(origin, "GET", `/handoffs/${args[0]}`);
  while (handoff.status === "pending" && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    try {
      handoff = await apiRequest(origin, "GET", `/handoffs/${args[0]}`);
    } catch (err) {
      if (!isTransient(err)) throw err;
    }
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
