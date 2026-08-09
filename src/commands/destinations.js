/**
 * Destination commands: catalogue, connection state, connect (via a
 * Converly-hosted handoff URL a human opens), handoff polling, and the
 * conversion-action picker.
 *
 * Deliberately absent: paste-token connect. Ad platform credentials
 * should be entered by a human in the Converly-hosted connect popup
 * (the handoff URL), never passed through an agent or a shell history.
 */

import { apiRequest } from "../http.js";

/** `google-ads` → `dest_google-ads`; accepts either form. */
function destId(value) {
  return value.startsWith("dest_") ? value : `dest_${value}`;
}

export async function list({ origin }) {
  return apiRequest(origin, "GET", "/destinations");
}

export async function get({ args, origin }) {
  return apiRequest(origin, "GET", `/destinations/${destId(args[0])}`);
}

export async function types({ origin }) {
  return apiRequest(origin, "GET", "/destination-types");
}

export async function connect({ args, flags, origin }) {
  if (!flags.site) {
    throw new Error(
      "Missing --site. Pass the site id (from `converly sites list`) this connection is for."
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
  return apiRequest(origin, "GET", `/handoffs/${args[0]}`);
}

export async function handoffWait({ args, flags, origin }) {
  const timeoutSeconds = Number(flags.timeout ?? 600);
  const intervalMs = 4000;
  const deadline = Date.now() + timeoutSeconds * 1000;

  let handoff = await apiRequest(origin, "GET", `/handoffs/${args[0]}`);
  while (handoff.status === "pending" && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    handoff = await apiRequest(origin, "GET", `/handoffs/${args[0]}`);
  }

  if (handoff.status === "completed") return handoff;

  const reason =
    handoff.status === "pending"
      ? `Timed out after ${timeoutSeconds}s — the connection was not completed in the browser.`
      : `Handoff ended with status "${handoff.status}".`;
  const err = new Error(
    `${reason} Create a fresh connect link with \`converly destinations connect\` if needed.`
  );
  err.handoff = handoff;
  throw err;
}

export async function conversions({ args, flags, origin }) {
  return apiRequest(
    origin,
    "GET",
    `/destinations/${destId(args[0])}/conversions`,
    { query: { refresh: flags.refresh ? "true" : undefined } }
  );
}
