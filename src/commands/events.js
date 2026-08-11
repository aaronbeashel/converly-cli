/**
 * Event commands — the read side. Listing recent conversions, checking
 * delivery health, per-event diagnostics.
 */

import { apiRequest } from "../http.js";
import { assertIdSegment } from "./ids.js";

export async function list({ flags, origin }) {
  return apiRequest(origin, "GET", "/events", {
    query: {
      site_id: flags.site,
      flow_id: flags.flow,
      email: flags.email,
      status: flags.status,
      occurred_after: flags.since,
      occurred_before: flags.until,
      limit: flags.limit,
    },
  });
}

export async function get({ args, origin }) {
  return apiRequest(origin, "GET", `/events/${assertIdSegment(args[0], "event id")}`);
}
