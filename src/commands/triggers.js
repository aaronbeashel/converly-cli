/**
 * Trigger-source commands beyond the catalogue: connecting a source that
 * needs setup outside the CLI. Most sources run an OAuth sign-in on a
 * Converly-hosted page; the api source instead hands out webhook
 * credentials for the site's backend.
 *
 * The catalogue itself (`converly triggers`) lives in flows.js next to
 * the other flow-building lookups.
 */

import { apiRequest } from "../http.js";

export async function connect({ args, flags, origin }) {
  if (!args[0]) {
    throw new Error(
      "Missing trigger source. Usage: converly triggers connect <source> --site <site_id> (run `converly triggers` for the source slugs)."
    );
  }
  if (!flags.site) {
    throw new Error(
      "Missing --site. Pass the site id (from `converly sites list`) this trigger connection is for."
    );
  }

  const handoff = await apiRequest(origin, "POST", "/handoffs", {
    body: {
      purpose: "connect_trigger_source",
      trigger_source: args[0],
      site_id: flags.site,
    },
  });

  // The api source shows credentials instead of running an OAuth
  // sign-in, so the follow-up instructions differ.
  const nextStep =
    args[0] === "api"
      ? "A human must open `url` in a browser. The page shows the webhook URL and secret, " +
        "which they hand to whoever maintains the site's backend. Then run " +
        "`converly handoffs wait " +
        handoff.id +
        "` to confirm it completed. Completion means the credentials were " +
        "issued, NOT that the backend call is wired up — that remaining step " +
        "is only proven when the first conversion arrives."
      : "A human must open `url` in a browser and sign in to the platform there. " +
        "Then run `converly handoffs wait " +
        handoff.id +
        "` to confirm it completed. If the completed result lists " +
        "`user_steps_remaining`, connecting alone is NOT enough — relay those " +
        "steps to the human and treat setup as unfinished until they're done.";
  return { ...handoff, next_step: nextStep };
}

/**
 * List a CONNECTED platform's filter options — the account's REAL forms /
 * event types, with ids and names — so a specific one can be offered to the
 * user and written back as the flow's trigger_config.conditions. This is the
 * middle of the narrowing loop: `triggers connect` → `handoffs wait` →
 * `triggers options`. Only requires_connection providers (Typeform,
 * Calendly, Acuity, Jotform) support it; browser-detected form tools narrow
 * by page instead (`flows create --pages`).
 */
export async function options({ args, flags, origin }) {
  if (!args[0]) {
    throw new Error(
      "Missing trigger source. Usage: converly triggers options <source> --site <site_id> (a requires_connection provider slug from `converly triggers`, e.g. typeform, calendly, acuity-scheduling, jotform)."
    );
  }
  if (!flags.site) {
    throw new Error(
      "Missing --site. Pass the site id (from `converly sites list`) the connection belongs to."
    );
  }

  const result = await apiRequest(
    origin,
    "GET",
    `/sites/${flags.site}/trigger-filter-options`,
    {
      query: {
        integration_id: args[0],
        query: flags.query,
        limit: flags.limit,
      },
    }
  );

  // Retrieval is not the end — tell the agent how to apply a chosen value.
  // The field key comes from the response so the example matches the actual
  // condition ("form", "calendar", …). Values are live from the platform;
  // never invent ones not listed here.
  const field = Array.isArray(result?.fields)
    ? result.fields.find((f) => f && f.field)
    : null;
  const fieldKey = field?.field ?? "form";
  return {
    ...result,
    next_step:
      "Offer the user a specific value from fields[].values, then narrow the flow to it by " +
      "writing trigger_config.conditions, e.g. `converly flows update <flow_id> --json " +
      `'{"trigger_config":{"conditions":{"${fieldKey}":{"ids":["<id>"],"names":["<name>"]}}}}'\`. ` +
      "Values come live from the platform; never invent ones not in this list.",
  };
}
