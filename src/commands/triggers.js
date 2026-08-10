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
