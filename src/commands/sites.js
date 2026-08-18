/**
 * Site commands: list/create/get/update, install snippet, install status.
 *
 * Note: site deletion is intentionally not exposed. The OAuth login's
 * scope set doesn't include sites:delete, and an agent should never
 * delete a site anyway.
 */

import { apiRequest } from "../http.js";
import { assertIdSegment } from "./ids.js";

export async function list({ flags, origin }) {
  return apiRequest(origin, "GET", "/sites", {
    query: {
      limit: flags.limit,
      starting_after: flags["starting-after"],
    },
  });
}

export async function get({ args, origin }) {
  return apiRequest(origin, "GET", `/sites/${assertIdSegment(args[0], "site id")}`);
}

export async function create({ flags, origin }) {
  return apiRequest(origin, "POST", "/sites", {
    body: {
      ...(flags.name !== undefined && { name: flags.name }),
      ...(flags.domain !== undefined && { domain: flags.domain }),
      ...(flags.timezone !== undefined && { timezone: flags.timezone }),
    },
  });
}

export async function update({ args, flags, origin }) {
  const body = {};
  if (flags.name !== undefined) body.name = flags.name;
  if (flags.domain !== undefined) body.domain = flags.domain;
  if (flags.timezone !== undefined) body.timezone = flags.timezone;
  if (Object.keys(body).length === 0) {
    throw new Error(
      "Nothing to update — pass at least one of --name, --domain, --timezone."
    );
  }
  return apiRequest(origin, "PATCH", `/sites/${assertIdSegment(args[0], "site id")}`, { body });
}

export async function snippet({ args, origin }) {
  const result = await apiRequest(
    origin,
    "GET",
    `/sites/${assertIdSegment(args[0], "site id")}/install-snippet`
  );
  // Retrieval is not installation — mirror the handoff commands'
  // next_step pattern so an agent knows the job isn't done yet.
  return {
    ...result,
    next_step:
      "Add this tag to the website's <head> (do it yourself if you have " +
      "repo access, otherwise hand it to the user; site builders need a " +
      "republish before it is live). Then load any page of the site once " +
      "in a real browser (you can do this yourself if you have browser " +
      "tools) and verify with `converly install status " +
      args[0] +
      '`. The loader phones home on page load and detection becomes ' +
      '"confirmed" within moments.',
  };
}

export async function installStatus({ args, origin }) {
  if (!args[0]) {
    throw new Error(
      "Usage: converly install status <site_id>   (get the id from `converly sites list`)"
    );
  }
  return apiRequest(origin, "GET", `/sites/${assertIdSegment(args[0], "site id")}/install-status`);
}

/**
 * The per-site setup checklist (GET /v1/sites/{id}/setup-status) with a
 * ready-to-run converly command attached to each actionable item. The
 * mapping is by ITEM ID, never by provider — new providers flow through
 * with no CLI changes (the server's structured `next` stays alongside
 * as the source of truth).
 */
export async function status({ args, flags, origin }) {
  let siteId = flags.site ?? args[0];
  if (!siteId) {
    const sitesResult = await apiRequest(origin, "GET", "/sites");
    const all = Array.isArray(sitesResult?.data) ? sitesResult.data : [];
    if (all.length === 1) {
      siteId = all[0].id;
    } else if (all.length === 0) {
      throw new Error("This account has no sites yet.");
    } else {
      throw new Error(
        `This account has ${all.length} sites — pass --site <site_id> (run \`converly sites list\`).`
      );
    }
  }
  assertIdSegment(siteId, "site id");
  const result = await apiRequest(origin, "GET", `/sites/${siteId}/setup-status`);
  const commandFor = (item) => {
    const slug = item.integration;
    switch (item.id) {
      case "site_domain":
        return `converly sites update ${siteId} --domain <their-domain>`;
      case "install_snippet":
        return `converly install snippet ${siteId}`;
      case "flows":
        return item.what_and_why.includes("No flows")
          ? "converly flows create --site " +
              siteId +
              ' --name "..." --trigger <slug> --destination <slug> ...'
          : "converly flows validate <flow_id>, then converly flows publish <flow_id>";
      case "destination_connections":
        return slug
          ? `converly destinations connect ${slug} --site ${siteId}`
          : null;
      case "trigger_connection":
        return slug ? `converly triggers connect ${slug} --site ${siteId}` : null;
      case "first_conversion":
        return "converly test-event --flow <flow_id>, or submit the real form and check converly events list";
      default:
        return null;
    }
  };
  return {
    ...result,
    items: (result.items ?? []).map((item) => {
      const command =
        item.status === "action_needed" ? commandFor(item) : null;
      return command ? { ...item, command } : item;
    }),
  };
}
