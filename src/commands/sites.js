/**
 * Site commands: list/create/get/update, install snippet, install status.
 *
 * Note: site deletion is intentionally not exposed. The OAuth login's
 * scope set doesn't include sites:delete, and an agent should never
 * delete a site anyway.
 */

import { apiRequest } from "../http.js";

export async function list({ flags, origin }) {
  return apiRequest(origin, "GET", "/sites", {
    query: {
      limit: flags.limit,
      starting_after: flags["starting-after"],
    },
  });
}

export async function get({ args, origin }) {
  return apiRequest(origin, "GET", `/sites/${args[0]}`);
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
  return apiRequest(origin, "PATCH", `/sites/${args[0]}`, { body });
}

export async function snippet({ args, origin }) {
  return apiRequest(origin, "GET", `/sites/${args[0]}/install-snippet`);
}

export async function installStatus({ args, origin }) {
  return apiRequest(origin, "GET", `/sites/${args[0]}/install-status`);
}
