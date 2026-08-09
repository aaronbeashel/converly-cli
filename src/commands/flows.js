/**
 * Flow commands: the trigger/action catalogue, CRUD, validate, publish,
 * unpublish, and the end-to-end test event.
 */

import { apiRequest } from "../http.js";

export async function triggerTypes({ flags, origin }) {
  return apiRequest(origin, "GET", "/trigger-types", {
    query: { platform: flags.platform },
  });
}

export async function actionTypes({ args, origin }) {
  return apiRequest(origin, "GET", "/action-types", {
    query: { destination_type: args[0] },
  });
}

export async function list({ flags, origin }) {
  return apiRequest(origin, "GET", "/flows", {
    query: {
      site_id: flags.site,
      limit: flags.limit,
      starting_after: flags["starting-after"],
    },
  });
}

export async function get({ args, origin }) {
  return apiRequest(origin, "GET", `/flows/${args[0]}`);
}

function parseJsonFlag(value, flagName) {
  try {
    return JSON.parse(value);
  } catch (cause) {
    throw new Error(`--${flagName} is not valid JSON: ${cause.message}`);
  }
}

/**
 * Build the action config for the simple one-destination case.
 * Google Ads picks a conversion by --conversion-id; Meta / GA4 use
 * --event-name. Values nest inside `conversion` (the shape the
 * publish pipeline reads).
 */
function buildActionConfig(flags) {
  const conversion = {};
  if (flags["conversion-id"] !== undefined) {
    conversion.id = flags["conversion-id"];
  }
  if (flags["event-name"] !== undefined) {
    conversion.event_name = flags["event-name"];
    conversion.is_custom = Boolean(flags.custom);
  }
  if (flags.value !== undefined) conversion.value = Number(flags.value);
  if (flags.currency !== undefined) conversion.currency = flags.currency;

  const config = {};
  if (Object.keys(conversion).length > 0) config.conversion = conversion;
  if (flags.enhanced !== undefined) {
    config.enhancedConversions = flags.enhanced !== "false";
  }
  return config;
}

export async function create({ flags, origin }) {
  if (flags.json) {
    return apiRequest(origin, "POST", "/flows", {
      body: parseJsonFlag(flags.json, "json"),
    });
  }

  if (!flags.site || !flags.name) {
    throw new Error(
      "Missing --site or --name. Simple form: --site <id> --name <name> --trigger <slug> --destination <slug> plus --conversion-id (Google Ads) or --event-name (Meta/GA4). Full control: --json '<flow body>'."
    );
  }

  const body = {
    site_id: flags.site,
    name: flags.name,
    ...(flags.description !== undefined && { description: flags.description }),
  };

  if (flags.trigger) {
    body.trigger_config = flags.pages
      ? {
          integrationId: flags.trigger,
          pageFilter: "specific",
          pages: String(flags.pages)
            .split(",")
            .map((p) => p.trim())
            .filter(Boolean),
        }
      : { integrationId: flags.trigger, pageFilter: "all" };
  }

  if (flags.destination) {
    body.actions_config = [
      {
        id: "act-1",
        integrationId: flags.destination,
        config: buildActionConfig(flags),
      },
    ];
  }

  return apiRequest(origin, "POST", "/flows", { body });
}

export async function update({ args, flags, origin }) {
  if (!flags.json) {
    throw new Error(
      "flows update takes --json with the fields to change, e.g. --json '{\"name\":\"New name\"}'."
    );
  }
  return apiRequest(origin, "PATCH", `/flows/${args[0]}`, {
    body: parseJsonFlag(flags.json, "json"),
  });
}

export async function remove({ args, origin }) {
  return apiRequest(origin, "DELETE", `/flows/${args[0]}`);
}

export async function validate({ args, origin }) {
  return apiRequest(origin, "POST", `/flows/${args[0]}/validate`);
}

export async function publish({ args, origin }) {
  return apiRequest(origin, "POST", `/flows/${args[0]}/publish`);
}

export async function unpublish({ args, origin }) {
  return apiRequest(origin, "POST", `/flows/${args[0]}/unpublish`);
}

export async function testEvent({ flags, origin }) {
  if (!flags.flow) {
    throw new Error("Missing --flow <flow_id>.");
  }

  let action;
  if (flags["action-id"] || flags["action-json"]) {
    if (!flags["action-json"]) {
      // Look the action up on the flow by id.
      const flow = await apiRequest(origin, "GET", `/flows/${flags.flow}`);
      const found = (flow.actions_config ?? []).find(
        (a) => a.id === flags["action-id"]
      );
      if (!found) {
        throw new Error(
          `Action "${flags["action-id"]}" not found on ${flags.flow}.`
        );
      }
      action = found;
    } else {
      action = parseJsonFlag(flags["action-json"], "action-json");
    }
  } else {
    // Default: the flow's first action.
    const flow = await apiRequest(origin, "GET", `/flows/${flags.flow}`);
    action = (flow.actions_config ?? [])[0];
    if (!action) {
      throw new Error(
        `Flow ${flags.flow} has no actions configured — nothing to test.`
      );
    }
  }

  return apiRequest(origin, "POST", "/test-event", {
    body: {
      flow_id: flags.flow,
      action: {
        action_id: action.action_id ?? action.id,
        integration_id: action.integration_id ?? action.integrationId,
        config: action.config ?? {},
      },
      ...(flags["meta-code"] && { meta_test_event_code: flags["meta-code"] }),
    },
  });
}
