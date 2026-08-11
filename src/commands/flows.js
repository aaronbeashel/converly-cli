/**
 * Flow commands: the trigger/action catalogue, CRUD, validate, publish,
 * unpublish, and the end-to-end test event.
 */

import { apiRequest } from "../http.js";

export async function triggerTypes({ flags, origin }) {
  const result = await apiRequest(origin, "GET", "/trigger-types", {
    query: { platform: flags.platform },
    public: true,
  });
  if (Array.isArray(result?.data)) {
    result.data = toAgentTriggerCatalogue(result.data);
  }
  return result;
}

/**
 * Reshape the /v1 native-builder trigger catalogue into the honest
 * agent-facing shape — the same one the MCP surface emits
 * (src/app/mcp/route.ts builds it with omitFilterSchemas + agentSurface).
 * /v1's /trigger-types serves the FULL catalogue, which carries two things
 * an agent must not act on:
 *   1. custom_event — a type that can't be set up through this surface.
 *   2. the DESIGNED filter schemas (supports_filters / filters /
 *      at_least_one_filter_required). A flow write here only honours the
 *      trigger's page filter (`flows create --pages`). form_id /
 *      form_selector / page_path_filter are not accepted, and the
 *      "at least one filter required" flag is not enforced — a generic-form
 *      flow with pageFilter:"all" and no pages is valid and publishable.
 *      Leaving them in makes a careful agent stall on a requirement that
 *      does not exist. Strip both to match MCP.
 * Exported so the reshaping is testable without a network.
 */
export function toAgentTriggerCatalogue(data) {
  return data
    .filter((t) => t?.type !== "custom_event")
    .map((t) => {
      const clean = { ...t };
      delete clean.supports_filters;
      delete clean.filters;
      delete clean.at_least_one_filter_required;
      return clean;
    });
}

export async function actionTypes({ args, origin }) {
  if (!args[0]) {
    throw new Error("Usage: converly actions <destination_type>  (e.g. google-ads)");
  }
  return apiRequest(origin, "GET", "/action-types", {
    query: { destination_type: args[0] },
    public: true,
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

function requireFlowId(args, usage) {
  if (!args[0]) throw new Error(`Usage: ${usage}`);
  return args[0];
}

export async function get({ args, origin }) {
  return apiRequest(origin, "GET", `/flows/${requireFlowId(args, "converly flows get <flow_id>")}`);
}

function parseJsonFlag(value, flagName) {
  try {
    return JSON.parse(value);
  } catch (cause) {
    throw new Error(`--${flagName} is not valid JSON: ${cause.message}`);
  }
}

/**
 * Build the trigger config for the simple form. Form tool triggers
 * filter by page; the api trigger is a server-side webhook, so it takes
 * a --key (the webhook identifier) and no page filter. Exported so the
 * validation rules are testable without a network.
 */
export function buildTriggerConfig(flags) {
  if (flags.key !== undefined && flags.trigger !== "api") {
    throw new Error(
      "--key only applies to --trigger api. Form tool triggers filter by page, not by webhook key."
    );
  }
  if (flags.trigger === "api") {
    if (typeof flags.key !== "string" || flags.key === "") {
      throw new Error(
        "The api trigger needs --key, a webhook identifier you choose (letters, numbers, hyphens, underscores). The webhook URL and secret come from `converly triggers connect api --site <site_id>`."
      );
    }
    if (flags.pages !== undefined) {
      throw new Error(
        "--pages does not apply to --trigger api. The webhook fires from the site's backend, so there is no page to filter on."
      );
    }
    return { integrationId: "api", key: flags.key };
  }
  if (!flags.trigger) return undefined;
  return flags.pages
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
  if (flags.value !== undefined) {
    const value = Number(flags.value);
    if (!Number.isFinite(value)) {
      throw new Error("--value must be a number.");
    }
    conversion.value = value;
  }
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

  const triggerConfig = buildTriggerConfig(flags);
  if (triggerConfig) body.trigger_config = triggerConfig;

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
  return apiRequest(origin, "PATCH", `/flows/${requireFlowId(args, "converly flows update <flow_id> --json '{...}'")}`, {
    body: parseJsonFlag(flags.json, "json"),
  });
}

export async function remove({ args, flags, origin }) {
  const flowId = requireFlowId(args, "converly flows delete <flow_id> --yes");
  // Deletion is irreversible; require the explicit flag so an agent
  // can't delete on a whim mid-plan.
  if (!flags.yes) {
    throw new Error(
      `Deleting ${flowId} is permanent, and a published flow stops firing immediately (the delete also removes it from the live config). Re-run with --yes to confirm.`
    );
  }
  return apiRequest(origin, "DELETE", `/flows/${flowId}`);
}

export async function validate({ args, origin }) {
  return apiRequest(origin, "POST", `/flows/${requireFlowId(args, "converly flows validate <flow_id>")}/validate`);
}

export async function publish({ args, origin }) {
  return apiRequest(origin, "POST", `/flows/${requireFlowId(args, "converly flows publish <flow_id>")}/publish`);
}

export async function unpublish({ args, origin }) {
  return apiRequest(origin, "POST", `/flows/${requireFlowId(args, "converly flows unpublish <flow_id>")}/unpublish`);
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

  const result = await apiRequest(origin, "POST", "/test-event", {
    body: {
      flow_id: flags.flow,
      action: {
        action_id: action.action_id ?? action.id,
        integration_id: action.integration_id ?? action.integrationId,
        config: action.config ?? {},
      },
      ...(flags["meta-code"] && { meta_test_event_code: flags["meta-code"] }),
      ...(flags["reddit-id"] && { reddit_test_id: flags["reddit-id"] }),
      ...(flags["tiktok-code"] && { tiktok_test_event_code: flags["tiktok-code"] }),
      ...(flags["allow-real"] && { allow_real_conversion: true }),
    },
  });

  // Browser-only destinations have NO server leg to test — the raw "no
  // server-side forwarder" answer is true but unhelpful (test-campaign
  // finding). Derive the explanation from catalogue DATA, never a
  // hardcoded platform list, and tell the agent what the real test is.
  if (
    result &&
    result.server_status === "not_attempted" &&
    /no server-side forwarder/i.test(result.error_message ?? "")
  ) {
    try {
      const types = await apiRequest(origin, "GET", "/destination-types", {
        public: true,
      });
      const entry = (types?.data ?? []).find(
        (t) => t.type === result.integration_id
      );
      if (entry?.setup?.delivery === "browser") {
        return {
          ...result,
          next_step:
            `${entry.name ?? result.integration_id} fires from the visitor's ` +
            "browser into the platform's own tag, so there is no server call " +
            "to test. Prove it with a real submission on the page and check " +
            "`converly events list` — client_status \"fired\" is the success " +
            "signal. The platform's own tag must be on the page (see the " +
            "destination's setup.page_prerequisite).",
        };
      }
    } catch {
      /* annotation is best-effort — return the raw result */
    }
  }
  return result;
}
