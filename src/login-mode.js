/**
 * Login dispatch: which flow should `converly login` run?
 *
 * The loopback browser flow requires the browser and the CLI to share a
 * machine. On a headless/remote box that dead-ends silently (the browser
 * "opens" into nothing and the human never gets a code to act on) — the
 * worst possible first-run for an agent-driven install. So the default
 * command auto-routes to device login on STRONG remote/headless signals,
 * with explicit flags always winning.
 *
 * Precedence (Codex-reviewed, docs/DEVICE-LOGIN-ACQUISITION-PLAN.md §2):
 *   1. --device AND --browser         → conflict, usage error
 *   2. --device                       → device
 *   3. --browser                      → loopback (force, even if headless)
 *   4. --no-open                      → loopback WITHOUT launching (its
 *      long-standing meaning; it also keeps the refreshable OAuth
 *      credential, so repurposing it would silently change what gets
 *      stored — deliberately unchanged)
 *   5. CI truthy / SSH / linux-with-no-display → device (auto)
 *   6. otherwise                      → loopback
 *
 * Deliberately NOT a signal: stdout TTY-ness. This CLI pipes JSON to
 * stdout by contract, so stdout is non-TTY in perfectly browserful
 * setups (agents, `| jq`). Using it would misroute laptops to device.
 */

/** "1"/"true"/"yes" → true; ""/"0"/"false"/undefined → false. */
export function envTruthy(value) {
  if (value === undefined || value === null) return false;
  const s = String(value).trim().toLowerCase();
  return s !== "" && s !== "0" && s !== "false" && s !== "no";
}

/**
 * Decide the login mode. Pure — takes flags/env/platform so tests can
 * exercise every row of the environment table.
 *
 * Returns: "device" | "device_auto" | "loopback"
 * Throws on conflicting flags.
 */
export function resolveLoginMode(
  flags,
  env = process.env,
  platform = process.platform
) {
  if (flags.device && flags.browser) {
    throw new Error(
      "--device and --browser conflict. Pick one: --device approves from any device; --browser forces the local browser flow."
    );
  }
  if (flags.device) return "device";
  if (flags.browser) return "loopback";
  // --no-open keeps its long-standing loopback-without-launch meaning.
  if (flags["no-open"]) return "loopback";

  const headless =
    envTruthy(env.CI) ||
    Boolean(env.SSH_CONNECTION) ||
    Boolean(env.SSH_TTY) ||
    (platform === "linux" && !env.DISPLAY && !env.WAYLAND_DISPLAY);

  return headless ? "device_auto" : "loopback";
}
