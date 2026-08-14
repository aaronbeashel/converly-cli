# Converly CLI

Set up and manage [Converly](https://converly.io) conversion tracking from the command line. Built for AI agents (Claude Code, OpenClaw, Codex) and humans alike. Every command prints JSON.

Converly tracks form submissions on your website and fires conversion events to ad platforms (Google Ads, Meta, GA4, LinkedIn, TikTok and more), including server-side delivery like Google Enhanced Conversions and Meta CAPI.

## Install

```bash
npm install -g @converly/cli
```

This installs the `converly` command. Requires Node 20 or newer.

## Log in

```bash
converly login
```

Opens your browser, you log in or create an account (new accounts start a free trial automatically), and the CLI stores its credential in `~/.converly/config.json`. No API key to copy around. The credential is scoped for agent safety: it cannot touch billing, delete sites, or read stored ad platform credentials.

For headless environments, set `CONVERLY_API_KEY` instead.

## Set up tracking in nine commands

```bash
converly login --signup
converly sites list
converly sites update site_XXX --domain example.com
converly install snippet site_XXX          # add the tag to your site's <head>
converly destinations connect google-ads --site site_XXX
converly handoffs wait hdf_XXX             # finish connecting in the browser
converly flows create --site site_XXX --name "Demo requests" \
  --trigger generic-form --destination google-ads --conversion-id 123456
converly flows publish flow_XXX
converly test-event --flow flow_XXX        # proves delivery end to end
```

Then keep an eye on real conversions:

```bash
converly events list --limit 10
```

## For AI agents

The agent runbook lives at [github.com/converlyio/converly-agent](https://github.com/converlyio/converly-agent). Install it with `npx skills add converlyio/converly-agent` or `clawhub install converly`. It teaches the full workflow, including the parts that need a human (authorizing the ad platform).

Design notes for agent use:

- stdout is one JSON document for every data command (help and version print text); progress goes to stderr.
- Exit code 0 means success. Errors are JSON on stderr with the API's error code. The `gtm` commands add finer grained codes, listed under Google Tag Manager below.
- Each POST generates an idempotency key for its own internal retry. To make an explicit retry of the same operation safe across invocations, pass the same `--idempotency-key` value both times.
- Ad platform credentials never pass through the CLI. Connecting a destination returns a Converly-hosted URL where a human authorizes the platform directly.
- `converly login` needs the browser and the CLI on the same machine. For remote or headless environments, set `CONVERLY_API_KEY`.

## Google Tag Manager

`converly gtm` reads and writes Google Tag Manager containers. It exists to answer the questions you cannot answer by looking at a live page.

When a conversion is not tracking, the container usually looks fine from outside. The tag might be paused. It might be blocked by a second trigger. Its trigger might depend on a built-in variable nobody ever switched on. Most often of all, the tag is built and simply was never published, which from outside is indistinguishable from having no tag at all. These commands surface each of those.

### Connect a Google account

```bash
converly gtm login
```

This is a separate login from `converly login`, because it authorizes Google rather than Converly. It opens a browser on this machine, you approve access, and the credential is stored in the same `~/.converly/config.json` (permissions 0600) alongside the Converly one. `converly gtm logout` revokes the token at Google and removes it.

`converly gtm status` tells you whether the connection still works, and reports which scopes Google actually granted. That second part matters, because a user who unticks one checkbox at the consent screen gets a confusing permission error much later instead of an obvious failure at login.

### Google Cloud Console setup

Before `gtm login` works, someone with access to a Google Cloud project has to create the OAuth client. This is a one time job.

1. In Google Cloud Console, pick or create a project.
2. Under APIs & Services, enable the **Tag Manager API**.
3. Under APIs & Services > OAuth consent screen, set up the consent screen and add the four scopes listed below.
4. Under APIs & Services > Credentials, choose Create credentials > OAuth client ID, and set Application type to **Desktop app**. This is the important part. A Web application client will not work with the loopback redirect this CLI uses.
5. Take the client ID and set it as `CONVERLY_GTM_CLIENT_ID`, or paste it into `DEFAULT_CLIENT_ID` in `src/gtm-auth.js` so every user gets it by default.

A client ID is an identifier, not a credential, so it is safe to commit. If Google's token endpoint asks this client for a secret, supply it through `CONVERLY_GTM_CLIENT_SECRET`. Never commit that value. Desktop clients are public clients in the OAuth sense, so PKCE is what actually protects the flow, and this CLI always uses it.

You do not need to register a redirect URI. Google accepts any loopback port for Desktop app clients.

The CLI requests exactly four scopes and no others:

```
https://www.googleapis.com/auth/tagmanager.manage.accounts
https://www.googleapis.com/auth/tagmanager.edit.containers
https://www.googleapis.com/auth/tagmanager.edit.containerversions
https://www.googleapis.com/auth/tagmanager.publish
```

There is deliberately no delete scope. Nothing in these commands deletes a container, and asking for it would put "delete your containers" on the consent screen that every user reads.

### Reading a container

```bash
converly gtm accounts
converly gtm containers --account 6000123
converly gtm workspaces --account 6000123 --container 7770001
converly gtm changes --account 6000123 --container 7770001
```

Work outward from `accounts`. Every other command needs ids from the one before it.

Workspace IDs are assigned by GTM, are not predictable, and are rarely 1. Always list them rather than guessing.

`converly gtm changes` is the most useful command in the group. It checks every workspace, not just the default one, and tells you whether there are unpublished changes waiting. That is the difference between "you need to build this" and "you built it already, it just needs publishing", which lead to opposite advice.

The rest read one workspace:

| Command | What it is for |
| --- | --- |
| `gtm tags` | Tags, with `paused`, `blockingTriggerId`, `tagFiringOption`, `consentSettings` and the destination IDs pulled out of the parameter tree |
| `gtm triggers` | Triggers, with conditions returned literally |
| `gtm variables` | User-defined variables |
| `gtm builtins` | Which built-in variables are enabled, and which trigger-critical ones are not |
| `gtm versions` | Version history and which version is live |

`gtm triggers` returns conditions exactly as they are stored, for example `equals {arg0: "{{_event}}", arg1: "purchase"}`. It does not try to work out whether that condition is ever true on the real site, because that is precisely what cannot be known from the container. Preview mode or a real page load is the only way to settle it.

### Writing to a container

```bash
converly gtm create-tag --account 6000123 --container 7770001 --workspace 41 \
  --name "GA4 purchase" --type gaawe --trigger 7 \
  --json '{"parameter":[{"type":"template","key":"measurementId","value":"G-ABC123"}]}'
```

`create-tag`, `create-trigger` and `create-variable` write into a workspace. That is safe and needs no confirmation, because nothing in a workspace reaches the live site until a version is published.

`--json` takes the full resource body and wins over the convenience flags, which is how you set anything the flags do not cover. Copy `--type` from an existing resource rather than guessing it. Note that `tagFiringOption` values are lowercase at the start (`unlimited`, `oncePerEvent`, `oncePerLoad`), and the CLI rejects other spellings with a clear message rather than passing them to the API.

### Publishing, and why it is gated

```bash
converly gtm publish --account 6000123 --container 7770001 --workspace 41 --confirm
```

Publishing pushes the container to the live site for every visitor, immediately. It refuses unless **both** of these are true:

1. `CONVERLY_GTM_ALLOW_PUBLISH=true` is set in the environment.
2. `--confirm` is passed on the command line.

The two conditions are deliberately different in kind. A flag is not real protection on its own, because an AI agent driving this CLI can pass any flag it decides it needs. The environment variable is the operator's gate. An agent cannot set the environment of a session a human already started, so it is the condition it cannot satisfy by itself.

If you are an agent reading this, that is the point. Do not ask the user to export the variable just to get past the refusal. Building tags inside a workspace needs no gate, so carry on with that and let the person who owns the site decide when to publish.

The variable must be exactly `true`. Values like `1` or `yes` do not open the gate.

`--workspace` creates a version from that workspace and publishes it. `--version-id` publishes a version that already exists. It is spelled `--version-id` rather than `--version` because `--version` prints the CLI version.

To roll back, publish the previous version id from `converly gtm versions`.

### Exit codes

Every command prints JSON on stdout and diagnostics on stderr, the same as the rest of the CLI. The `gtm` commands add finer grained exit codes so an agent can branch without reading the message.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Unclassified failure. Also every argument parsing error, for all commands |
| 2 | Usage. A flag is missing, malformed, or contradictory. Retrying the same command will fail the same way |
| 3 | Not connected to Google, or the login expired and could not be refreshed. Run `converly gtm login` |
| 4 | Google refused the call. Either permission denied, or quota exhausted after retries |
| 5 | The publish gate refused. No other command returns this |

The rest of the CLI keeps its original contract of 0 for success and 1 for failure. Only the `gtm` group uses 2 through 5.

### Rate limits

The Tag Manager API allows 25 requests per 100 seconds per project, which is not much. The CLI paces itself against that window and retries with backoff.

Two things about this API are worth knowing. Quota exhaustion comes back as HTTP 403 rather than 429, so the CLI reads the error reason to tell a spent quota apart from a genuine permission problem. Under load the API also returns truncated or malformed bodies with a 200 status instead of a clean error. The CLI treats those as failures and retries them, rather than reporting an empty list. Reporting "no tags" for a container that has tags would be the most damaging thing this tool could do.

`converly gtm changes` makes one request per workspace, so on a container with many workspaces it can pause partway through. That is the pacing working, not a hang.

## All commands

Run `converly help` for the full list, or `converly help <command>` for one command's usage. Anything the named commands don't cover is reachable via `converly api <METHOD> </v1-path>` — the full REST API is documented at [developers.converly.io](https://developers.converly.io).

## License

MIT
