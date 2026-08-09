# Converly CLI

Set up and manage [Converly](https://converly.io) conversion tracking from the command line. Built for AI agents (Claude Code, OpenClaw, Codex) and humans alike. Every command prints JSON.

Converly tracks form submissions on your website and fires conversion events to ad platforms (Google Ads, Meta, GA4, LinkedIn, TikTok and more), including server-side delivery like Google Enhanced Conversions and Meta CAPI.

## Install

```bash
npm install -g converly
```

Requires Node 18.17+.

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
  --trigger html-form --destination google-ads --conversion-id 123456
converly flows publish flow_XXX
converly test-event --flow flow_XXX        # proves delivery end to end
```

Then keep an eye on real conversions:

```bash
converly events list --limit 10
```

## For AI agents

The agent runbook lives at [github.com/aaronbeashel/converly-agent](https://github.com/aaronbeashel/converly-agent) — install it with `npx skills add aaronbeashel/converly-agent` or `clawhub install converly`. It teaches the full workflow, including the parts that need a human (authorizing the ad platform).

Design notes for agent use:

- stdout is always one JSON document; progress text goes to stderr.
- Exit code 0 means success. Errors are JSON on stderr with the API's error code.
- POST commands send an idempotency key automatically, so retries are safe.
- Ad platform credentials never pass through the CLI. Connecting a destination returns a Converly-hosted URL where a human authorizes the platform directly.

## All commands

Run `converly help` for the full list, or `converly help <command>` for one command's usage. Anything the named commands don't cover is reachable via `converly api <METHOD> </v1-path>` — the full REST API is documented at [developers.converly.io](https://developers.converly.io).

## License

MIT
