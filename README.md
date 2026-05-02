# Adblock DoH Worker

A Cloudflare Worker that serves a DNS-over-HTTPS endpoint with ad blocking backed by a Bloom filter stored in Workers KV.

## What It Does

- Handles DoH requests at `/dns-query` over GET and POST.
- Loads a serialized Bloom filter from Workers KV key `blocklist:bloom`.
- Blocks matching domains with synthetic DNS responses.
- Forwards allowed queries to Cloudflare DNS at `https://cloudflare-dns.com/dns-query`.
- Writes per-query outcome metrics to Workers Analytics Engine when the `ANALYTICS` binding is available.
- Fails open if the Bloom filter is missing or cannot be loaded, so DNS keeps working.

## Requirements

- Node.js 24 & npm
- A Cloudflare account with Wrangler access
- A Workers KV namespace bound as `KV`
- A Workers Analytics Engine dataset bound as `ANALYTICS`

## Setup

```sh
npm ci
```

Review `wrangler.jsonc` before deploying:

- `name`: Worker name
- `main`: Worker entrypoint
- `kv_namespaces`: KV namespace binding used for the Bloom filter
- `analytics_engine_datasets`: analytics binding for query metrics

## Sinkhole DoH Endpoints

When the Bloom filter flags an upstream answer, the Worker re-issues the
original wire query to a sinkhole DoH endpoint, which owns the per-qtype
block synthesis (A/AAAA null route, HTTPS/SVCB NODATA, etc.).

Sink endpoints are personal AdGuard DNS URLs (e.g. `https://d.adguard-dns.com/dns-query/<hash>`),
each tied to an account-level quota — the AdGuard free tier allows roughly
**300,000 DNS queries per month per account**, so a pool of three accounts
covers ~900k/month. When a sink exhausts its quota, AdGuard stops blocking
and the Worker's `'blocked'` outcome silently degrades to a passthrough;
monitor the analytics dataset and rotate accounts as needed.

The sink URLs are read from `env.SINK_DOH_URLS`, a JSON-encoded string
array. They are not committed because they identify your AdGuard account
and are rate-limited.

Local dev — create `.dev.vars` (gitignored):

```
SINK_DOH_URLS=["https://d.adguard-dns.com/dns-query/AAA","https://d.adguard-dns.com/dns-query/BBB"]
```

Production — set as a Worker secret:

```sh
echo '["https://d.adguard-dns.com/dns-query/AAA","https://d.adguard-dns.com/dns-query/BBB"]' \
  | npx wrangler secret put SINK_DOH_URLS
```

If `SINK_DOH_URLS` is missing or malformed, blocked queries fall back to a
locally-synthesized NODATA reply (no upstream sink call).

## Local Development

Build the Bloom filter:

```sh
npm run bloom:build
```

Publish it to local Wrangler state:

```sh
npm run bloom:publish:local
```

Run the Worker locally:

```sh
npm run dev
```

The local Worker listens on Wrangler's dev server. Send DoH requests to `/dns-query`.

## Tests And Formatting

```sh
npm test
npm run format:check
```

Use `npm run format` to apply formatting to `scripts/`, `src/`, and `test/`.

## Bloom Filter

The build script downloads the configured blocklists, normalizes domains, deduplicates them, and writes:

```text
.cache/blocklist-bloom.json
```

By default it uses the HaGeZi Pro and TIF wildcard domain only lists. To build from custom sources, pass one or more URLs:

```sh
node scripts/build-bloom.js --url https://example.com/list.txt --output .cache/blocklist-bloom.json
```

Or set `BLOCKLIST_URL` to a comma- or whitespace-separated URL list.

## Deployment

Publish the Bloom filter to the remote KV namespace:

```sh
npm run bloom:publish:remote
```

Deploy the Worker:

```sh
npm run deploy
```

The GitHub Actions workflow in `.github/workflows/build-bloom.yml` runs on a schedule and can also be triggered manually. It installs dependencies with Node 24, runs tests, builds the Bloom filter, and publishes it to remote KV.

## References

- [Cloudflare Workers](https://developers.cloudflare.com/workers/)
- [Wrangler commands](https://developers.cloudflare.com/workers/wrangler/commands/)
- [Workers KV bindings](https://developers.cloudflare.com/kv/concepts/kv-bindings/)
- [Workers Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/get-started/)
