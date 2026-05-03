# Adblock DoH Worker

A Cloudflare Worker that serves a DNS-over-HTTPS endpoint with ad blocking backed by a Bloom filter stored in Workers KV.

## What It Does

- Handles DoH requests at `/dns-query` over GET and POST.
- Loads a serialized Bloom filter from Workers KV key `blocklist:bloom`.
- Blocks matching domains with synthetic DNS responses.
- Forwards queries to a recursive DoH upstream pool, then blocks replies whose answers match the Bloom filter.
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
