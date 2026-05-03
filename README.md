# Adblock DoH Worker

Cloudflare Worker DNS-over-HTTPS resolver with Bloom-filter ad blocking.

## Shape

- Endpoint: `/dns-query` over `GET` and `POST`.
- Blocklist: Bloom JSON in Workers KV key `blocklist:bloom`.
- Upstream: random recursive DoH resolver from pool.
- Block hit: synthetic DNS response.
- Filter miss or filter load fail: forward DNS upstream.
- Metrics: counts only. No queried domains. No client IPs.

## Requirements

- Node.js 24 + npm
- Cloudflare account + Wrangler access
- KV namespace bound as `KV`
- Analytics Engine dataset bound as `ANALYTICS`

## Commands

```sh
npm ci
npm run bloom:build
npm run bloom:publish:local
npm run dev
```

Check work:

```sh
npm test
npm run format:check
```

Deploy:

```sh
npm run bloom:publish:remote
npm run deploy
```

## Config

Check `wrangler.jsonc` before deploy:

- `name`: Worker name
- `main`: Worker entrypoint
- `kv_namespaces`: Bloom filter KV binding
- `analytics_engine_datasets`: query metrics binding
- `preview_urls`: Preview URL toggle

## Bloom Filter

Build output:

```text
.cache/blocklist-bloom.json
```

Default lists: HaGeZi Pro + TIF wildcard domain-only lists.

Custom list:

```sh
node scripts/build-bloom.js --url https://example.com/list.txt --output .cache/blocklist-bloom.json
```

Multiple lists: repeat `--url`, or set comma/whitespace-separated `BLOCKLIST_URL`.

## Analytics SQL

Dataset: `adblock_doh_analytics`

Slot map:

```text
blob1   outcome: allowed | blocked | servfail
blob2   qtype: A | AAAA | HTTPS | UNKNOWN_65 | ...
blob3   colo
blob4   upstream URL, or unknown
double1 latency_ms
```

Average latency by upstream and outcome:

```sql
SELECT
  blob4 AS upstream,
  blob1 AS outcome,
  SUM(_sample_interval) AS query_count,
  SUM(_sample_interval * double1) / SUM(_sample_interval) AS avg_latency_ms,
  quantileExactWeighted(0.50)(double1, _sample_interval) AS p50_latency_ms,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_latency_ms
FROM adblock_doh_analytics
WHERE timestamp >= NOW() - INTERVAL '1' DAY
GROUP BY upstream, outcome
ORDER BY upstream, outcome;
```

## Automation

`.github/workflows/build-bloom.yml` runs on schedule and manual trigger. It installs Node 24, runs tests, builds Bloom JSON, and publishes it to remote KV.

## References

- [Cloudflare Workers](https://developers.cloudflare.com/workers/)
- [Wrangler commands](https://developers.cloudflare.com/workers/wrangler/commands/)
- [Workers KV bindings](https://developers.cloudflare.com/kv/concepts/kv-bindings/)
- [Workers Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/get-started/)
- [Analytics Engine SQL API](https://developers.cloudflare.com/analytics/analytics-engine/sql-api/)
