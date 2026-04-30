import { domainToASCII } from 'node:url';
import { BloomFilter } from 'bloom-filters';

export const BLOOM_KEY = 'blocklist:bloom';
// 2h: bounds datacenter edge-cache staleness so a fresh bloom built every 6h
// reaches most regions within one cron cycle. Shorter than the 6h cron interval
// so at least one fetch per cycle bypasses the edge cache.
const KV_CACHE_TTL = 7_200;
// Total length 1-253; per-label 1-63 [a-z0-9] starting/ending alnum, hyphens inside.
const VALID_DOMAIN_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// Cache the in-flight promise so concurrent first requests on a cold isolate
// share one KV read + one BloomFilter.fromJSON (multi-MB JSON.parse risks the
// CPU limit if N concurrent requests each parse it).
let filterPromise = null;

export async function loadBloomFilter(kv) {
  if (filterPromise) return filterPromise;
  filterPromise = (async () => {
    try {
      // cacheTtl: serve from the local datacenter cache for KV_CACHE_TTL seconds
      // so repeat reads in the same region skip the round-trip to KV's origin store.
      const json = await kv.get(BLOOM_KEY, { type: 'json', cacheTtl: KV_CACHE_TTL });
      if (!json) {
        console.error('bloom load failed', { reason: 'missing' });
        return null;
      }
      const filter = BloomFilter.fromJSON(json);
      if (!filter || typeof filter.has !== 'function') {
        console.error('bloom load failed', { reason: 'invalid_shape' });
        return null;
      }
      return filter;
    } catch (err) {
      console.error('bloom load failed', { reason: 'load_error', message: err?.message });
      return null;
    }
  })();
  const filter = await filterPromise;
  // Don't cache misses — a transient KV failure shouldn't disable blocking
  // for the lifetime of the isolate.
  if (!filter) filterPromise = null;
  return filter;
}

export function normalizeDomain(value) {
  // domainToASCII: lowercase + IDN → punycode; returns '' for invalid input.
  // Trailing-dot input (FQDN form) is rejected: blocking it would walk parent
  // labels via isBlockedDomain and over-block subdomains, which is the opposite
  // of FQDN's "exact match only" semantics.
  const d = domainToASCII(value.trim());
  return VALID_DOMAIN_RE.test(d) ? d : '';
}

export function isBlockedDomain(domain, filter) {
  // Hagezi lists are wildcard sets: an entry `ads.example.com` blocks every
  // subdomain too. Walk left-to-right by label so `x.y.ads.example.com`
  // matches via its parent. Bloom false positives over-block a clean domain;
  // false negatives are impossible, which is what makes Bloom safe for a denylist.
  let candidate = normalizeDomain(domain);
  while (candidate) {
    if (filter.has(candidate)) return true;
    const dot = candidate.indexOf('.');
    if (dot === -1) return false;
    candidate = candidate.slice(dot + 1);
  }
  return false;
}

// Test-only: reset the isolate-level filter cache between specs. Double-
// underscore + `test` prefix to signal "do not call from request handlers".
export function __test_resetFilterCache() {
  filterPromise = null;
}
