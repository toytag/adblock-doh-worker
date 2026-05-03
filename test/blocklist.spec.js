import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BloomFilter } from 'bloom-filters';

import {
  BLOOM_KEY,
  __test_resetFilterCache,
  hasBlockedDomains,
  isBlockedDomain,
  loadBloomFilter,
  normalizeDomain,
} from '../src/blocklist.js';

beforeEach(() => __test_resetFilterCache());
afterEach(() => vi.restoreAllMocks());

describe('normalizeDomain', () => {
  it('lowercases ascii input', () => {
    expect(normalizeDomain('Example.COM')).toBe('example.com');
  });

  it('punycode-encodes IDN input', () => {
    expect(normalizeDomain('bücher.de')).toBe('xn--bcher-kva.de');
  });

  it('rejects FQDN form (trailing dot) so it never matches subdomains', () => {
    expect(normalizeDomain('example.com.')).toBe('');
  });

  it('rejects empty labels and leading hyphens', () => {
    expect(normalizeDomain('-bad.com')).toBe('');
    expect(normalizeDomain('a..b')).toBe('');
  });

  it('rejects labels over 63 chars and domains over 253', () => {
    expect(normalizeDomain('a'.repeat(64) + '.com')).toBe('');
    const long = (Array(20).fill('a'.repeat(12)).join('.') + '.com').slice(0, 254);
    expect(normalizeDomain(long + 'x')).toBe('');
  });

  it('accepts hyphens inside labels and digits', () => {
    expect(normalizeDomain('a-1.b2.example')).toBe('a-1.b2.example');
  });
});

describe('isBlockedDomain', () => {
  it('matches exact domain', () => {
    const filter = stubFilter(['ads.example.com']);
    expect(isBlockedDomain('ads.example.com', filter)).toBe(true);
  });

  it('matches by parent-label walk (wildcard semantics)', () => {
    const filter = stubFilter(['ads.example.com']);
    expect(isBlockedDomain('foo.bar.ads.example.com', filter)).toBe(true);
  });

  it('does not match non-suffix overlap', () => {
    const filter = stubFilter(['ads.example.com']);
    expect(isBlockedDomain('badads.example.com', filter)).toBe(false);
    expect(isBlockedDomain('safe.example.com', filter)).toBe(false);
  });

  it('returns false for invalid domain', () => {
    const filter = stubFilter(['anything']);
    expect(isBlockedDomain('-bad.com', filter)).toBe(false);
  });
});

describe('loadBloomFilter', () => {
  it('returns null when KV key is missing and logs reason', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await loadBloomFilter(new KvStub())).toBeNull();
    expect(err).toHaveBeenCalledWith('bloom load failed', { reason: 'missing' });
  });

  it('returns null when Bloom JSON rehydrates to an invalid filter shape', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(BloomFilter, 'fromJSON').mockReturnValue({});
    const kv = new KvStub({ [BLOOM_KEY]: { filter: 'invalid' } });
    expect(await loadBloomFilter(kv)).toBeNull();
    expect(err).toHaveBeenCalledWith('bloom load failed', { reason: 'invalid_shape' });
  });

  it('returns null when KV throws and logs reason with message', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const kv = {
      get: async () => {
        throw new Error('kv down');
      },
    };
    expect(await loadBloomFilter(kv)).toBeNull();
    expect(err).toHaveBeenCalledWith('bloom load failed', { reason: 'load_error', message: 'kv down' });
  });

  it('rehydrates a real Bloom filter from KV JSON', async () => {
    const kv = bloomKv(['blocked.test']);
    const filter = await loadBloomFilter(kv);
    expect(filter?.has('blocked.test')).toBe(true);
    expect(filter?.has('open.test')).toBe(false);
  });

  it('caches rehydrated filter in module memory after first call', async () => {
    const kv = bloomKv(['blocked.test']);
    await loadBloomFilter(kv);
    await loadBloomFilter(kv);
    expect(kv.gets).toBe(1);
  });

  it('shares one KV read across concurrent first calls (thundering herd)', async () => {
    const kv = bloomKv(['blocked.test']);
    await Promise.all([
      loadBloomFilter(kv),
      loadBloomFilter(kv),
      loadBloomFilter(kv),
      loadBloomFilter(kv),
      loadBloomFilter(kv),
    ]);
    expect(kv.gets).toBe(1);
  });

  it('does not cache misses (lets a transient KV failure retry)', async () => {
    let calls = 0;
    const kv = {
      async get() {
        calls++;
        if (calls === 1) throw new Error('kv down');
        return null;
      },
    };
    expect(await loadBloomFilter(kv)).toBeNull();
    expect(await loadBloomFilter(kv)).toBeNull();
    expect(calls).toBe(2);
  });
});

describe('hasBlockedDomains', () => {
  it('returns true when the value itself is a blocked domain', () => {
    expect(hasBlockedDomains('tracker.example', stubFilter(['tracker.example']))).toBe(true);
  });

  it('returns true when any nested string is blocked', () => {
    const value = {
      service: {
        metadata: ['clean.example', { target: 'tracker.example' }],
      },
    };

    expect(hasBlockedDomains(value, stubFilter(['tracker.example']))).toBe(true);
  });

  it('returns true when a decoded DNS-like object contains a blocked domain', () => {
    const value = {
      answers: [
        {
          name: 'clean.example',
          type: 'HTTPS',
          class: 'IN',
          ttl: 60,
          data: { priority: 1, target: 'tracker.example', values: [] },
        },
      ],
    };

    expect(hasBlockedDomains(value, stubFilter(['tracker.example']))).toBe(true);
  });

  it('returns true when the record name itself is blocked by a parent-label match', () => {
    const reply = {
      answers: [{ name: 'sub.tracker.example', type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }],
    };
    expect(hasBlockedDomains(reply, stubFilter(['tracker.example']))).toBe(true);
  });

  it('returns false for all-clean nested values', () => {
    const value = {
      hostnames: ['clean.example', { target: 'cdn.example' }],
      addresses: ['1.2.3.4', '::1'],
    };

    expect(hasBlockedDomains(value, stubFilter(['tracker.example']))).toBe(false);
  });

  it('returns false for empty and non-string containers without throwing', () => {
    const filter = stubFilter(['tracker.example']);
    const values = [
      { items: [] },
      {},
      { count: 1, enabled: true, nested: null },
      { foo: { bar: 42, baz: null, list: [{ ok: false }] } },
    ];

    for (const value of values) {
      expect(() => hasBlockedDomains(value, filter)).not.toThrow();
      expect(hasBlockedDomains(value, filter)).toBe(false);
    }
  });

  it('ignores TXT junk that is not a valid domain', () => {
    const value = {
      text: ['v=spf1 include:_spf.example -all'],
    };
    expect(hasBlockedDomains(value, stubFilter(['tracker.example']))).toBe(false);
  });

  it('does not special-case DNS sections', () => {
    const value = {
      answers: [{ name: 'clean.example', type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }],
      authorities: [{ name: 'tracker.example', type: 'NS', class: 'IN', ttl: 60, data: 'tracker.example' }],
      additionals: [{ name: 'tracker.example', type: 'A', class: 'IN', ttl: 60, data: '5.6.7.8' }],
    };
    expect(hasBlockedDomains(value, stubFilter(['tracker.example']))).toBe(true);
  });
});

function stubFilter(domains) {
  const set = new Set(domains);
  return { has: (d) => set.has(d) };
}

// In-memory KV stub. Real Workers KV (via vitest-pool-workers) doesn't expose
// a read counter or let us inject throws, both of which the cache tests below
// rely on. `get` ignores opts because loadBloomFilter always passes
// `{type: 'json'}` and we hand back the parsed object directly.
class KvStub {
  gets = 0;

  constructor(store = {}) {
    this.store = store;
  }

  async get(key) {
    this.gets++;
    return this.store[key] ?? null;
  }
}

function bloomKv(domains) {
  const filter = BloomFilter.create(Math.max(domains.length, 1), 1e-6);
  for (const d of domains) filter.add(d);
  return new KvStub({ [BLOOM_KEY]: filter.saveAsJSON() });
}
