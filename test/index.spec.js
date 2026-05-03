import { Buffer } from 'node:buffer';
import { env, exports as workerExports } from 'cloudflare:workers';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import * as dnsPacket from 'dns-packet';
import { BloomFilter } from 'bloom-filters';

import { BLOOM_KEY } from '../src/blocklist.js';
import { UPSTREAM_DOH_URLS } from '../src/dns.js';
// Importing the worker source (even unused) keeps Vitest re-running this spec
// when src/ changes.
import '../src/index.js';

const BLOCKED = 'blocked.test';
const OPEN = 'open.test';

beforeAll(async () => {
  // Seed the miniflare-backed KV with a Bloom filter that contains BLOCKED.
  // Every test in this file uses this same filter, so the isolate-level cache
  // can persist across tests — no per-test reset needed.
  const filter = BloomFilter.create(8, 1e-6);
  filter.add(BLOCKED);
  await env.KV.put(BLOOM_KEY, JSON.stringify(filter.saveAsJSON()));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('routing', () => {
  it('returns 404 for non-/dns-query path', async () => {
    const res = await workerExports.default.fetch(new Request('https://x/other'));
    expect(res.status).toBe(404);
  });

  it('returns 405 for unsupported method with Allow header', async () => {
    const res = await workerExports.default.fetch(new Request('https://x/dns-query', { method: 'PUT' }));
    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toBe('GET, POST');
  });
});

describe('blocking', () => {
  it('blocks listed domain via POST after checking the upstream reply', async () => {
    const upstreamBody = encodeReply(BLOCKED, [{ name: BLOCKED, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }]);
    const calls = [];
    vi.stubGlobal('fetch', async (req) => {
      calls.push(req.url);
      return new Response(upstreamBody);
    });

    const res = await postQuery(BLOCKED);
    expect(calls).toHaveLength(1);
    expect(UPSTREAM_DOH_URLS).toContain(calls[0]);
    expect(res.status).toBe(200);
    expect((await decode(res)).answers[0].data).toBe('0.0.0.0');
  });

  it('blocks via GET base64url', async () => {
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(encodeReply(BLOCKED, [{ name: BLOCKED, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }])),
    );

    const wire = encodeQuery(BLOCKED);
    const res = await workerExports.default.fetch(new Request(`https://x/dns-query?dns=${toBase64Url(wire)}`));
    expect((await decode(res)).answers[0].data).toBe('0.0.0.0');
  });

  it('blocks via parent-label match', async () => {
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(
          encodeReply('foo.' + BLOCKED, [{ name: 'foo.' + BLOCKED, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }]),
        ),
    );

    const res = await postQuery('foo.' + BLOCKED);
    expect((await decode(res)).answers[0].data).toBe('0.0.0.0');
  });

  it('blocks HTTPS queries with cacheable NODATA after upstream scan hit', async () => {
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(
          encodeReply(BLOCKED, [{ name: BLOCKED, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED }], 'UNKNOWN_65'),
        ),
    );

    const res = await postQuery(BLOCKED, encodeQuery(BLOCKED, 'UNKNOWN_65'));
    const decoded = await decode(res);

    expect(res.status).toBe(200);
    expect(decoded.flags & 0xf).toBe(0);
    expect(decoded.answers).toEqual([]);
    expect(decoded.authorities.find((r) => r.type === 'SOA')).toBeDefined();
  });
});

describe('forwarding', () => {
  it('forwards unblocked queries to upstream with original wire body', async () => {
    const upstreamBody = encodeReply(OPEN, [{ name: OPEN, type: 'A', class: 'IN', ttl: 60, data: '93.184.216.34' }]);
    const wire = encodeQuery(OPEN);
    let forwardedBody = null;
    vi.stubGlobal('fetch', async (req) => {
      expect(UPSTREAM_DOH_URLS).toContain(req.url);
      forwardedBody = new Uint8Array(await req.arrayBuffer());
      return new Response(upstreamBody);
    });

    const res = await postQuery(OPEN, wire);
    expect(res.status).toBe(200);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array(upstreamBody));
    expect(forwardedBody && [...forwardedBody]).toEqual([...wire]);
  });

  it('returns SERVFAIL on upstream non-2xx', async () => {
    vi.stubGlobal('fetch', async () => new Response('', { status: 502 }));
    const res = await postQuery(OPEN);
    expect(res.status).toBe(200);
    expect((await decode(res)).flags & 0xf).toBe(2);
  });

  it('returns SERVFAIL on upstream throw', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new Error('upstream gone');
    });
    const res = await postQuery(OPEN);
    expect((await decode(res)).flags & 0xf).toBe(2);
  });

  it('returns SERVFAIL when upstream selection fails before fetch starts', async () => {
    const saved = [...UPSTREAM_DOH_URLS];
    UPSTREAM_DOH_URLS.length = 0;
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const analytics = vi.spyOn(env.ANALYTICS, 'writeDataPoint');
    try {
      const res = await postQuery(OPEN);
      expect((await decode(res)).flags & 0xf).toBe(2);
      assertSingleDataPoint(analytics, 'servfail', 'A', 'unknown');
    } finally {
      UPSTREAM_DOH_URLS.push(...saved);
    }
  });

  it('returns SERVFAIL on unparseable upstream reply', async () => {
    vi.stubGlobal('fetch', async () => new Response(new Uint8Array([0xff, 0xff, 0xff, 0xff])));
    const res = await postQuery(OPEN);
    expect((await decode(res)).flags & 0xf).toBe(2);
  });
});

describe('reply-side blocking', () => {
  it('blocks when a clean-looking qname resolves through a CNAME to a listed target', async () => {
    const cloak = 'metrics.cloak.test';
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(
          encodeReply(cloak, [
            { name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED },
            { name: BLOCKED, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' },
          ]),
        ),
    );

    const res = await postQuery(cloak);
    expect((await decode(res)).answers[0].data).toBe('0.0.0.0');
  });

  it('returns upstream verbatim when bloom filter is unavailable', async () => {
    const cloak = 'metrics.cloak.test';
    const upstreamBody = encodeReply(cloak, [{ name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED }]);
    const calls = [];
    vi.stubGlobal('fetch', async (req) => {
      calls.push(req.url);
      return new Response(upstreamBody);
    });

    const { __test_resetFilterCache, loadBloomFilter } = await import('../src/blocklist.js');
    __test_resetFilterCache();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const analytics = vi.spyOn(env.ANALYTICS, 'writeDataPoint');
    const originalGet = env.KV.get.bind(env.KV);
    env.KV.get = async () => null;
    try {
      const res = await postQuery(cloak);
      expect(calls).toHaveLength(1);
      expect(UPSTREAM_DOH_URLS).toContain(calls[0]);
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array(upstreamBody));
      assertSingleDataPoint(analytics, 'allowed', 'A');
    } finally {
      env.KV.get = originalGet;
      __test_resetFilterCache();
      await loadBloomFilter(env.KV);
    }
  });
});

describe('analytics', () => {
  it('emits blocked outcome with qtype and colo', async () => {
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(encodeReply(BLOCKED, [{ name: BLOCKED, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }])),
    );
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(BLOCKED);

    assertSingleDataPoint(spy, 'blocked', 'A');
    spy.mockRestore();
  });

  it('emits allowed outcome on upstream success', async () => {
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(encodeReply(OPEN, [{ name: OPEN, type: 'A', class: 'IN', ttl: 60, data: '93.184.216.34' }])),
    );
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(OPEN);

    assertSingleDataPoint(spy, 'allowed', 'A');
    spy.mockRestore();
  });

  it('emits servfail outcome on upstream throw', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new Error('upstream gone');
    });
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(OPEN);

    assertSingleDataPoint(spy, 'servfail', 'A');
    spy.mockRestore();
  });
});

describe('input validation', () => {
  it('rejects malformed dns packet with 400', async () => {
    const res = await workerExports.default.fetch(
      new Request('https://x/dns-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/dns-message' },
        body: new Uint8Array([0, 0]),
      }),
    );
    expect(res.status).toBe(400);
  });

  it('rejects POST without dns content-type with 415', async () => {
    const res = await workerExports.default.fetch(new Request('https://x/dns-query', { method: 'POST', body: 'x' }));
    expect(res.status).toBe(415);
  });
});

async function postQuery(name, wire = encodeQuery(name)) {
  return workerExports.default.fetch(
    new Request('https://x/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: wire,
    }),
  );
}

function encodeQuery(name, type = 'A') {
  return dnsPacket.encode({
    type: 'query',
    id: 42,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ name, type, class: 'IN' }],
  });
}

function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeReply(name, answers, type = 'A') {
  return dnsPacket.encode({
    type: 'response',
    id: 42,
    flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
    questions: [{ name, type, class: 'IN' }],
    answers,
  });
}

async function decode(response) {
  return dnsPacket.decode(Buffer.from(await response.arrayBuffer()));
}

function assertSingleDataPoint(spy, outcome, qtype, upstream = UPSTREAM_DOH_URLS) {
  expect(spy).toHaveBeenCalledTimes(1);
  assertDataPoint(spy.mock.calls[0][0], outcome, qtype, upstream);
}

function assertDataPoint(point, outcome, qtype, upstream) {
  expect(point.blobs).toHaveLength(4);
  expect(point.blobs[0]).toBe(outcome);
  expect(point.blobs[1]).toBe(qtype);
  expect(typeof point.blobs[2]).toBe('string');
  if (Array.isArray(upstream)) expect(upstream).toContain(point.blobs[3]);
  else expect(point.blobs[3]).toBe(upstream);
  expect(point.doubles).toHaveLength(1);
  expect(point.doubles[0]).toBeGreaterThanOrEqual(0);
  expect(point.indexes).toBeUndefined();
}
