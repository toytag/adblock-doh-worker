import { Buffer } from 'node:buffer';
import { env, exports as workerExports } from 'cloudflare:workers';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import * as dnsPacket from 'dns-packet';
import { BloomFilter } from 'bloom-filters';

import { BLOOM_KEY } from '../src/blocklist.js';
import { parseSinkUrls, UPSTREAM_DOH_URLS } from '../src/dns.js';

const SINK_DOH_URLS = parseSinkUrls(env);
// Importing the worker source (even unused) keeps Vitest re-running this spec
// when src/ changes.
import '../src/index.js';

const BLOCKED = 'blocked.test';
const OPEN = 'open.test';

beforeAll(async () => {
  // Sink-routing tests rely on env.SINK_DOH_URLS being populated (via
  // .dev.vars in local dev / vitest-pool-workers). Fail loudly if missing
  // so the suite doesn't silently fall back to the SERVFAIL path.
  expect(SINK_DOH_URLS.length).toBeGreaterThan(0);

  // Seed the miniflare-backed KV with a Bloom filter that contains BLOCKED.
  // Every test in this file uses this same filter, so the isolate-level cache
  // can persist across tests — no per-test reset needed.
  const filter = BloomFilter.create(8, 1e-6);
  filter.add(BLOCKED);
  await env.KV.put(BLOOM_KEY, JSON.stringify(filter.saveAsJSON()));
});

afterEach(() => {
  vi.unstubAllGlobals();
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

  it('serves GET ?dns=... requests', async () => {
    const upstreamBody = encodeReply(OPEN, [{ name: OPEN, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }]);
    vi.stubGlobal('fetch', async () => new Response(upstreamBody));
    const wire = encodeQuery(OPEN);
    const b64 = Buffer.from(wire).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const res = await workerExports.default.fetch(new Request(`https://x/dns-query?dns=${b64}`));
    expect(res.status).toBe(200);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array(upstreamBody));
  });
});

describe('forwarding', () => {
  it('returns the upstream reply verbatim when no answer is blocked', async () => {
    const upstreamBody = encodeReply(OPEN, [{ name: OPEN, type: 'A', class: 'IN', ttl: 60, data: '93.184.216.34' }]);
    const wire = encodeQuery(OPEN);
    let forwardedUrl = null;
    let forwardedBody = null;
    vi.stubGlobal('fetch', async (req) => {
      forwardedUrl = req.url;
      forwardedBody = new Uint8Array(await req.arrayBuffer());
      return new Response(upstreamBody);
    });

    const res = await postQuery(OPEN, wire);
    expect(UPSTREAM_DOH_URLS).toContain(forwardedUrl);
    expect(forwardedBody && [...forwardedBody]).toEqual([...wire]);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array(upstreamBody));
  });

  it('returns SERVFAIL on upstream non-2xx', async () => {
    vi.stubGlobal('fetch', async () => new Response('', { status: 502 }));
    const res = await postQuery(OPEN);
    expect((await decode(res)).flags & 0xf).toBe(2);
  });

  it('returns SERVFAIL on upstream throw', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new Error('upstream gone');
    });
    const res = await postQuery(OPEN);
    expect((await decode(res)).flags & 0xf).toBe(2);
  });

  it('returns SERVFAIL on unparseable upstream reply', async () => {
    const garbage = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    vi.stubGlobal('fetch', async () => new Response(garbage));
    const res = await postQuery(OPEN);
    expect((await decode(res)).flags & 0xf).toBe(2);
  });
});

describe('reply-side blocking', () => {
  it('returns the AdGuard sink response when an answer is blocked (CNAME chain)', async () => {
    const cloak = 'metrics.cloak.test';
    const upstreamBody = encodeReply(cloak, [
      { name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED },
      { name: BLOCKED, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' },
    ]);
    const sinkBody = encodeReply(cloak, [{ name: cloak, type: 'A', class: 'IN', ttl: 60, data: '0.0.0.0' }]);
    const calls = [];
    vi.stubGlobal('fetch', async (req) => {
      calls.push(req.url);
      if (SINK_DOH_URLS.includes(req.url)) return new Response(sinkBody);
      return new Response(upstreamBody);
    });

    const res = await postQuery(cloak);
    expect(calls).toHaveLength(2);
    expect(UPSTREAM_DOH_URLS).toContain(calls[0]);
    expect(SINK_DOH_URLS).toContain(calls[1]);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array(sinkBody));
  });

  it.each([
    ['throws', () => Promise.reject(new Error('sink down'))],
    ['returns non-2xx', () => new Response('', { status: 502 })],
  ])('returns SERVFAIL when sink %s (worker can\'t synth block, let client fall back)', async (_label, sinkResponder) => {
    const cloak = 'metrics.cloak.test';
    const upstreamBody = encodeReply(cloak, [{ name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED }]);
    vi.stubGlobal('fetch', async (req) => {
      if (SINK_DOH_URLS.includes(req.url)) return sinkResponder();
      return new Response(upstreamBody);
    });

    const res = await postQuery(cloak);
    const decoded = await decode(res);
    expect(decoded.flags & 0xf).toBe(2);
    expect(decoded.answers).toEqual([]);
  });

  it('passes the original wire bytes to the sink', async () => {
    const cloak = 'metrics.cloak.test';
    const wire = encodeQuery(cloak);
    const upstreamBody = encodeReply(cloak, [{ name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED }]);
    let sinkBody = null;
    vi.stubGlobal('fetch', async (req) => {
      if (SINK_DOH_URLS.includes(req.url)) {
        sinkBody = new Uint8Array(await req.arrayBuffer());
        return new Response(encodeReply(cloak, []));
      }
      return new Response(upstreamBody);
    });

    await postQuery(cloak, wire);
    expect(sinkBody && [...sinkBody]).toEqual([...wire]);
  });

  it('blocks via parent-label match in answers (subdomain of a listed parent)', async () => {
    const sub = 'asset.cdn.test';
    // Bloom contains BLOCKED ('blocked.test'); use a CNAME pointing to a deeper label.
    const upstreamBody = encodeReply(sub, [
      { name: sub, type: 'CNAME', class: 'IN', ttl: 60, data: 'tile.' + BLOCKED },
    ]);
    vi.stubGlobal('fetch', async (req) => {
      if (SINK_DOH_URLS.includes(req.url)) return new Response(encodeReply(sub, []));
      return new Response(upstreamBody);
    });

    const res = await postQuery(sub);
    // Confirm we hit the sink path (response is an empty NOERROR from the stub).
    expect((await decode(res)).answers).toEqual([]);
  });

  it('returns upstream verbatim when bloom filter is unavailable (fail open)', async () => {
    const cloak = 'metrics.cloak.test';
    const upstreamBody = encodeReply(cloak, [{ name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED }]);
    const calls = [];
    vi.stubGlobal('fetch', async (req) => {
      calls.push(req.url);
      return new Response(upstreamBody);
    });

    // Reset the isolate cache and point KV at a missing key for one call.
    const { __test_resetFilterCache } = await import('../src/blocklist.js');
    __test_resetFilterCache();
    const original = env.KV.get.bind(env.KV);
    env.KV.get = async () => null;
    try {
      const res = await postQuery(cloak);
      expect(calls).toHaveLength(1);
      expect(UPSTREAM_DOH_URLS).toContain(calls[0]);
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array(upstreamBody));
    } finally {
      env.KV.get = original;
      __test_resetFilterCache();
      // Re-warm the cache so subsequent tests see BLOCKED again.
      const { loadBloomFilter } = await import('../src/blocklist.js');
      await loadBloomFilter(env.KV);
    }
  });
});

describe('analytics', () => {
  it('emits allowed outcome on clean upstream reply', async () => {
    const upstreamBody = encodeReply(OPEN, [{ name: OPEN, type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }]);
    vi.stubGlobal('fetch', async () => new Response(upstreamBody));
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(OPEN);

    expect(spy).toHaveBeenCalledTimes(1);
    assertDataPoint(spy.mock.calls[0][0], 'allowed', 'A');
    spy.mockRestore();
  });

  it('emits blocked outcome when scan hits and sink succeeds', async () => {
    const cloak = 'metrics.cloak.test';
    const upstreamBody = encodeReply(cloak, [{ name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED }]);
    vi.stubGlobal('fetch', async (req) => {
      if (SINK_DOH_URLS.includes(req.url)) return new Response(encodeReply(cloak, []));
      return new Response(upstreamBody);
    });
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(cloak);

    expect(spy).toHaveBeenCalledTimes(1);
    assertDataPoint(spy.mock.calls[0][0], 'blocked', 'A');
    spy.mockRestore();
  });

  it('emits servfail outcome when scan hits and sink fails', async () => {
    const cloak = 'metrics.cloak.test';
    const upstreamBody = encodeReply(cloak, [{ name: cloak, type: 'CNAME', class: 'IN', ttl: 60, data: BLOCKED }]);
    vi.stubGlobal('fetch', async (req) => {
      if (SINK_DOH_URLS.includes(req.url)) throw new Error('sink down');
      return new Response(upstreamBody);
    });
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(cloak);

    expect(spy).toHaveBeenCalledTimes(1);
    assertDataPoint(spy.mock.calls[0][0], 'servfail', 'A');
    spy.mockRestore();
  });

  it('emits servfail outcome on upstream throw', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new Error('upstream gone');
    });
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(OPEN);

    expect(spy).toHaveBeenCalledTimes(1);
    assertDataPoint(spy.mock.calls[0][0], 'servfail', 'A');
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

function assertDataPoint(point, outcome, qtype) {
  expect(point.blobs).toHaveLength(3);
  expect(point.blobs[0]).toBe(outcome);
  expect(point.blobs[1]).toBe(qtype);
  expect(typeof point.blobs[2]).toBe('string');
  expect(point.doubles).toHaveLength(1);
  expect(point.doubles[0]).toBeGreaterThanOrEqual(0);
  expect(point.indexes).toBeUndefined();
}
