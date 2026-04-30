import { Buffer } from 'node:buffer';
import { env, exports as workerExports } from 'cloudflare:workers';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import * as dnsPacket from 'dns-packet';
import { BloomFilter } from 'bloom-filters';

import { BLOOM_KEY } from '../src/blocklist.js';
import { UPSTREAM_DOH_URL } from '../src/dns.js';
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
  it('blocks listed domain via POST without calling upstream', async () => {
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);

    const res = await postQuery(BLOCKED);
    expect(upstream).not.toHaveBeenCalled();
    expect(res.status).toBe(200);
    expect((await decode(res)).answers[0].data).toBe('0.0.0.0');
  });

  it('blocks via GET base64url', async () => {
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);

    const wire = encodeQuery(BLOCKED);
    const res = await workerExports.default.fetch(new Request(`https://x/dns-query?dns=${toBase64Url(wire)}`));
    expect(upstream).not.toHaveBeenCalled();
    expect((await decode(res)).answers[0].data).toBe('0.0.0.0');
  });

  it('blocks via parent-label match', async () => {
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);

    const res = await postQuery('foo.' + BLOCKED);
    expect(upstream).not.toHaveBeenCalled();
    expect((await decode(res)).answers[0].data).toBe('0.0.0.0');
  });
});

describe('forwarding', () => {
  it('forwards unblocked queries to upstream with original wire body', async () => {
    const upstreamBody = new Uint8Array([1, 2, 3, 4]);
    const wire = encodeQuery(OPEN);
    let forwardedBody = null;
    vi.stubGlobal('fetch', async (req) => {
      expect(req.url).toBe(UPSTREAM_DOH_URL);
      forwardedBody = new Uint8Array(await req.arrayBuffer());
      return new Response(upstreamBody);
    });

    const res = await postQuery(OPEN, wire);
    expect(res.status).toBe(200);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(upstreamBody);
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
});

describe('analytics', () => {
  it('emits blocked outcome with qtype and colo', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(BLOCKED);

    expect(spy).toHaveBeenCalledTimes(1);
    assertDataPoint(spy.mock.calls[0][0], 'blocked', 'A');
    spy.mockRestore();
  });

  it('emits allowed outcome on upstream success', async () => {
    vi.stubGlobal('fetch', async () => new Response(new Uint8Array([1, 2, 3, 4])));
    const spy = vi.spyOn(env.ANALYTICS, 'writeDataPoint');

    await postQuery(OPEN);

    expect(spy).toHaveBeenCalledTimes(1);
    assertDataPoint(spy.mock.calls[0][0], 'allowed', 'A');
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

function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
