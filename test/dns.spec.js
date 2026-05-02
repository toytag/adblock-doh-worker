import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import * as dnsPacket from 'dns-packet';

import {
  dnsResponse,
  pickRandom,
  readDnsRequest,
  scanAnswersForBlocked,
  servfailResponse,
  UPSTREAM_DOH_URLS,
} from '../src/dns.js';

const baseQuestion = { name: 'x.com', type: 'A', class: 'IN' };
const baseQuery = {
  id: 42,
  flags: dnsPacket.RECURSION_DESIRED,
  questions: [baseQuestion],
};

describe('readDnsRequest', () => {
  it('decodes GET base64url dns parameter', async () => {
    const wire = encodeQuery('blocked.test');
    const url = new URL(`http://x/dns-query?dns=${toBase64Url(wire)}`);
    const result = await readDnsRequest(new Request(url, { method: 'GET' }), url);
    expect(result.ok).toBe(true);
    expect([...new Uint8Array(result.body)]).toEqual([...wire]);
  });

  it('rejects GET without dns parameter', async () => {
    const url = new URL('http://x/dns-query');
    const result = await readDnsRequest(new Request(url, { method: 'GET' }), url);
    expect(result).toEqual({
      ok: false,
      status: 400,
      message: 'missing dns parameter',
    });
  });

  it('rejects GET with non-base64url characters', async () => {
    const url = new URL('http://x/dns-query?dns=not!valid');
    const result = await readDnsRequest(new Request(url, { method: 'GET' }), url);
    expect(result.ok).toBe(false);
    expect(result.status).toBe(400);
  });

  it('rejects POST without application/dns-message content-type', async () => {
    const url = new URL('http://x/dns-query');
    const req = new Request(url, { method: 'POST', body: 'x' });
    const result = await readDnsRequest(req, url);
    expect(result).toEqual({
      ok: false,
      status: 415,
      message: 'unsupported content type',
    });
  });

  it('reads POST wire body when content-type is set', async () => {
    const url = new URL('http://x/dns-query');
    const wire = encodeQuery('blocked.test');
    const req = new Request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: wire,
    });
    const result = await readDnsRequest(req, url);
    expect(result.ok).toBe(true);
    expect([...new Uint8Array(result.body)]).toEqual([...wire]);
  });

  it('accepts POST content-type with parameters and mixed case', async () => {
    const url = new URL('http://x/dns-query');
    const wire = encodeQuery('blocked.test');
    const req = new Request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'Application/DNS-Message; charset=binary' },
      body: wire,
    });
    const result = await readDnsRequest(req, url);
    expect(result.ok).toBe(true);
    expect([...new Uint8Array(result.body)]).toEqual([...wire]);
  });
});

describe('servfailResponse', () => {
  it('has rcode 2 and preserves id', () => {
    const decoded = decode(servfailResponse(baseQuery, baseQuestion));
    expect(decoded.flags & 0xf).toBe(2);
    expect(decoded.id).toBe(42);
  });

  it('echoes client OPT with DO bit cleared', () => {
    const query = { ...baseQuery, additionals: [opt({ flags: dnsPacket.DNSSEC_OK })] };
    const decoded = decode(servfailResponse(query, baseQuestion));
    const echoed = decoded.additionals.find((r) => r.type === 'OPT');
    expect(echoed).toBeDefined();
    expect(echoed.flags & dnsPacket.DNSSEC_OK).toBe(0);
  });
});

describe('pickRandom', () => {
  it('returns the only element of a one-item array', () => {
    expect(pickRandom(['only'])).toBe('only');
  });

  it('eventually returns every element across many calls', () => {
    const items = ['a', 'b', 'c'];
    const seen = new Set();
    for (let i = 0; i < 200 && seen.size < items.length; i++) {
      const picked = pickRandom(items);
      expect(items).toContain(picked);
      seen.add(picked);
    }
    expect(seen.size).toBe(items.length);
  });
});

describe('UPSTREAM_DOH_URLS pool', () => {
  it('is a non-empty array of https URLs', () => {
    expect(Array.isArray(UPSTREAM_DOH_URLS)).toBe(true);
    expect(UPSTREAM_DOH_URLS.length).toBeGreaterThan(0);
    for (const u of UPSTREAM_DOH_URLS) expect(u).toMatch(/^https:\/\//);
  });
});

describe('scanAnswersForBlocked', () => {
  const filter = stubFilter(['tracker.example']);

  it('returns true when CNAME chain ends in a blocked target', () => {
    const reply = {
      answers: [{ name: 'clean.example', type: 'CNAME', class: 'IN', ttl: 60, data: 'tracker.example' }],
    };
    expect(scanAnswersForBlocked(reply, filter)).toBe(true);
  });

  it.each(['HTTPS', 'SVCB'])('returns true when a %s record target is blocked', (type) => {
    const reply = {
      answers: [
        {
          name: 'clean.example',
          type,
          class: 'IN',
          ttl: 60,
          data: { priority: 1, target: 'tracker.example', values: [] },
        },
      ],
    };
    expect(scanAnswersForBlocked(reply, filter)).toBe(true);
  });

  it('returns true when a PTR rdata is blocked', () => {
    const reply = {
      answers: [{ name: '1.0.0.127.in-addr.arpa', type: 'PTR', class: 'IN', ttl: 60, data: 'tracker.example' }],
    };
    expect(scanAnswersForBlocked(reply, filter)).toBe(true);
  });

  it('returns true when the record name itself is blocked (parent-label match)', () => {
    const reply = {
      answers: [{ name: 'sub.tracker.example', type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }],
    };
    expect(scanAnswersForBlocked(reply, filter)).toBe(true);
  });

  it('returns false for an all-clean answers section', () => {
    const reply = {
      answers: [
        { name: 'clean.example', type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' },
        { name: 'clean.example', type: 'AAAA', class: 'IN', ttl: 60, data: '::1' },
      ],
    };
    expect(scanAnswersForBlocked(reply, filter)).toBe(false);
  });

  it('returns false for an empty answers section', () => {
    expect(scanAnswersForBlocked({ answers: [] }, filter)).toBe(false);
  });

  it('returns false when answers is missing entirely (does not throw)', () => {
    expect(scanAnswersForBlocked({}, filter)).toBe(false);
  });

  it('does not throw on records with unexpected rdata shapes', () => {
    const reply = {
      answers: [{ name: 'clean.example', type: 'WEIRD', class: 'IN', ttl: 60, data: { foo: { bar: 42, baz: null } } }],
    };
    expect(() => scanAnswersForBlocked(reply, filter)).not.toThrow();
    expect(scanAnswersForBlocked(reply, filter)).toBe(false);
  });

  it('ignores TXT junk that is not a valid domain', () => {
    const reply = {
      answers: [
        { name: 'clean.example', type: 'TXT', class: 'IN', ttl: 60, data: ['v=spf1 include:_spf.example -all'] },
      ],
    };
    expect(scanAnswersForBlocked(reply, filter)).toBe(false);
  });

  it('ignores authorities and additionals sections', () => {
    const reply = {
      answers: [{ name: 'clean.example', type: 'A', class: 'IN', ttl: 60, data: '1.2.3.4' }],
      authorities: [{ name: 'tracker.example', type: 'NS', class: 'IN', ttl: 60, data: 'tracker.example' }],
      additionals: [{ name: 'tracker.example', type: 'A', class: 'IN', ttl: 60, data: '5.6.7.8' }],
    };
    expect(scanAnswersForBlocked(reply, filter)).toBe(false);
  });
});

describe('dnsResponse', () => {
  it('wraps body with DoH content-type and default 200', async () => {
    const body = new Uint8Array([1, 2, 3]);
    const res = dnsResponse(body);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('application/dns-message');
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(body);
  });

  it('honors explicit status override', () => {
    const res = dnsResponse(new Uint8Array([0]), 502);
    expect(res.status).toBe(502);
    expect(res.headers.get('Content-Type')).toBe('application/dns-message');
  });
});

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

function decode(bytes) {
  return dnsPacket.decode(Buffer.from(bytes));
}

function stubFilter(domains) {
  const set = new Set(domains);
  return { has: (d) => set.has(d) };
}

function opt({ flags = 0, udpPayloadSize = 1232 } = {}) {
  return { type: 'OPT', name: '.', udpPayloadSize, flags, extendedRcode: 0, ednsVersion: 0, options: [] };
}
