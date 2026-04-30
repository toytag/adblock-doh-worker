import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import * as dnsPacket from 'dns-packet';

import { blockedResponse, dnsResponse, readDnsRequest, servfailResponse } from '../src/dns.js';

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
});

describe('blockedResponse', () => {
  it('A returns 0.0.0.0 with the requested TTL', () => {
    const decoded = decode(blockedResponse(baseQuery, baseQuestion, 60));
    expect(decoded.answers[0].data).toBe('0.0.0.0');
    expect(decoded.answers[0].ttl).toBe(60);
  });

  it('AAAA returns ::', () => {
    const q = { ...baseQuestion, type: 'AAAA' };
    const decoded = decode(blockedResponse({ ...baseQuery, questions: [q] }, q, 60));
    expect(decoded.answers[0].data).toBe('::');
  });

  it('TXT returns empty NOERROR', () => {
    const q = { ...baseQuestion, type: 'TXT' };
    const decoded = decode(blockedResponse({ ...baseQuery, questions: [q] }, q, 60));
    expect(decoded.answers).toEqual([]);
    expect(decoded.flags & 0xf).toBe(0);
  });

  it('non-A/AAAA NODATA carries SOA in authority for negative caching (RFC 2308)', () => {
    const q = { ...baseQuestion, type: 'TXT' };
    const decoded = decode(blockedResponse({ ...baseQuery, questions: [q] }, q, 60));
    const soa = decoded.authorities.find((r) => r.type === 'SOA');
    expect(soa).toBeDefined();
    expect(soa.name).toBe('x.com');
    expect(soa.ttl).toBe(60);
    expect(soa.data.minimum).toBe(60);
    expect(soa.data.mname).toBe('x.com');
    expect(soa.data.rname).toBe('hostmaster.x.com');
  });

  it('HTTPS (UNKNOWN_65) is treated as non-A/AAAA: NODATA with SOA', () => {
    const q = { ...baseQuestion, type: 'UNKNOWN_65' };
    const decoded = decode(blockedResponse({ ...baseQuery, questions: [q] }, q, 60));
    expect(decoded.answers).toEqual([]);
    expect(decoded.authorities.find((r) => r.type === 'SOA')).toBeDefined();
  });

  it('A block omits authority SOA (synth answer carries TTL already)', () => {
    const decoded = decode(blockedResponse(baseQuery, baseQuestion, 60));
    expect(decoded.authorities.find((r) => r.type === 'SOA')).toBeUndefined();
  });

  it('AAAA block omits authority SOA', () => {
    const q = { ...baseQuestion, type: 'AAAA' };
    const decoded = decode(blockedResponse({ ...baseQuery, questions: [q] }, q, 60));
    expect(decoded.authorities.find((r) => r.type === 'SOA')).toBeUndefined();
  });

  it('preserves query id and RD flag, sets RA bit', () => {
    const decoded = decode(blockedResponse(baseQuery, baseQuestion, 60));
    expect(decoded.id).toBe(42);
    expect(decoded.flags & dnsPacket.RECURSION_DESIRED).toBeTruthy();
    expect(decoded.flags & dnsPacket.RECURSION_AVAILABLE).toBeTruthy();
  });

  it('echoes client OPT with DO bit cleared', () => {
    const query = { ...baseQuery, additionals: [opt({ flags: dnsPacket.DNSSEC_OK })] };
    const decoded = decode(blockedResponse(query, baseQuestion, 60));
    const echoed = decoded.additionals.find((r) => r.type === 'OPT');
    expect(echoed).toBeDefined();
    expect(echoed.udpPayloadSize).toBe(1232);
    expect(echoed.flags & dnsPacket.DNSSEC_OK).toBe(0);
  });

  it('omits OPT when query has none', () => {
    const decoded = decode(blockedResponse(baseQuery, baseQuestion, 60));
    expect(decoded.additionals.find((r) => r.type === 'OPT')).toBeUndefined();
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

describe('dnsResponse', () => {
  it('wraps body with DoH content-type and default 200', async () => {
    const body = new Uint8Array([1, 2, 3]);
    const res = dnsResponse(body);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('application/dns-message');
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(body);
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

function opt({ flags = 0, udpPayloadSize = 1232 } = {}) {
  return { type: 'OPT', name: '.', udpPayloadSize, flags, extendedRcode: 0, ednsVersion: 0, options: [] };
}
