import { Buffer } from 'node:buffer';
import * as dnsPacket from 'dns-packet';

// Pool of recursive DoH endpoints; one is picked at random per request via
// pickRandom so no single upstream sees the full query stream from one client.
export const UPSTREAM_DOH_URLS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
  'https://dns.quad9.net/dns-query',
];
const BLOCK_TTL_SECONDS = 60;

const RCODE_NOERROR = 0;
const RCODE_SERVFAIL = 2;

export async function readDnsRequest(request, url) {
  if (request.method === 'GET') {
    // RFC 8484 §4.1: wire-format DNS query in base64url `dns` parameter.
    const encoded = url.searchParams.get('dns');
    if (!encoded) return { ok: false, status: 400, message: 'missing dns parameter' };
    const body = decodeBase64Url(encoded);
    return body ? { ok: true, body } : { ok: false, status: 400, message: 'invalid dns parameter' };
  }
  // RFC 8484 §4.1: POST puts raw wire bytes in the body.
  const ct = request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase();
  if (ct !== 'application/dns-message') {
    return { ok: false, status: 415, message: 'unsupported content type' };
  }
  return { ok: true, body: new Uint8Array(await request.arrayBuffer()) };
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+=*$/.test(value)) return null;
  try {
    const buf = Buffer.from(value, 'base64url');
    return buf.length ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength) : null;
  } catch {
    return null;
  }
}

function negativeCachingSoa(name, ttl) {
  return {
    name,
    type: 'SOA',
    ttl,
    data: {
      // mname/rname are synthetic — we are not a real authoritative server,
      // but the record must parse. Clients only read `minimum` for neg-cache.
      mname: 'fake-for-negative-caching.invalid',
      rname: `hostmaster.${name && name !== '.' ? name : 'invalid'}`,
      serial: 1,
      refresh: 1800,
      retry: 900,
      expire: 604800,
      minimum: ttl,
    },
  };
}

function encode(query, question, rcode, answers, authorities = []) {
  return dnsPacket.encode({
    type: 'response',
    id: query.id ?? 0,
    // Mirror a real recursive resolver: keep client RD, set RA, layer in rcode;
    // otherwise clients reject the synthetic response.
    flags: dnsPacket.RECURSION_AVAILABLE | ((query.flags ?? 0) & dnsPacket.RECURSION_DESIRED) | rcode,
    questions: [question],
    answers,
    additionals: [],
    authorities,
  });
}

export function blockedResponse(query, question, ttl = BLOCK_TTL_SECONDS) {
  const answers = [];
  // A/AAAA get null-route synthesis; other types get empty NOERROR so the
  // client sees "no such record" rather than a fake IP.
  if (question.type === 'A') answers.push({ ...question, ttl, data: '0.0.0.0' });
  else if (question.type === 'AAAA') answers.push({ ...question, ttl, data: '::' });
  // RFC 2308: empty NOERROR (NODATA) needs an SOA in the authority section so
  // the client knows how long to negative-cache. Without it, RFC-strict clients
  // re-query on every lookup — common for HTTPS/SVCB (type 65), which Apple and
  // Chrome fire alongside every A/AAAA. A/AAAA blocks already carry a TTL on
  // the synth answer, so they don't need this.
  const authorities = answers.length === 0 ? [negativeCachingSoa(question.name, ttl)] : [];
  return encode(query, question, RCODE_NOERROR, answers, authorities);
}

export function servfailResponse(query, question) {
  return encode(query, question, RCODE_SERVFAIL, []);
}

export function dnsResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'application/dns-message' },
  });
}

export function pickRandom(items) {
  return items[Math.floor(Math.random() * items.length)];
}

export function dnsRequest(body, url = pickRandom(UPSTREAM_DOH_URLS)) {
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message' },
    body,
  });
}
