import { Buffer } from 'node:buffer';
import * as dnsPacket from 'dns-packet';

import { isBlockedDomain, normalizeDomain } from './blocklist.js';

// Pool of recursive DoH endpoints; one is picked at random per request via
// pickRandom. Spreading load across providers is privacy + reliability
// hygiene — no single upstream sees the full query stream from one client.
export const UPSTREAM_DOH_URLS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
  'https://dns.quad9.net/dns-query',
];

// env.SINK_DOH_URLS is a JSON-encoded URL array. Anything malformed throws
// → caught by the outer fetch handler → SERVFAIL with the error logged.
export function parseSinkUrls(env) {
  return JSON.parse(env.SINK_DOH_URLS);
}

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

export function servfailResponse(query, question) {
  // Echo client's OPT (EDNS) record with the DNSSEC OK bit cleared — synth
  // answers are unsigned, so a validating client must not be told this
  // response carries DNSSEC data.
  const opt = query.additionals?.find((r) => r.type === 'OPT');
  const additionals = opt
    ? [{ ...opt, flags: (opt.flags ?? 0) & ~dnsPacket.DNSSEC_OK, options: opt.options ?? [] }]
    : [];
  // Mirror a real recursive resolver: set RA, echo client RD per RFC 1035
  // §4.1.1, OR in SERVFAIL in the low nibble — otherwise stub resolvers
  // reject the response.
  const flags = dnsPacket.RECURSION_AVAILABLE | ((query.flags ?? 0) & dnsPacket.RECURSION_DESIRED) | RCODE_SERVFAIL;
  return dnsPacket.encode({
    type: 'response',
    id: query.id ?? 0,
    flags,
    questions: [question],
    answers: [],
    additionals,
  });
}

export function dnsResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'application/dns-message' },
  });
}

// Type-agnostic recursive walk: yield every string anywhere in `value`. Lets
// us scan rdata without per-record-type knowledge. normalizeDomain filters
// out anything that isn't a syntactically valid domain (TXT junk, base64
// blobs, IP literals, SPF strings with spaces all fail the regex).
function* allStrings(value) {
  if (typeof value === 'string') yield value;
  else if (Array.isArray(value)) for (const v of value) yield* allStrings(v);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) yield* allStrings(v);
}

// Scan only the answers section. Authorities/additionals carry NS hostnames
// and glue records — false-positive risk if any NS hostname matches the
// bloom, and tracker domains live in answers anyway.
export function scanAnswersForBlocked(reply, filter) {
  for (const record of reply?.answers ?? []) {
    for (const s of allStrings(record)) {
      const d = normalizeDomain(s);
      if (d && isBlockedDomain(d, filter)) return true;
    }
  }
  return false;
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
