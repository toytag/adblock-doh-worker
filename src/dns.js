import { Buffer } from 'node:buffer';
import * as dnsPacket from 'dns-packet';

export const UPSTREAM_DOH_URL = 'https://cloudflare-dns.com/dns-query';
const BLOCK_TTL_SECONDS = 300;

const RCODE_NOERROR = 0;
const RCODE_SERVFAIL = 2;
const RCODE_NXDOMAIN = 3;

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

function syntheticSoa(name, ttl) {
  return {
    name,
    type: 'SOA',
    ttl,
    data: {
      // mname/rname are synthetic — we are not a real authoritative server,
      // but the record must parse. Clients only read `minimum` for neg-cache.
      mname: name,
      rname: `hostmaster.${name}`,
      serial: 1,
      refresh: ttl,
      retry: ttl,
      expire: ttl,
      minimum: ttl,
    },
  };
}

function echoOpt(query) {
  const opt = query.additionals?.find((r) => r.type === 'OPT');
  if (!opt) return [];
  // Clear DO bit: synth answers are unsigned, so a validating client must not
  // be told this response carries DNSSEC data.
  return [{ ...opt, flags: (opt.flags ?? 0) & ~dnsPacket.DNSSEC_OK, options: opt.options ?? [] }];
}

function encode(query, question, rcode, answers, authorities = []) {
  const flags =
    // Mirror a real recursive resolver: keep client RD, set RA, layer in rcode;
    // otherwise clients reject the synthetic response.
    dnsPacket.RECURSION_AVAILABLE | ((query.flags ?? 0) & dnsPacket.RECURSION_DESIRED) | rcode;
  return dnsPacket.encode({
    type: 'response',
    id: query.id ?? 0,
    flags,
    questions: [question],
    answers,
    additionals: echoOpt(query),
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
  const authorities = answers.length === 0 ? [syntheticSoa(question.name, ttl)] : [];
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

export function dnsRequest(body, url = UPSTREAM_DOH_URL) {
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message' },
    body,
  });
}
