import { Buffer } from 'node:buffer';
import * as dnsPacket from 'dns-packet';

import { hasBlockedDomains, loadBloomFilter } from './blocklist.js';
import { blockedResponse, dnsRequest, dnsResponse, readDnsRequest, servfailResponse } from './dns.js';

export default {
  async fetch(request, env) {
    const startedAt = Date.now();

    const url = new URL(request.url);
    if (url.pathname !== '/dns-query') {
      return Response.json({ error: 'not found' }, { status: 404 });
    }
    if (request.method !== 'GET' && request.method !== 'POST') {
      return new Response('method not allowed', {
        status: 405,
        headers: { Allow: 'GET, POST' },
      });
    }

    const wire = await readDnsRequest(request, url);
    if (!wire.ok) return new Response(wire.message, { status: wire.status });

    let query, question;
    try {
      query = dnsPacket.decode(Buffer.from(wire.body));
      question = query.questions?.[0];
      if (!question) throw new Error('missing question');
    } catch {
      return new Response('malformed dns packet', { status: 400 });
    }

    const colo = request.cf?.colo ?? 'unknown';
    const emit = (outcome) => emitAnalytics(env, outcome, question.type, colo, startedAt);

    // Overlap KV Bloom load with upstream DoH fetch. Both promises are awaited
    // together so the latency win does not leave floating Workers I/O behind.
    const filterP = loadBloomFilter(env.KV);
    const upstreamP = fetch(dnsRequest(wire.body));
    try {
      const [res, filter] = await Promise.all([upstreamP, filterP]);
      if (!res.ok) throw new Error(`upstream ${res.status}`);

      // Fail-open on missing/failed filter: a broken blocklist must not break DNS.
      if (!filter) {
        console.warn('serving without bloom filter');
        emit('allowed');
        return dnsResponse(res.body, res.status);
      }

      const upstreamBytes = new Uint8Array(await res.arrayBuffer());
      const reply = dnsPacket.decode(Buffer.from(upstreamBytes));
      if (hasBlockedDomains(reply, filter)) {
        emit('blocked');
        return dnsResponse(blockedResponse(query, question));
      }

      emit('allowed');
      return dnsResponse(upstreamBytes, res.status);
    } catch (err) {
      console.error('servfail', { error: err?.message });
      emit('servfail');
      // RFC 8484 §4.2.1: return SERVFAIL inside DNS, not HTTP 5xx, so DoH
      // clients apply their normal resolver fallback.
      return dnsResponse(servfailResponse(query, question));
    }
  },
};

function emitAnalytics(env, outcome, qtype, colo, startedAt) {
  try {
    // WAE schema — slot order is the contract, never reorder or repurpose
    // (old data stays in old slots forever; silent corruption otherwise).
    //   blobs[0] outcome — 'blocked' | 'allowed' | 'servfail'
    //   blobs[1] qtype   — DNS QTYPE string: 'A', 'AAAA', 'HTTPS', 'TXT', ...
    //   blobs[2] colo    — Cloudflare PoP code (e.g. 'SJC') or 'unknown' in dev
    //   doubles[0] latency_ms — Date.now() - startedAt for the whole request
    // No `indexes` field: dataset is single-stream until traffic warrants
    // per-key sampling (`_sample_interval > 1` in queries).
    env.ANALYTICS?.writeDataPoint({
      blobs: [outcome, qtype, colo],
      doubles: [Date.now() - startedAt],
    });
  } catch {
    // Analytics must not break DNS responses.
  }
}
