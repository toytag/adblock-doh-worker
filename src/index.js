import { Buffer } from 'node:buffer';
import * as dnsPacket from 'dns-packet';

import { loadBloomFilter } from './blocklist.js';
import {
  dnsRequest,
  dnsResponse,
  parseSinkUrls,
  pickRandom,
  readDnsRequest,
  scanAnswersForBlocked,
  servfailResponse,
} from './dns.js';

export default {
  async fetch(request, env) {
    // Analytics - latency_ms
    const startedAt = Date.now();
    // Analytics - server location
    const colo = request.cf?.colo ?? 'unknown';

    // RFC 8484: DoH lives at a single resource (`/dns-query`) and accepts
    // only GET (base64url query in `?dns=`) or POST (raw wire in body).
    // Everything else is HTTP-layer noise — reject before touching DNS.
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

    // Wire bytes + decoded query are kept side-by-side: the wire is what we
    // forward to upstream/sink (preserves client's exact OPT/EDNS), the
    // decoded form is what we need for SERVFAIL synth (id, RD flag, OPT echo).
    const wire = await readDnsRequest(request, url);
    if (!wire.ok) return new Response(wire.message, { status: wire.status });

    // Decode failure here = client sent garbage. HTTP 400 (not SERVFAIL): we
    // have no query id/flags to build a valid DNS response from.
    let query, question;
    try {
      query = dnsPacket.decode(Buffer.from(wire.body));
      question = query.questions?.[0];
      if (!question) throw new Error('missing question');
    } catch {
      return new Response('malformed dns packet', { status: 400 });
    }

    // Analytics - helper function
    const emit = (outcome) => emitAnalytics(env, outcome, question.type, colo, startedAt);

    // Overlap KV bloom load with upstream DoH fetch — they're independent and
    // the cold-isolate KV read can otherwise serialize ~10-50ms in front of
    // the upstream RTT. loadBloomFilter never throws (returns null on failure).
    const filterP = loadBloomFilter(env.KV);
    try {
      const res = await fetch(dnsRequest(wire.body));
      if (!res.ok) throw new Error(`upstream ${res.status}`);
      const filter = await filterP;

      // Fail-open on missing/failed filter: a broken blocklist must not break
      // DNS. Stream upstream body straight through — no decode needed.
      if (!filter) {
        console.warn('serving without bloom filter');
        emit('allowed');
        return dnsResponse(res.body, res.status);
      }

      // Scan path: buffer the reply so we can decode + walk answers for any
      // domain the bloom flags. Costs one extra alloc vs streaming, but the
      // alternative is teeing the body — same memory, more plumbing.
      const upstreamBytes = new Uint8Array(await res.arrayBuffer());
      const reply = dnsPacket.decode(Buffer.from(upstreamBytes));
      if (!scanAnswersForBlocked(reply, filter)) {
        emit('allowed');
        return dnsResponse(upstreamBytes);
      }

      // Scan hit: re-issue original wire to sinkhole DoH so it owns per-qtype
      // block synthesis (A/AAAA null route, HTTPS/SVCB NODATA, etc.).
      // Anything wrong here (missing/bad config, sink failure) falls into
      // the outer catch → SERVFAIL.
      const sinkRes = await fetch(dnsRequest(wire.body, pickRandom(parseSinkUrls(env))));
      if (!sinkRes.ok) throw new Error(`sink ${sinkRes.status}`);
      emit('blocked');
      return dnsResponse(sinkRes.body, sinkRes.status);
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
    //   blobs[0] outcome — 'allowed' | 'blocked' | 'servfail'
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
