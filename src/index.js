import { Buffer } from 'node:buffer';
import * as dnsPacket from 'dns-packet';

import { hasBlockedDomains, loadBloomFilter } from './blocklist.js';
import {
  blockedResponse,
  dnsRequest,
  dnsResponse,
  pickRandom,
  readDnsRequest,
  servfailResponse,
  UPSTREAM_DOH_URLS,
} from './dns.js';

export default {
  async fetch(request, env) {
    const startedAt = Date.now();

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
    // forward upstream (preserves client's exact OPT/EDNS), the
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

    const colo = request.cf?.colo ?? 'unknown';
    let upstreamUrl = 'unknown';
    const emitAnalytics = (outcome) => {
      try {
        // Workers Analytics Engine schema: slot order is the contract, never reorder or repurpose
        // (old data stays in old slots forever; silent corruption otherwise).
        //   blobs[0] outcome       — 'blocked' | 'allowed' | 'servfail'
        //   blobs[1] question.type — DNS QTYPE string: 'A', 'AAAA', 'HTTPS', 'TXT', ...
        //   blobs[2] colo          — Cloudflare PoP code (e.g. 'SJC') or 'unknown' in dev
        //   blobs[3] upstreamUrl   — selected recursive DoH endpoint URL, or 'unknown' if setup failed
        //   doubles[0] latency_ms  — Date.now() - startedAt for the whole request
        // No `indexes` field: dataset is single-stream until traffic warrants
        // per-key sampling (`_sample_interval > 1` in queries).
        env.ANALYTICS?.writeDataPoint({
          blobs: [outcome, question.type, colo, upstreamUrl],
          doubles: [Date.now() - startedAt],
        });
      } catch {
        // Analytics must not break DNS responses.
      }
    };

    try {
      // Overlap KV Bloom load with upstream DoH fetch. Both promises are awaited
      // together so the latency win does not leave floating Workers I/O behind.
      upstreamUrl = pickRandom(UPSTREAM_DOH_URLS);
      const filterP = loadBloomFilter(env.KV);
      const upstreamP = fetch(dnsRequest(wire.body, upstreamUrl));
      const [res, filter] = await Promise.all([upstreamP, filterP]);
      if (!res.ok) throw new Error(`upstream ${res.status}`);

      const upstreamBytes = new Uint8Array(await res.arrayBuffer());
      // If the filter is unavailable, skip block scanning and pass upstream
      // DNS bytes through; loadBloomFilter already logged why.
      if (filter) {
        const reply = dnsPacket.decode(Buffer.from(upstreamBytes));
        if (hasBlockedDomains(reply, filter)) {
          emitAnalytics('blocked');
          return dnsResponse(blockedResponse(query, question));
        }
      }

      emitAnalytics('allowed');
      return dnsResponse(upstreamBytes, res.status);
    } catch (err) {
      console.error('servfail', { message: err?.message });
      emitAnalytics('servfail');
      // RFC 8484 §4.2.1: return SERVFAIL inside DNS, not HTTP 5xx, so DoH
      // clients apply their normal resolver fallback.
      return dnsResponse(servfailResponse(query, question));
    }
  },
};
