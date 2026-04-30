import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BloomFilter } from 'bloom-filters';

import { normalizeDomain } from '../src/blocklist.js';

const BLOCKLIST_URLS = [
  'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt',
  'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt',
];
export const FALSE_POSITIVE_RATE = 1e-10;
// Prevent worker stalls caused by excessively large fetch requests
const MAX_SOURCE_BYTES = 25 * 1024 * 1024;
// Cloudflare KV: 25 MiB max value size.
const MAX_KV_VALUE_BYTES = 25 * 1024 * 1024;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main(process.argv.slice(2), process.env);
}

export async function main(args = process.argv.slice(2), env = process.env, { log = console.log } = {}) {
  const { output, urls } = parseArgs(args, env);
  const domains = new Set();

  for (const url of urls) {
    const text = await fetchSource(url);
    for (const line of text.split(/\r?\n/)) {
      const domain = normalizeDomain(line);
      if (!domain) continue;
      domains.add(domain);
    }
  }

  if (!domains.size) throw new Error('No valid blocklist domains found');

  const filter = BloomFilter.create(domains.size, FALSE_POSITIVE_RATE);
  for (const domain of domains) filter.add(domain);

  const json = JSON.stringify(filter.saveAsJSON());
  const byteLength = Buffer.byteLength(json);
  if (byteLength > MAX_KV_VALUE_BYTES) {
    throw new Error(`Bloom JSON exceeds KV value limit: ${byteLength} > ${MAX_KV_VALUE_BYTES}`);
  }

  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, json);

  const summary = {
    output,
    sources: urls,
    domains: domains.size,
    bytes: byteLength,
    bits: filter.size,
    falsePositiveRate: FALSE_POSITIVE_RATE,
  };

  log(JSON.stringify(summary, null, 2));
  return summary;
}

function parseArgs(args, env) {
  const urls = [];
  let output;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--output') {
      output = args[++i];
    } else if (arg === '--url') {
      urls.push(args[++i]);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!output) throw new Error('--output is required');
  if (!urls.length) urls.push(...parseUrlList(env.BLOCKLIST_URL));

  return { output, urls };
}

function parseUrlList(value) {
  const urls = value?.split(/[\s,]+/).filter(Boolean) ?? [];
  return urls.length ? urls : BLOCKLIST_URLS;
}

async function fetchSource(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`blocklist fetch ${url} failed: ${response.status}`);

  const contentLength = Number(response.headers.get('Content-Length') ?? 0);
  if (contentLength > MAX_SOURCE_BYTES) throw new Error(`blocklist response is too large: ${url}`);

  const buffer = await response.arrayBuffer();
  if (buffer.byteLength > MAX_SOURCE_BYTES) throw new Error(`blocklist response is too large: ${url}`);

  return new TextDecoder().decode(buffer);
}
