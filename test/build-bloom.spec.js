import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BloomFilter } from 'bloom-filters';

import { FALSE_POSITIVE_RATE, main } from '../scripts/build-bloom.js';

const scriptPath = fileURLToPath(new URL('../scripts/build-bloom.js', import.meta.url));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('build-bloom script', () => {
  it('sizes the Bloom filter from actual unique domains', async () => {
    stubFetch(['# comment', '*.Blocked.test', 'blocked.test', 'Open.test', 'bad..test'].join('\n'));
    const output = await tmpOutput();

    const summary = await main(['--url', 'https://x/list.txt', '--output', output], {}, { log() {} });
    const json = JSON.parse(await readFile(output, 'utf8'));
    const filter = BloomFilter.fromJSON(json);

    expect(summary.domains).toBe(2);
    expect(summary.falsePositiveRate).toBe(FALSE_POSITIVE_RATE);
    expect(json._size).toBe(BloomFilter.create(2, FALSE_POSITIVE_RATE).size);
    expect(filter.has('blocked.test')).toBe(true);
    expect(filter.has('open.test')).toBe(true);
  });

  it('strips wildcard prefix and # comments, dedupes case', async () => {
    stubFetch(['# header', '*.Foo.example', 'foo.example', 'FOO.EXAMPLE', '', 'bar.example'].join('\n'));
    const output = await tmpOutput();

    const summary = await main(['--url', 'https://x/list.txt', '--output', output], {}, { log() {} });
    expect(summary.domains).toBe(2);
  });

  it('throws when no valid domains are found', async () => {
    stubFetch(['# comment only', '   ', '.invalid.', 'a..b'].join('\n'));
    const output = await tmpOutput();

    await expect(main(['--url', 'https://x/list.txt', '--output', output], {}, { log() {} })).rejects.toThrow(
      /No valid blocklist domains/,
    );
  });

  it('rejects unknown CLI flags', async () => {
    await expect(main(['--bogus', 'x'], {}, { log() {} })).rejects.toThrow(/Unknown argument/);
  });

  it('requires --output', async () => {
    await expect(main([], {}, { log() {} })).rejects.toThrow(/--output is required/);
  });

  it('uses the default blocklist URLs when args and env omit URLs', async () => {
    const calls = [];
    vi.stubGlobal('fetch', async (url) => {
      calls.push(url);
      return new Response('default.example');
    });
    const output = await tmpOutput();

    const summary = await main(['--output', output], {}, { log() {} });

    expect(calls).toEqual(summary.sources);
    expect(summary.sources).toHaveLength(2);
    expect(summary.sources[0]).toContain('/pro-onlydomains.txt');
    expect(summary.sources[1]).toContain('/tif-onlydomains.txt');
    expect(summary.domains).toBe(1);
  });

  it('splits BLOCKLIST_URL env on commas and whitespace', async () => {
    const calls = [];
    vi.stubGlobal('fetch', async (url) => {
      calls.push(url);
      return new Response(new URL(url).hostname);
    });
    const output = await tmpOutput();
    const env = {
      BLOCKLIST_URL: 'https://a.example/list.txt, https://b.example/list.txt\nhttps://c.example/list.txt',
    };

    const summary = await main(['--output', output], env, { log() {} });

    expect(calls).toEqual(['https://a.example/list.txt', 'https://b.example/list.txt', 'https://c.example/list.txt']);
    expect(summary.domains).toBe(3);
  });

  it('throws when upstream returns non-2xx', async () => {
    vi.stubGlobal('fetch', async () => new Response('', { status: 500 }));
    const output = await tmpOutput();

    await expect(main(['--url', 'https://x/list.txt', '--output', output], {}, { log() {} })).rejects.toThrow(
      /blocklist fetch .* failed: 500/,
    );
  });

  it('throws when upstream Content-Length exceeds the source size cap', async () => {
    const tooBig = 26 * 1024 * 1024;
    vi.stubGlobal('fetch', async () => new Response('x', { headers: { 'Content-Length': String(tooBig) } }));
    const output = await tmpOutput();

    await expect(main(['--url', 'https://x/list.txt', '--output', output], {}, { log() {} })).rejects.toThrow(
      /too large/,
    );
  });

  it('throws when downloaded source body exceeds the source size cap', async () => {
    vi.stubGlobal('fetch', async () => ({
      ok: true,
      headers: { get: () => null },
      arrayBuffer: async () => new ArrayBuffer(26 * 1024 * 1024),
    }));
    const output = await tmpOutput();

    await expect(main(['--url', 'https://x/list.txt', '--output', output], {}, { log() {} })).rejects.toThrow(
      /too large/,
    );
  });

  it('throws when serialized Bloom JSON exceeds the KV value cap', async () => {
    stubFetch('oversized.example');
    vi.spyOn(Buffer, 'byteLength').mockReturnValue(26 * 1024 * 1024);
    const output = await tmpOutput();

    await expect(main(['--url', 'https://x/list.txt', '--output', output], {}, { log() {} })).rejects.toThrow(
      /Bloom JSON exceeds KV value limit/,
    );
  });

  it('runs main when loaded as the script entrypoint', async () => {
    const originalArgv = process.argv;
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const output = await tmpOutput();
    process.argv = [process.execPath, scriptPath, '--url', 'data:text/plain,cli.example', '--output', output];

    try {
      await import(/* @vite-ignore */ `file://${scriptPath}?entrypoint=${Date.now()}`);
    } finally {
      process.argv = originalArgv;
    }

    const filter = BloomFilter.fromJSON(JSON.parse(await readFile(output, 'utf8')));
    expect(filter.has('cli.example')).toBe(true);
    expect(log).toHaveBeenCalled();
  });
});

function stubFetch(body) {
  vi.stubGlobal('fetch', async () => new Response(body));
}

async function tmpOutput() {
  const dir = await mkdtemp(join(tmpdir(), 'build-bloom-'));
  return join(dir, 'blocklist-bloom.json');
}
