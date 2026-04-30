import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BloomFilter } from 'bloom-filters';

import { FALSE_POSITIVE_RATE, main } from '../scripts/build-bloom.js';

afterEach(() => vi.unstubAllGlobals());

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
});

function stubFetch(body) {
  vi.stubGlobal('fetch', async () => new Response(body));
}

async function tmpOutput() {
  const dir = await mkdtemp(join(tmpdir(), 'build-bloom-'));
  return join(dir, 'blocklist-bloom.json');
}
