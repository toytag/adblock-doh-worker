import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// Two projects keep the worker runtime overhead off of pure helper tests.
//   worker — runs through @cloudflare/vitest-pool-workers (real Workers
//            runtime, miniflare-backed KV binding) for end-to-end tests.
//   node   — plain Node environment for pure helpers and the build script.
export default defineConfig({
  test: {
    projects: [
      {
        plugins: [cloudflareTest({ wrangler: { configPath: './wrangler.jsonc' } })],
        test: {
          name: 'worker',
          include: ['test/index.spec.js'],
        },
      },
      {
        test: {
          name: 'node',
          environment: 'node',
          include: [
            'test/blocklist.spec.js',
            'test/build-bloom.spec.js',
            'test/dns.spec.js',
          ],
        },
      },
    ],
  },
});
