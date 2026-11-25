import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // The global fetch answers nothing and fails the test that reached it.
    setupFiles: ['test/support/noRealNetwork.ts'],
    // craftedSnapshot.test.ts collects garbage between reads, so that the
    // process's peak memory measures one read at a time.
    execArgv: ['--expose-gc'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'html', 'json-summary'],
      thresholds: {
        'src/analyzers/**': { lines: 85 },
      },
    },
  },
});
