import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],

    // Machine-readable run output alongside the human one. `npm run test:report` writes
    // reports/junit.xml and reports/test-results.json so a CI system can render per-test
    // results and trends rather than a pass/fail exit code.
    reporters: process.env.CI === 'true' || process.env.TEST_REPORT === 'true'
      ? ['default', 'junit', 'json']
      : ['default'],
    outputFile: {
      junit: './reports/junit.xml',
      json: './reports/test-results.json',
    },

    coverage: {
      provider: 'v8',
      reportsDirectory: './reports/coverage',
      reporter: ['text', 'text-summary', 'html', 'lcov', 'json-summary'],
      include: ['src/**/*.ts'],
      // Entry point and CLI presentation are exercised by scripts/demo.sh rather than by unit
      // tests; excluding them keeps the number honest instead of diluting it.
      exclude: ['src/index.ts', 'src/cli/**'],

      // Thresholds are a ratchet, set just under the current numbers. They exist to make a
      // coverage regression fail the build rather than to chase a target.
      thresholds: {
        statements: 90,
        branches: 82,
        functions: 90,
        lines: 90,
      },
    },
  },
});
