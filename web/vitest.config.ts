import { defineConfig, mergeConfig } from 'vitest/config'

import viteConfig from './vite.config'

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: ['./src/test-setup.ts'],
      exclude: ['e2e/**', 'node_modules/**'],
      coverage: {
        provider: 'v8',
        reporter: ['text', 'lcov'],
        // Unit coverage measures the logic modules. The screens are React
        // wiring over them, exercised end to end by Playwright, and counting
        // their JSX here would only reward render-and-snapshot tests.
        include: ['src/api/**/*.ts', 'src/lib/**/*.ts'],
        exclude: ['src/**/*.test.{ts,tsx}', 'src/lib/sessionContext.ts'],
        thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
      },
    },
  }),
)
