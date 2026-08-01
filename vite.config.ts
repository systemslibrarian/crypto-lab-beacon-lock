import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: '/crypto-lab-beacon-lock/',
  test: {
    // Colocated unit tests only — keeps the Playwright a11y specs in e2e/ out
    // of the Vitest run.
    include: ['src/**/*.test.ts'],
  },
})
