import { defineConfig } from '@playwright/test'

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Port 4604 is unique to this lab across the fleet, so a stray
 * `reuseExistingServer` never scans a different lab's preview.
 */
export default defineConfig({
  testDir: './e2e',
  // The gate is four independent configurations — {dark, light} x {1280, 380} —
  // and each one drives the whole lab from scratch. Without this Playwright
  // parallelises by FILE, so all four run in series in one worker and the gate
  // takes four times as long for no reason.
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4604/crypto-lab-beacon-lock/',
    // Pin the emulated scheme to dark so the default scan is the real dark
    // default and the shared-header toggle deterministically reaches light.
    colorScheme: 'dark',
  },
  webServer: {
    // Build first: `vite preview` only serves whatever is already in `dist/`.
    // Without the build, a source change that fails to compile leaves the last
    // good bundle in place and the suite passes green against code that no
    // longer builds — which silently invalidates mutation checks.
    command: 'npm run build && npm run preview -- --port 4604 --strictPort',
    url: 'http://localhost:4604/crypto-lab-beacon-lock/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
