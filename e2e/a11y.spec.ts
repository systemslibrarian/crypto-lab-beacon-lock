/**
 * WCAG 2.1 A/AA gate, run by axe against the production build in BOTH themes.
 *
 * Axe only checks what is in the DOM, so an unscanned state is an ungated
 * state. This spec therefore drives the whole lab rather than scanning the
 * landing view, and it scans each theme twice:
 *
 *   pass 1 — the healthy states: a ciphertext opened, a signature verified,
 *            every attack rejected, the beacon running.
 *   pass 2 — the failure states: a stranded ciphertext, a halted beacon, a
 *            chained chain refusing to address the future, an early-signed
 *            ciphertext rendered as an alarm.
 *
 * Those two sets use different colours and different live regions, which is
 * exactly where contrast and live-region violations hide.
 */

import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/** Freeze motion and reveal anything collapsed or hidden before a scan. */
async function reveal(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  })
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true))
    document.querySelectorAll<HTMLElement>('[hidden],[role="tabpanel"]').forEach((el) => {
      el.removeAttribute('hidden')
      el.style.display = ''
      el.classList.add('active', 'is-active', 'open')
    })
  })
}

async function scan(page: Page, label: string): Promise<void> {
  await reveal(page)
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(
    violations.map((v) => ({
      state: label,
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([])
}

/**
 * The beacon ticks on a timer, which would move results under the scan. Pause
 * it first and drive it with the fast-forward button instead, so every state
 * below is deterministic.
 */
async function settle(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Pause' }).click()
  await expect(page.locator('#clock-round')).toBeVisible()
}

/** Pass 1 — everything on screen is behaving. */
async function driveHealthy(page: Page): Promise<void> {
  await settle(page)

  // Lock two ciphertexts: one close enough to reach, one that stays shut.
  await page.locator('#lock-ahead').fill('2')
  await page.getByRole('button', { name: 'Lock it' }).click()
  await expect(page.locator('#lock .verdict-locked').first()).toBeVisible()

  await page.locator('#lock-preset').selectOption('1')
  await page.locator('#lock-ahead').fill('30')
  await page.getByRole('button', { name: 'Lock it' }).click()

  // The too-early path, then the wrong-signature rejection, then the opening.
  await page.getByRole('button', { name: /^Open with round/ }).last().click()
  await page.getByRole('button', { name: 'Force it with the latest signature' }).first().click()
  await expect(page.locator('#lock .verdict').first()).toBeVisible()

  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  await page.getByRole('button', { name: /^Open with round/ }).last().click()
  await expect(page.locator('#lock .plaintext').first()).toBeVisible()

  // Beacon: verify a round so the two GT elements and the pass verdict render.
  await page.locator('#beacon').getByRole('button', { name: 'Verify' }).first().click()
  await expect(page.locator('#beacon .hexdiff-equal')).toBeVisible()

  // Mechanism: walk every step, back once, then land on the comparison.
  for (let i = 0; i < 7; i++) {
    await page.getByRole('button', { name: 'Next step' }).click()
  }
  await page.getByRole('button', { name: 'Back', exact: true }).click()
  await page.getByRole('button', { name: 'Fresh randomness' }).click()
  await page.getByRole('button', { name: 'Jump to the comparison' }).click()
  await expect(page.locator('#mechanism .hexdiff-equal')).toBeVisible()

  // Comparison: exercise both selects, the slider, and the reset.
  await page.locator('#cmp-delay').selectOption('31557600')
  await page.locator('#cmp-parties').selectOption('1000')
  await page.locator('#cmp-speed').fill('4.5')
  await expect(page.locator('#compare .chart')).toBeVisible()
  await page.getByRole('button', { name: 'Back to 1×' }).click()

  // Attacks: run every one, then leave a rejection on screen.
  const attack = page.locator('#attack-choice')
  for (const value of await attack
    .locator('option')
    .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))) {
    await attack.selectOption(value)
    await expect(page.locator('#attack .verdict')).toBeVisible()
  }
  await attack.selectOption('wrong-round')
  await page.getByRole('button', { name: 'Run it against the real decryptor' }).click()
  await expect(page.locator('#attack .verdict-ok')).toBeVisible()
}

/** Pass 2 — the failure states, which use a different palette entirely. */
async function driveFailures(page: Page): Promise<void> {
  // The attack that succeeds — rendered as an alarm, not as success.
  await page.locator('#attack-choice').selectOption('operator')
  await expect(page.locator('#attack .verdict-alarm')).toBeVisible()

  // A chained chain cannot address the future. This also resets the vault, so
  // re-lock afterwards to have something to strand.
  await page.locator('#clock-scheme').selectOption('chained')
  await expect(page.locator('#beacon .verdict-alarm')).toBeVisible()
  await page.locator('#clock-scheme').selectOption('unchained')

  await page.locator('#lock-preset').selectOption('2')
  await page.locator('#lock-ahead').fill('25')
  await page.getByRole('button', { name: 'Lock it' }).click()

  // Halt the beacon from the outage exhibit and strand it.
  await page.getByRole('button', { name: 'Halt the beacon now' }).click()
  await expect(page.locator('#outage .verdict-alarm')).toBeVisible()
  await expect(page.locator('#lock .vault-item.is-stranded').first()).toBeVisible()

  // A stranded item reports "stranded" rather than "too early".
  await page.getByRole('button', { name: /^Open with round/ }).first().click()
  await expect(page.locator('#lock .verdict-alarm').first()).toBeVisible()

  // The comparison picks the outage up: the beacon curve becomes "never".
  await expect(page.locator('#compare .chart')).toBeVisible()

  // The slowest tick rate and the reset control, for completeness.
  await page.locator('#clock-speed').selectOption('3000')
  await page.getByRole('button', { name: 'Reset lab' }).click()
  await page.getByRole('button', { name: 'Pause' }).click()
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.')
  await driveHealthy(page)
  await scan(page, 'dark / healthy')
  await driveFailures(page)
  await scan(page, 'dark / failures')
})

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.')
  await page.locator('#cl-theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await driveHealthy(page)
  await scan(page, 'light / healthy')
  await driveFailures(page)
  await scan(page, 'light / failures')
})
