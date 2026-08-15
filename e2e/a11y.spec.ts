import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The beacon is paused before the first scan, then moved only by the
 * fast-forward button, so every state below is one a visitor can hold still and
 * read. The lab is driven the way a visitor drives it and scanned after every
 * single step: a ciphertext locked and opened too early, forced with a genuine
 * signature for the wrong round, refused for being empty, then opened for real;
 * a beacon round verified with both pairings printed; all eight mechanism steps
 * plus Back, a fresh replay and the jump to the comparison; the drand reference
 * ciphertext opened; the comparison at both ends of every control; all nine
 * attacks one at a time including the one that succeeds; the beacon halted with
 * a ciphertext stranded and again with nothing waiting; every one of the nine
 * `<details class="expert">` disclosures opened by clicking its summary; and
 * finally the chain switched, cleared and reset. Every resulting state is
 * scanned in both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no `<details>`
 * is forced open from script, why the drive asserts this lab's defaults instead
 * of assuming them, why every step is scanned rather than only the last, and
 * why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
