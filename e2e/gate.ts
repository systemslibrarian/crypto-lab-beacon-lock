import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaces
 *     pushed `*{animation:none!important;transition:none!important}` through
 *     `addStyleTag` before each of its four scans, then forced `open = true` on
 *     every `<details>`, stripped every `[hidden]` attribute, and added
 *     `.active/.is-active/.open` to anything it could find. This lab has nine
 *     collapsed `<details class="expert">` blocks and a `.live:empty
 *     { display: none }` rule, so that produced a document with every expert
 *     aside expanded at once — one no visitor can reach. Suppressing motion
 *     with a style tag also BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *
 *  2. IT DROVE THE WHOLE LAB AND SCANNED TWICE PER THEME. Every exhibit was
 *     walked — two ciphertexts locked, a round verified, all eight mechanism
 *     steps, both comparison selects, all nine attacks — and then one axe pass
 *     ran on whatever happened to be on screen last. The nine attacks in
 *     particular were selected in a `for` loop with no scan between them, so
 *     eight of the nine result renderings never existed for the oracle at all —
 *     including the only one that renders as an ALARM rather than as a
 *     rejection. Here every step is scanned in its own right.
 *
 *  3. THE BEACON IS PAUSED FOR THE WHOLE DRIVE. `state.start()` runs on load
 *     and a `setInterval` advances the round every second, re-rendering the
 *     clock face, the published-round list, the vault, every progress meter and
 *     the outage stats each time. A scan taken while that is running measures a
 *     document that has already changed. `boot` pauses it before the first
 *     scan and the drive moves the beacon only with the fast-forward button, so
 *     every state below is one a visitor can hold still and read.
 *
 *  4. ASSERT THE DEFAULTS, NEVER ASSUME THEM. `boot` pins down what this lab
 *     ships with — the beacon running and unhalted, the vault empty, the
 *     mechanism on step 1 of 8, the interop check already green, the comparison
 *     at 1× hardware, and the chain unchained. A gate that assumes the wrong
 *     half scans the wrong half.
 *
 *  5. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for the page to hold still: no running animations, and no scrolling.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * Scroll position is part of "held still" because this lab scrolls itself: the
 * exhibit navigator's `<select>` calls `scrollIntoView({ behavior: 'smooth' })`,
 * which is a JS-initiated scroll and keeps animating regardless of the
 * reduced-motion preference — and does not appear in `document.getAnimations()`.
 * Measuring contrast while the document is still moving reads rects that are
 * stale by the time the ancestor walk uses them.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number; __lastY?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      const still = running.length === 0 && w.__lastY === window.scrollY;
      w.__lastY = window.scrollY;
      w.__quietFrames = still ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * block collapses durations to `0.001ms` rather than setting `animation: none`,
 * which is the safe form — a cancelled animation loses its end state, a
 * zero-length one still lands on it. That is a fact about this stylesheet, and
 * this assertion is what keeps it true on every scan.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, pause
 * the beacon, and assert this lab's real starting state before anything is
 * driven.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 *
 * Pausing is asserted too, not merely requested. Everything after this depends
 * on the round number holding still, and a Pause that silently failed would
 * turn every later assertion into a race rather than a failure.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is built by `src/main.ts` into `#exhibits` and `#labnav`,
  // and the beacon is already ticking — so unlike most labs in this fleet there
  // IS content at first paint, and it is moving.
  await expect(page.locator('#exhibits .panel')).toHaveCount(8);
  await expect(page.locator('.labnav-link')).toHaveCount(8);
  await expect(page.locator('.clock-state')).toContainText('ticking every');

  // Stop the clock. Every state the drive builds afterwards is one a visitor
  // can hold still and read, and every round number below is deterministic.
  await page.getByRole('button', { name: 'Pause' }).click();
  await expect(page.locator('.clock-state')).toHaveText('paused');
  const round = Number(await page.locator('#clock-round').textContent());
  expect(round, 'the beacon must have published at least one round').toBeGreaterThan(0);
  await expect(page.locator('#clock-round')).toHaveText(String(round));

  // Defaults, asserted rather than assumed.
  await expect(page.locator('.vault .vault-item')).toHaveCount(0);
  await expect(page.locator('#lock')).toContainText('Nothing locked yet.');
  await expect(page.locator('#clock-scheme')).toHaveValue('unchained');
  await expect(page.locator('#clock-speed')).toHaveValue('1000');
  await expect(page.locator('#lock-ahead')).toHaveValue('8');
  await expect(page.locator('#cmp-speed')).toHaveValue('0');
  await expect(page.locator('#cmp-delay')).toHaveValue('86400');
  await expect(page.locator('#cmp-parties')).toHaveValue('1');
  await expect(page.locator('.stepcard-count')).toHaveText('Step 1 of 8');
  await expect(page.getByRole('button', { name: 'Halt the beacon', exact: true })).toBeVisible();

  // Two results already exist at first paint, and both are load-bearing: the
  // interop check runs on mount, and the attack panel runs its first entry.
  await expect(page.locator('#interop .verdict-ok')).toBeVisible();
  await expect(page.locator('#attack .verdict')).toBeVisible();

  // Nothing is expanded. If this ever fails, the gate is scanning a document a
  // visitor cannot reach — which is exactly what the gate it replaces did.
  await expect(page.locator('details.expert')).toHaveCount(9);
  await expect(page.locator('details.expert[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender at 380px: it prints 1152-hex-digit GT elements, a
 * `min-width: 34rem` SVG chart, an eight-link sticky navigator, a comparison
 * table and a stepper track of eight dots.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab is full of the same
    // decoy: `.chart-host` wraps a chart that is 34rem wide by design, and
    // every `.hexblock` and `.tablewrap` is a scroller around content far
    // wider than a phone.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * Several of this lab's scrollers only overflow once content exists — the
 * vault's `.hexblock`s and the mechanism's `.hexblock-tall` pairing dumps do
 * not exist until something is locked or stepped to — so a gate that scans a
 * pristine page cannot see them.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Every text-entry control's boundary must reach 3:1 against BOTH the surface
 * beside it and its own fill (WCAG 1.4.11).
 *
 * axe has no rule for border-vs-surface, and this lab's `--control-border` token
 * exists specifically to satisfy it — a token with no gate is a token that
 * drifts. Carried over from the spec this replaces, which is the one part of it
 * that was doing real work, and now run on every scan rather than twice on a
 * pristine page: several of these controls do not exist until something is
 * locked.
 */
export async function expectControlBorders(page: Page, label: string): Promise<void> {
  const weak = await page.evaluate(() => {
    interface C {
      r: number;
      g: number;
      b: number;
      a: number;
    }
    const parse = (s: string): C => {
      const m = s.match(/rgba?\(([^)]+)\)/);
      if (!m || m[1] === undefined) return { r: 0, g: 0, b: 0, a: 0 };
      const p = m[1].split(/[,\s/]+/).map(parseFloat);
      return { r: p[0] ?? 0, g: p[1] ?? 0, b: p[2] ?? 0, a: p.length > 3 ? (p[3] ?? 1) : 1 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const [hi, lo] = lum(a) > lum(b) ? [lum(a), lum(b)] : [lum(b), lum(a)];
      return (hi + 0.05) / (lo + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i] as C, out);
      return out;
    };
    const bad: string[] = [];
    document
      .querySelectorAll<HTMLElement>("select, textarea, input[type='text'], input[type='range']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        const cs = getComputedStyle(el);
        if (parseFloat(cs.borderTopWidth) === 0) return;
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const border = over(over(parse(cs.borderTopColor), fill), outside);
        const worst = Math.min(ratio(border, outside), ratio(border, fill));
        if (Math.round(worst * 100) / 100 < 3)
          bad.push(
            `${Math.round(worst * 100) / 100}:1 ${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}`
          );
      });
    return bad;
  });
  expect(
    Array.from(new Set(weak)),
    `control boundaries under 3:1 (WCAG 1.4.11) in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set fails at the end via
 * `reportCollected`, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function softly(run: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return run();
  try {
    await run();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — `expectNotBlank`, above.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result axe
 *    simply could not finish — including `aria-prohibited-attr`, which is where
 *    an `aria-label` on a role-less `<div>` hides, a defect that never reaches
 *    the violations array at all. This lab hangs `aria-label` on a lot of divs
 *    (`.hexblock`, `.tablewrap`, `.meter-track`, every live region), each with
 *    an explicit `role`; this assertion keeps that pairing honest.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    including the chart's SVG labels, which take their ink from `fill`.
 *  - control boundaries — WCAG 1.4.11 over every field's border.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await softly(() => expectControlBorders(page, label));
  await softly(() => expectScrollersReachable(page, label));
  await softly(() => expectNoHorizontalOverflow(page, label));
  await expectNoNewNonTextFailures(page, label);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Four things shape the order:
 *
 *  - THE BEACON MOVES ONLY WHEN THE DRIVE MOVES IT. `boot` paused it; every
 *    round below advances through the fast-forward button, so "8 rounds to go"
 *    means what it says and the vault's progress meters are reproducible.
 *
 *  - ONE VAULT, MANY OUTCOMES, AND THEY OVERWRITE EACH OTHER. Each locked item
 *    owns one live region, and "Open with round n", "Force it with the latest
 *    signature" and a later halt all write into it. The gate this replaces
 *    clicked several in a row and scanned once at the end, so the too-early
 *    refusal, the wrong-signature rejection and the stranded verdict were each
 *    destroyed before anything measured them — and they use three different
 *    tones (`locked`, `ok`, `alarm`) out of the palette's five.
 *
 *  - THE NINE ATTACKS OVERWRITE EACH OTHER TOO, AND ONE OF THEM IS THE POINT.
 *    Eight render as `ok` because a refusal is the system holding; the ninth —
 *    the beacon operator signing early — renders as `alarm` even though
 *    decryption succeeded. A `for` loop with no scan between iterations threw
 *    away eight of the nine, and which one survived depended on iteration order.
 *
 *  - THE DESTRUCTIVE STATES GO LAST. Switching the chain scheme and resetting
 *    the lab both discard the vault and bump `chainEpoch`, which retires the
 *    beacon panel's verification and the lock panel's receipt. Those retirement
 *    renderings are themselves states worth scanning, so they are driven — but
 *    after everything that needs a populated vault.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);
  const byName = (name: string | RegExp) => page.getByRole('button', { name });
  // Every panel writes into a `liveRegion`, and several own more than one, so
  // results are addressed by the region's own accessible name rather than by
  // "the first verdict in the panel" — which quietly picks up whichever
  // neighbouring region happens to render first.
  const live = (name: string) => page.locator(`[aria-label="${name}"]`);
  // The vault names each item's live region after the item, so it is addressed
  // by prefix rather than by exact name.
  const vaultResult = () => page.locator('[aria-label^="Result for "]');

  await scanAt('first paint, beacon paused');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('skip link focused');

  // ── Lock something, and try to open it before its time ───────────────────
  await page.locator('#lock-ahead').fill('8');
  await byName('Lock it').click();
  await expect(live('Lock result').locator('.verdict-locked')).toBeVisible();
  await expect(page.locator('.vault-item')).toHaveCount(1);
  await scanAt('lock — one ciphertext locked 8 rounds out');

  await byName(/^Open with round/).click();
  await expect(vaultResult().first().locator('.verdict-locked')).toContainText(
    'Nothing to decrypt with'
  );
  await scanAt('lock — opened too early, nothing to decrypt with');

  await byName('Force it with the latest signature').click();
  await expect(vaultResult().first().locator('.verdict-ok')).toContainText(
    'Rejected — as it should be'
  );
  await scanAt('lock — a genuine signature for the wrong round, rejected');

  // The refusal path for an empty message, which is the only state in which the
  // lock panel's `warn` tone renders at all.
  await page.locator('#lock-message').fill('');
  await byName('Lock it').click();
  await expect(live('Lock result').locator('.verdict-warn')).toContainText('Nothing to lock');
  await scanAt('lock — refused an empty message');

  // A second ciphertext, from a different preset and a different distance, so
  // the vault renders two cards in two different states.
  await page.locator('#lock-preset').selectOption('2');
  await expect(page.locator('#lock-message')).not.toBeEmpty();
  await page.locator('#lock-ahead').fill('30');
  await byName('Lock it').click();
  await expect(page.locator('.vault-item')).toHaveCount(2);
  await scanAt('lock — two ciphertexts, 8 and 30 rounds out');

  // ── Move the clock, and open one for real ────────────────────────────────
  await byName('Fast-forward 10 rounds').click();
  await expect(page.locator('.vault-item.is-ready').first()).toBeVisible();
  await scanAt('lock — the nearer round has arrived, one item ready');

  await byName(/^Open with round/).last().click();
  await expect(page.locator('.vault-item.is-open .plaintext')).toBeVisible();
  await expect(page.locator('.vault-item.is-open .verdict-ok')).toContainText('Opened');
  await scanAt('lock — opened with the beacon’s own signature');

  // ── The beacon ───────────────────────────────────────────────────────────
  await page.locator('#beacon').getByRole('button', { name: 'Verify' }).first().click();
  await expect(live('Verification result').locator('.hexdiff-equal')).toBeVisible();
  await expect(live('Verification result').locator('.verdict-ok')).toContainText(
    'Signature valid'
  );
  await scanAt('beacon — a round verified, both pairings printed');

  await page.locator('#clock-speed').selectOption('3000');
  await expect(page.locator('.clock-state')).toHaveText('paused');
  await scanAt('beacon — tick rate set to real quicknet speed');

  // ── The mechanism, one step at a time ────────────────────────────────────
  for (let i = 2; i <= 8; i++) {
    await byName('Next step').click();
    await expect(page.locator('.stepcard-count')).toHaveText(`Step ${i} of 8`);
    await scanAt(`mechanism — step ${i} of 8`);
  }
  await expect(byName('Done')).toBeDisabled();

  await page.locator('.mechanism-back, #mechanism').getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.locator('.stepcard-count')).toHaveText('Step 7 of 8');
  await scanAt('mechanism — stepped back to 7');

  await byName('Fresh randomness').click();
  await expect(page.locator('.stepcard-count')).toHaveText('Step 7 of 8');
  await scanAt('mechanism — replayed on a fresh key and a fresh r');

  await byName('Jump to the comparison').click();
  await expect(page.locator('.stepcard-count')).toHaveText('Step 7 of 8');
  await expect(page.locator('#mechanism .stepbody .hexdiff-equal')).toBeVisible();
  await scanAt('mechanism — jumped to the pairing comparison');

  await byName('Open the reference ciphertext').click();
  await expect(live('Interop check result').locator('.verdict-ok')).toBeVisible();
  await scanAt('interop — a drand reference ciphertext opened');

  // ── The comparison, at both ends of every control ────────────────────────
  await page.locator('#cmp-speed').fill('6');
  await expect(page.locator('#compare .compare-summary')).toContainText('1.0M× hardware');
  await scanAt('compare — adversary hardware at one million×');

  await page.locator('#cmp-delay').selectOption('31557600');
  await page.locator('#cmp-parties').selectOption('1000');
  await scanAt('compare — a one-year delay for a thousand recipients');

  await byName('Back to 1×').click();
  await expect(page.locator('#cmp-speed')).toHaveValue('0');
  await scanAt('compare — back to 1× hardware');

  // ── All nine attacks, each measured before the next replaces it ──────────
  const choices = await page
    .locator('#attack-choice option')
    .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value));
  expect(choices, 'the attack list must be the nine the panel claims').toHaveLength(9);
  for (const value of choices) {
    await page.locator('#attack-choice').selectOption(value);
    await expect(live('Attack result').locator('.verdict')).toBeVisible();
    await scanAt(`attack — ${value}`);
  }

  // The one that succeeds, re-run through the button rather than the select, so
  // the explicit "run it" path is exercised too. It renders as an ALARM even
  // though decryption returned a plaintext.
  await page.locator('#attack-choice').selectOption('operator');
  await byName('Run it against the real decryptor').click();
  await expect(live('Attack result').locator('.verdict-alarm')).toContainText('Opened early');
  await scanAt('attack — the operator signs early, and it works');

  // ── The outage: halt the beacon and strand what is left ──────────────────
  const outage = page.locator('#outage');
  await outage.getByRole('button', { name: 'Halt the beacon now' }).click();
  await expect(live('Outage status').locator('.verdict-alarm')).toBeVisible();
  await expect(page.locator('.vault-item.is-stranded').first()).toBeVisible();
  await scanAt('outage — beacon halted, a ciphertext stranded');

  await page.locator('.vault-item.is-stranded').first().getByRole('button', { name: /^Open with round/ }).click();
  await expect(page.locator('.vault-item.is-stranded .verdict-alarm')).toContainText('Stranded');
  await scanAt('outage — the stranded item reports why it will never open');

  // The comparison picks the outage up: the beacon curve becomes "never".
  await expect(page.locator('#compare .legend-note', { hasText: 'halted' })).toBeVisible();
  await scanAt('compare — with the beacon dead, its curve never opens');

  await outage.getByRole('button', { name: 'Restart the beacon' }).click();
  await expect(live('Outage status').locator('.verdict-ok')).toContainText('Beacon running');
  await scanAt('outage — beacon restarted');

  // Halting with nothing waiting is a third, separate rendering of this panel.
  await byName('Fast-forward 10 rounds').click();
  await byName('Fast-forward 10 rounds').click();
  await byName('Fast-forward 10 rounds').click();
  await byName(/^Open with round/).first().click();
  await outage.getByRole('button', { name: 'Halt the beacon now' }).click();
  await expect(live('Outage status').locator('.verdict-warn')).toContainText('nothing stranded');
  await scanAt('outage — halted with nothing left waiting');
  await outage.getByRole('button', { name: 'Restart the beacon' }).click();

  // ── Every disclosure, opened by clicking its own summary ─────────────────
  const summaries = page.locator('#exhibits details.expert > summary');
  const total = await summaries.count();
  for (let i = 0; i < total; i++) {
    await summaries.nth(i).click();
    await expect(page.locator('#exhibits details.expert[open]')).toHaveCount(i + 1);
    await scanAt(`expert disclosure ${i + 1} of ${total} open`);
  }

  // ── The exhibit navigator, in whichever form this viewport shows ─────────
  const menu = page.locator('.labnav-select');
  if (await menu.isVisible()) {
    await menu.selectOption('attack');
    await scanAt('navigator — the attack exhibit reached through the narrow menu');
  } else {
    await page.locator('.labnav-link[href="#attack"]').click();
    await expect(page.locator('.labnav-link.is-current')).toBeVisible();
    await scanAt('navigator — attack link followed, current link marked');
  }

  // ── Destructive last: a chained chain cannot address the future ──────────
  await page.locator('#clock-scheme').selectOption('chained');
  await expect(page.locator('#clock-future .verdict-alarm')).toBeVisible();
  await expect(page.locator('.vault-item')).toHaveCount(0);
  // Switching the chain bumps chainEpoch, which retires the verification the
  // beacon panel was showing rather than letting it outlive its key pair.
  await expect(live('Verification result').locator('.verdict-idle')).toContainText(
    'Verification cleared'
  );
  await scanAt('beacon — chained scheme, the future has no address');

  await page.locator('#clock-scheme').selectOption('unchained');
  await expect(page.locator('#clock-future .verdict-ok')).toBeVisible();
  await scanAt('beacon — back to unchained, the future is addressable again');

  await byName('Reset lab').click();
  // Reset restarts the clock, so pause it again before measuring anything.
  await byName('Pause').click();
  await expect(page.locator('.clock-state')).toHaveText('paused');
  await expect(page.locator('.vault-item')).toHaveCount(0);
  await scanAt('lab reset from the navigator');

  reportCollected();
}
