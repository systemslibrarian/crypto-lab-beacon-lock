/**
 * Functional gate: the claims this lab makes on screen, asserted against the
 * rendered DOM of the production build.
 *
 * The a11y spec next door proves the page is perceivable. It never reads a
 * verdict, so before this file every headline on the page — "Opened", "Signature
 * valid", "Rejected", "N ciphertexts permanently locked" — could have been a
 * static string and the suite would still have been green.
 *
 * Three rules shape what is asserted here:
 *
 *   1. Never assert a verdict against a literal the source also contains.
 *      Where possible a value is checked against another value the PAGE
 *      computed by a different route — the plaintext against the textarea that
 *      produced it, the byte count against the byte stats beside it, the
 *      comparison summary against the comparison table, the nav round against
 *      the clock face.
 *   2. Every failure path must both REACH the failure state and NAME the cause.
 *      A red box that says nothing is not a demonstration.
 *   3. Counters must add up. Parts against the whole, in the panel that renders
 *      each part and again in the panel that renders the total.
 *
 * Two regressions are pinned at the bottom for bugs this file found: verdicts
 * that outlived the chain they described. See `chainEpoch` in `ui/state.ts`.
 */

import { expect, test, type Locator, type Page } from '@playwright/test'

/** The AES-256 key the timelock covers. The page states this size in prose. */
const AES_KEY_BYTES = 32

/** Collect uncaught page exceptions so any test can fail on them. */
function trackErrors(page: Page): string[] {
  const out: string[] = []
  page.on('pageerror', (e) => out.push(e.message))
  return out
}

/**
 * Load the lab with the beacon stopped.
 *
 * Everything downstream of `state.notify()` re-renders on every tick, so an
 * unpaused clock rebuilds the per-item live regions under the assertions and
 * moves the round numbers they are checked against.
 */
async function openLab(page: Page): Promise<void> {
  await page.goto('.')
  await page.waitForSelector('#lock-message')
  await page.getByRole('button', { name: 'Pause' }).click()
  await expect(page.getByRole('button', { name: 'Resume' })).toBeVisible()
}

/**
 * Mark every node matching `selector` as stale.
 *
 * Result regions here are cleared and repopulated rather than replaced, so a
 * bare `toBeVisible()` after an action happily re-reads the PREVIOUS result and
 * asserts nothing. Marking first, then waiting for an unmarked node, makes the
 * wait mean what it looks like it means.
 */
async function markStale(page: Page, selector: string): Promise<void> {
  await page
    .locator(selector)
    .evaluateAll((els) => els.forEach((el) => el.setAttribute('data-stale', '1')))
}

function fresh(page: Page, selector: string): Locator {
  return page.locator(`${selector}:not([data-stale])`)
}

/** Read a `.statrow` as a label -> value map. */
async function stats(scope: Locator): Promise<Record<string, string>> {
  return scope.locator('.stat').evaluateAll((els) => {
    const out: Record<string, string> = {}
    for (const el of els) {
      const label = el.querySelector('.stat-label')?.textContent?.trim()
      const value = el.querySelector('.stat-value')?.textContent?.trim()
      if (label) out[label] = value ?? ''
    }
    return out
  })
}

/** The comparison table as row-label -> [puzzle, vdf, beacon]. */
async function compareTable(page: Page): Promise<Record<string, string[]>> {
  return page.locator('#compare .datatable tbody tr').evaluateAll((trs) => {
    const out: Record<string, string[]> = {}
    for (const tr of trs) {
      const label = tr.querySelector('th')?.textContent?.trim() ?? ''
      out[label] = Array.from(tr.querySelectorAll('td')).map((td) => td.textContent?.trim() ?? '')
    }
    return out
  })
}

function firstGroup(text: string, re: RegExp): string {
  const m = text.match(re)
  expect(m, `no match for ${re} in: ${text}`).not.toBeNull()
  return m![1]!.trim()
}

/** Lock the message currently in the textarea, `ahead` rounds into the future. */
async function lock(page: Page, ahead: number): Promise<void> {
  await markStale(page, '#lock [aria-label="Lock result"] .verdict')
  await page.locator('#lock-ahead').fill(String(ahead))
  await page.getByRole('button', { name: 'Lock it' }).click()
  await expect(fresh(page, '#lock [aria-label="Lock result"] .verdict')).toBeVisible()
}

// ---------------------------------------------------------------------------
// The headline: a ciphertext locked to a future round, opened by that round.
// ---------------------------------------------------------------------------

test('a locked ciphertext opens to exactly the text that was locked', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  // A message the source does not contain, so nothing downstream can be a
  // hardcoded echo of a preset.
  const secret = 'sealed until the beacon says otherwise — 7f3a91'
  await page.locator('#lock-message').fill(secret)
  await lock(page, 3)

  const item = page.locator('#lock .vault-item').first()
  await expect(item.locator('.vault-badge')).toHaveText('3 rounds to go')

  // Before the round exists there is nothing to decrypt with, and the page
  // must say so in those terms rather than calling it a rejection.
  await markStale(page, '#lock .vault-item .verdict')
  await item.getByRole('button', { name: /^Open with round/ }).click()
  const early = fresh(page, '#lock .vault-item .verdict').first()
  await expect(early).toHaveClass(/verdict-locked/)
  await expect(early).toContainText('Nothing to decrypt with')
  await expect(early).toContainText('3 away')

  // Walk the beacon past the target round and open it for real.
  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  await markStale(page, '#lock .vault-item .verdict')
  await item.getByRole('button', { name: /^Open with round/ }).click()
  await expect(item.locator('.plaintext')).toBeVisible()

  // The verdict is checked against the value the page itself produced: the
  // recovered plaintext must equal the textarea that fed the encryptor.
  const typed = await page.locator('#lock-message').inputValue()
  await expect(item.locator('.plaintext')).toHaveText(typed)
  expect(typed).toBe(secret)

  await expect(item.locator('.verdict-ok')).toContainText('Opened')
  await expect(item.locator('.vault-badge')).toHaveText('open')

  expect(errors).toEqual([])
})

test('the wire size adds up from the byte stats printed beside it', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  const secret = 'a message of a length nothing in the source knows about'
  await page.locator('#lock-message').fill(secret)
  await lock(page, 5)

  const receipt = await page.locator('#lock [aria-label="Lock result"] .verdict').innerText()
  const wire = Number(firstGroup(receipt, /(\d+) bytes on the wire/))

  const s = await stats(page.locator('#lock .vault-item').first())
  const plaintext = Number(firstGroup(s['Plaintext'] ?? '', /(\d+) B/))
  const timelock = Number(firstGroup(s['Timelock overhead'] ?? '', /(\d+) B/))
  const aead = Number(firstGroup(s['AEAD overhead'] ?? '', /(\d+) B/))

  // The plaintext stat is the encoded length of what was typed, not a guess.
  expect(plaintext).toBe(new TextEncoder().encode(secret).length)

  // Parts against the whole: the timelock ciphertext carries the 32-byte AES
  // key plus its own overhead, and the envelope carries the text plus the AEAD
  // nonce and tag. Nothing else is on the wire.
  expect(wire).toBe(plaintext + timelock + aead + AES_KEY_BYTES)

  // And the target round the stats name is the one the receipt named.
  expect(s['Target round']).toBe(firstGroup(receipt, /Locked to round (\d+)/))
  expect(s['Identity']).toBe(`SHA-256(${s['Target round']})`)

  expect(errors).toEqual([])
})

// ---------------------------------------------------------------------------
// Failure paths. Each must reach the failure state AND name the cause.
// ---------------------------------------------------------------------------

test('every refusal path reaches its failure state and names the cause', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  // 1. Nothing to lock.
  await page.locator('#lock-message').fill('   ')
  await markStale(page, '#lock [aria-label="Lock result"] .verdict')
  await page.getByRole('button', { name: 'Lock it' }).click()
  const empty = fresh(page, '#lock [aria-label="Lock result"] .verdict').first()
  await expect(empty).toHaveClass(/verdict-warn/)
  await expect(empty).toContainText('type a message first')

  // 2. A genuine beacon signature for the wrong round, fed to the real
  //    decryptor. The refusal must name both rounds.
  await page.locator('#lock-message').fill('forced-open probe')
  await lock(page, 6)
  const item = page.locator('#lock .vault-item').first()
  const target = (await stats(item))['Target round']
  const round = await page.locator('#clock-round').innerText()

  await markStale(page, '#lock .vault-item .verdict')
  await item.getByRole('button', { name: 'Force it with the latest signature' }).click()
  const forced = fresh(page, '#lock .vault-item .verdict').first()
  await expect(forced).toContainText('Rejected')
  await expect(forced).toContainText(`round ${round}`)
  await expect(forced).toContainText(`round ${target}`)

  // 3. A halted beacon strands it — and says stranded, not "too early".
  await page.getByRole('button', { name: 'Halt the beacon now' }).click()
  await expect(page.locator('#lock .vault-item.is-stranded').first()).toBeVisible()
  await expect(item.locator('.vault-badge')).toHaveText('stranded')
  await markStale(page, '#lock .vault-item .verdict')
  await item.getByRole('button', { name: /^Open with round/ }).click()
  const stranded = fresh(page, '#lock .vault-item .verdict').first()
  await expect(stranded).toHaveClass(/verdict-alarm/)
  await expect(stranded).toContainText('Stranded')
  await expect(stranded).toContainText('halted')

  expect(errors).toEqual([])
})

test('a chained chain refuses the future in both panels that can say so', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  // Baseline: unchained can address the future, and the identity is a real
  // 32-byte digest rather than a placeholder.
  await expect(page.locator('#clock-future .verdict')).toHaveClass(/verdict-ok/)
  const target = firstGroup(
    await page.locator('#clock-future h3').innerText(),
    /round (\d+) today/,
  )
  const identity = (await page.locator('#clock-future .hexblock .hex').innerText()).trim()
  expect(identity).toMatch(/^[0-9a-f]{64}$/)

  await page.locator('#clock-scheme').selectOption('chained')

  // Surface one: the beacon panel says the identity does not exist yet, and
  // names the missing predecessor.
  const future = page.locator('#clock-future .verdict')
  await expect(future).toHaveClass(/verdict-alarm/)
  await expect(future).toContainText('does not exist')
  await expect(page.locator('#clock-future .hexblock .hex')).toContainText('undefined')

  // Surface two: the lock panel, running entirely different code, refuses to
  // produce a ciphertext at all — and gives the same reason.
  await page.locator('#lock-message').fill('cannot address the future on a chained chain')
  await markStale(page, '#lock [aria-label="Lock result"] .verdict')
  await page.locator('#lock-ahead').fill('8')
  await page.getByRole('button', { name: 'Lock it' }).click()
  const refused = fresh(page, '#lock [aria-label="Lock result"] .verdict').first()
  await expect(refused).toHaveClass(/verdict-warn/)
  await expect(refused).toContainText('Cannot lock')
  await expect(refused).toContainText('chained beacon has no message')
  await expect(page.locator('#lock .vault-item')).toHaveCount(0)

  // Switching back restores both, so neither surface is stuck.
  await page.locator('#clock-scheme').selectOption('unchained')
  await expect(page.locator('#clock-future .verdict')).toHaveClass(/verdict-ok/)
  await page.locator('#lock-message').fill('unchained again')
  await lock(page, 4)
  await expect(page.locator('#lock .vault-item')).toHaveCount(1)

  // The chain instance was replaced twice over, with a fresh master secret
  // each time, and the identity for the same round is byte-identical — which
  // is the property the whole exhibit turns on: an unchained identity is a
  // pure function of the round number, owing nothing to chain state.
  expect(firstGroup(await page.locator('#clock-future h3').innerText(), /round (\d+) today/)).toBe(
    target,
  )
  expect((await page.locator('#clock-future .hexblock .hex').innerText()).trim()).toBe(identity)

  expect(errors).toEqual([])
})

// ---------------------------------------------------------------------------
// Counters, and the panels that render the same count twice.
// ---------------------------------------------------------------------------

test('the nav readout and the clock face agree about the beacon', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  const agree = async () => {
    const nav = await page.locator('.labnav-status').innerText()
    const face = await page.locator('#clock-round').innerText()
    // Two independent renders of `state.round`, in two modules.
    expect(firstGroup(nav, /round (\d+)/)).toBe(face.trim())
    const stillLocked = Number(firstGroup(nav, /(\d+) still locked/))
    const openItems = await page.locator('#lock .vault-item.is-open').count()
    const allItems = await page.locator('#lock .vault-item').count()
    // Parts against the whole: every vault item is either opened or not.
    expect(stillLocked).toBe(allItems - openItems)
    return { nav, face }
  }

  await agree()
  await page.locator('#lock-message').fill('first')
  await lock(page, 2)
  await page.locator('#lock-message').fill('second')
  await lock(page, 20)
  await agree()

  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  await agree()

  // Open the reachable one; the counter must drop by exactly one.
  const before = Number(firstGroup(await page.locator('.labnav-status').innerText(), /(\d+) still locked/))
  await page.locator('#lock .vault-item.is-ready').first().getByRole('button', { name: /^Open with round/ }).click()
  await expect(page.locator('#lock .vault-item.is-open')).toHaveCount(1)
  const after = Number(firstGroup(await page.locator('.labnav-status').innerText(), /(\d+) still locked/))
  expect(after).toBe(before - 1)
  await agree()

  expect(errors).toEqual([])
})

test('the outage panel counts exactly the ciphertexts the vault marks stranded', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  // Three items: one reachable and opened, two beyond any round the beacon
  // will reach once it is halted.
  await page.locator('#lock-message').fill('reachable')
  await lock(page, 2)
  await page.locator('#lock-message').fill('far one')
  await lock(page, 25)
  await page.locator('#lock-message').fill('far two')
  await lock(page, 28)

  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  await page.locator('#lock .vault-item.is-ready').first().getByRole('button', { name: /^Open with round/ }).click()
  await expect(page.locator('#lock .vault-item.is-open')).toHaveCount(1)

  await page.getByRole('button', { name: 'Halt the beacon now' }).click()

  const strandedCards = await page.locator('#lock .vault-item.is-stranded').count()
  expect(strandedCards).toBe(2)

  const s = await stats(page.locator('#outage'))
  // The outage panel's own counter, computed from state rather than from the DOM.
  expect(Number(s['Ciphertexts waiting'])).toBe(strandedCards)
  expect(s['Beacon']).toContain('halted at round')
  expect(s['Recoverable by brute force']).toBe('none')

  // And its headline verdict repeats the count a third time, through a third
  // code path, alongside a list with one entry per stranded item.
  const alarm = page.locator('#outage .verdict-alarm')
  await expect(alarm).toContainText(`${strandedCards} ciphertexts permanently locked`)
  await expect(page.locator('#outage .live li')).toHaveCount(strandedCards)

  // Every listed item names the round that will never be signed, and that
  // round is the one its vault card advertises.
  const listed = await page.locator('#outage .live li').allInnerTexts()
  const cardRounds = await page
    .locator('#lock .vault-item.is-stranded')
    .evaluateAll((cards) =>
      cards.map((c) =>
        Array.from(c.querySelectorAll('.stat'))
          .filter((s) => s.querySelector('.stat-label')?.textContent?.trim() === 'Target round')
          .map((s) => s.querySelector('.stat-value')?.textContent?.trim())[0],
      ),
    )
  expect(cardRounds).toHaveLength(strandedCards)
  for (const round of cardRounds) {
    expect(listed.some((l) => l.includes(`needed round ${round}`))).toBe(true)
  }

  // The beacon is halted at a round strictly below every stranded target.
  const haltedAt = Number(firstGroup(s['Beacon'] ?? '', /halted at round (\d+)/))
  for (const round of cardRounds) expect(Number(round)).toBeGreaterThan(haltedAt)

  expect(errors).toEqual([])
})

// ---------------------------------------------------------------------------
// The comparison exhibit: five renderings of the same two durations.
// ---------------------------------------------------------------------------

test('the comparison summary, chart label, caption and table agree', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  const read = async () => {
    const summary = await page.locator('.compare-summary').innerText()
    const aria = (await page.locator('#compare .chart').getAttribute('aria-label')) ?? ''
    const caption = await page.locator('#compare .chart-caption').innerText()
    const table = await compareTable(page)
    return {
      summaryPuzzle: firstGroup(summary, /puzzle opens in ([^.]+)\./),
      summaryBeacon: firstGroup(summary, /beacon lock opens in (.+?) —/),
      ariaFrom: firstGroup(aria, /fall in exact proportion to hardware, from (.+?) down to/),
      ariaDownTo: firstGroup(aria, /down to (.+?)\./),
      ariaBeacon: firstGroup(aria, /beacon timelock stays at (.+?) across/),
      captionDelay: firstGroup(caption, /both are (.+?) divided by hardware/),
      tablePuzzle: table['Opens after']![0]!,
      tableVdf: table['Opens after']![1]!,
      tableBeacon: table['Opens after']![2]!,
      table,
    }
  }

  // At 1x every surface is describing the same delay, five different ways.
  await page.locator('#cmp-speed').fill('0')
  const base = await read()
  expect(base.summaryPuzzle).toBe(base.tablePuzzle)
  expect(base.summaryBeacon).toBe(base.tableBeacon)
  expect(base.ariaBeacon).toBe(base.tableBeacon)
  expect(base.captionDelay).toBe(base.tableBeacon)
  expect(base.ariaFrom).toBe(base.tablePuzzle)
  // The puzzle and the VDF share a line exactly; the exhibit's prose says so.
  expect(base.tableVdf).toBe(base.tablePuzzle)

  // Parts against the whole at one interested party: nobody else grinds, so
  // total work equals the critical path for both compute-bound models.
  expect(base.table['Work burned across 1 interested party']![0]).toBe(
    base.table['Sequential work on the critical path']![0],
  )
  expect(base.table['Work burned across 1 interested party']![1]).toBe(
    base.table['Sequential work on the critical path']![1],
  )
  // The beacon does no work at all, on any row.
  expect(base.table['Sequential work on the critical path']![2]).toBe('0 squarings')
  expect(base.table['Work burned across 1 interested party']![2]).toBe('0 squarings')

  // The headline claim of the exhibit: turn the adversary's hardware up a
  // millionfold and the beacon answer does not move, while the puzzle does.
  await page.locator('#cmp-speed').fill('6')
  await expect(page.locator('.compare-summary')).toContainText('1.0M×')
  const fast = await read()
  expect(fast.tableBeacon).toBe(base.tableBeacon)
  expect(fast.summaryBeacon).toBe(base.summaryBeacon)
  expect(fast.ariaBeacon).toBe(base.ariaBeacon)
  expect(fast.tablePuzzle).not.toBe(base.tablePuzzle)
  expect(fast.summaryPuzzle).toBe(fast.tablePuzzle)
  // At the top of the range the puzzle has arrived at the chart's own endpoint.
  expect(fast.tablePuzzle).toBe(base.ariaDownTo)

  // Halting the beacon must reach every surface, not just the one it was
  // triggered from — including the chart's screen-reader description.
  await page.getByRole('button', { name: 'Halt the beacon now' }).click()
  const dead = await compareTable(page)
  expect(dead['Opens after']![2]).toBe('never')
  await expect(page.locator('.compare-summary')).toContainText('never opens')
  await expect(page.locator('#compare .chart-caption')).toContainText('they do not open')
  expect((await page.locator('#compare .chart').getAttribute('aria-label')) ?? '').toContain(
    'stays at never',
  )
  await expect(page.locator('#compare .legend')).toContainText('halted, never opens')

  expect(errors).toEqual([])
})

// ---------------------------------------------------------------------------
// The mechanism, and the interop check that grounds it.
// ---------------------------------------------------------------------------

test('both halves of the pairing land on the same GT element, live', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  await page.getByRole('button', { name: 'Jump to the comparison' }).click()
  await expect(page.locator('#mechanism .stepcard-count')).toHaveText('Step 7 of 8')

  const compare = page.locator('#mechanism .stepbody')
  await expect(compare.locator('.hexdiff-summary')).toHaveClass(/hexdiff-equal/)
  await expect(compare.locator('.hexdiff-summary')).toContainText('all 1152 hex digits match')
  await expect(compare.locator('.verdict')).toHaveClass(/verdict-ok/)
  await expect(compare.locator('.verdict')).toContainText('Same group element')

  // The two sides are read off the page and compared here as well, so the
  // panel's own "identical" claim is checked rather than trusted.
  const sides = await compare.locator('.hexdiff-row .hex').allInnerTexts()
  expect(sides).toHaveLength(2)
  expect(sides[0]).toHaveLength(1152)
  expect(sides[0]).toBe(sides[1])

  // Re-draw the beacon key, r and the message. If the panel were rendering a
  // fixture the hex would not move; it must move AND stay equal.
  await page.getByRole('button', { name: 'Fresh randomness' }).click()
  await expect(page.locator('#mechanism .stepcard-count')).toHaveText('Step 7 of 8')
  const again = await compare.locator('.hexdiff-row .hex').allInnerTexts()
  expect(again[0]).not.toBe(sides[0])
  expect(again[0]).toBe(again[1])
  await expect(compare.locator('.hexdiff-summary')).toHaveClass(/hexdiff-equal/)

  // Step 8 runs the real decryptor: the recovered bytes and the rebuilt U must
  // both match, and the verdict is read off `decrypt()`'s result.
  await page.getByRole('button', { name: 'Next step' }).click()
  await expect(page.locator('#mechanism .stepcard-count')).toHaveText('Step 8 of 8')
  const summaries = compare.locator('.hexdiff-summary')
  await expect(summaries).toHaveCount(2)
  await expect(summaries.nth(0)).toHaveClass(/hexdiff-equal/)
  await expect(summaries.nth(1)).toHaveClass(/hexdiff-equal/)
  const pairs = await compare.locator('.hexdiff-row .hex').allInnerTexts()
  expect(pairs).toHaveLength(4)
  expect(pairs[0]).toBe(pairs[1]) // what was locked vs what came out
  expect(pairs[2]).toBe(pairs[3]) // U as sent vs H3(sigma, M)*G2 rebuilt
  await expect(compare.locator('.verdict')).toHaveClass(/verdict-ok/)
  await expect(compare.locator('.verdict')).toContainText('the exact bytes that were locked')

  // The step counter is honest about where it is, and the controls are alive
  // at both ends of the walk.
  await expect(page.getByRole('button', { name: 'Done' })).toBeDisabled()
  await page.getByRole('button', { name: 'Back', exact: true }).click()
  await expect(page.locator('#mechanism .stepcard-count')).toHaveText('Step 7 of 8')
  await expect(page.getByRole('button', { name: 'Next step' })).toBeEnabled()

  expect(errors).toEqual([])
})

test('the interop check opens drand’s own ciphertext and says which key it got', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  const interop = page.locator('#interop')
  await markStale(page, '#interop .verdict')
  await page.getByRole('button', { name: 'Open the reference ciphertext' }).click()
  await expect(fresh(page, '#interop .verdict').first()).toBeVisible()

  const s = await stats(interop)
  // The published beacon signature is verified against the real quicknet-t
  // group key before it is used, and the page reports that separately.
  expect(s['Beacon signature']).toBe('verifies')
  expect(s['Chain']).toBe('quicknet-t')
  expect(s['Round']).toMatch(/^\d+$/)

  // The verdict is checked against the two values it is a claim about: the key
  // the Go implementation locked, and the key this page recovered.
  const keys = await interop.locator('.hexdiff-row .hex').allInnerTexts()
  expect(keys).toHaveLength(2)
  expect(keys[0]).toMatch(/^[0-9a-f]{32}$/)
  expect(keys[1]).toBe(keys[0])
  await expect(interop.locator('.hexdiff-summary')).toHaveClass(/hexdiff-equal/)
  await expect(interop.locator('.verdict')).toHaveClass(/verdict-ok/)
  await expect(interop.locator('.verdict')).toContainText('did not create')

  expect(errors).toEqual([])
})

// ---------------------------------------------------------------------------
// The attack exhibit: the page claims eight of nine fail. Count them.
// ---------------------------------------------------------------------------

test('eight of the nine attacks are refused, and the ninth is an alarm', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  const select = page.locator('#attack-choice')
  const ids = await select.locator('option').evaluateAll((os) =>
    os.map((o) => (o as HTMLOptionElement).value),
  )
  expect(ids).toHaveLength(9)

  const tones: Record<string, string> = {}
  for (const id of ids) {
    await markStale(page, '#attack .live .verdict')
    await select.selectOption(id)
    const v = fresh(page, '#attack .live .verdict').first()
    await expect(v).toBeVisible()
    const cls = (await v.getAttribute('class')) ?? ''
    tones[id] = cls.includes('verdict-alarm') ? 'alarm' : cls.includes('verdict-ok') ? 'ok' : cls

    // Whatever the outcome, the page must name the cause rather than just
    // colouring a box: a verdict detail, plus the prose that explains it.
    await expect(v.locator('.verdict-detail')).not.toBeEmpty()
    await expect(page.locator('#attack .explain')).not.toBeEmpty()
    await expect(page.locator('#attack .claim')).not.toBeEmpty()
  }

  const refused = ids.filter((id) => tones[id] === 'ok')
  const alarms = ids.filter((id) => tones[id] === 'alarm')
  expect(refused).toHaveLength(8)
  expect(alarms).toEqual(['operator'])

  // The one that works is the beacon operator, and the page colours it as a
  // failure of the trust assumption rather than as a success.
  await markStale(page, '#attack .live .verdict')
  await select.selectOption('operator')
  const alarm = fresh(page, '#attack .live .verdict').first()
  await expect(alarm).toContainText('Opened early')
  await expect(page.locator('#attack .explain')).toContainText('threshold')
  // It shows the plaintext it recovered, which is the point of the exhibit.
  await expect(page.locator('#attack .hexblock .hex')).toContainText('vote tally')

  // The button re-runs the selected attack rather than going dead after the
  // select has driven it once.
  await markStale(page, '#attack .live .verdict')
  await page.getByRole('button', { name: 'Run it against the real decryptor' }).click()
  await expect(fresh(page, '#attack .live .verdict').first()).toContainText('Opened early')

  expect(errors).toEqual([])
})

// ---------------------------------------------------------------------------
// Regressions.
// ---------------------------------------------------------------------------

/**
 * REGRESSION — a verified round outliving the chain it was verified against.
 *
 * Found by this file. `Verify` printed "Signature valid" plus both 576-byte GT
 * elements; switching the chain scheme (or resetting the lab) builds a
 * `SimulatedBeacon` with a freshly drawn master secret and clears the vault,
 * but the verification region was never told. The page went on displaying a
 * valid-signature verdict, and hex, for a key pair that no longer existed
 * anywhere — while the panel immediately above it reported that this chain
 * cannot address the future at all.
 */
test('a verified round does not outlive the chain it was verified against', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  const out = page.locator('#beacon [aria-label="Verification result"]')

  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  await page.locator('#beacon').getByRole('button', { name: 'Verify' }).first().click()
  await expect(out.locator('.verdict')).toHaveClass(/verdict-ok/)
  await expect(out.locator('.verdict')).toContainText('Signature valid')
  const gt = await out.locator('.hexdiff-row .hex').allInnerTexts()
  expect(gt[0]).toHaveLength(1152)
  expect(gt[0]).toBe(gt[1])

  // A scheme switch replaces the beacon and its keys.
  await page.locator('#clock-scheme').selectOption('chained')
  await expect(out.locator('.verdict')).not.toHaveClass(/verdict-ok/)
  await expect(out).not.toContainText('Signature valid')
  await expect(out.locator('.hexdiff-row')).toHaveCount(0)
  await expect(out.locator('.verdict')).toContainText('the chain was replaced')

  // So does a lab reset. Verify on the new chain first, so this is not just
  // reading the cleared state from the step above.
  await page.locator('#clock-scheme').selectOption('unchained')
  await page.getByRole('button', { name: 'Resume' }).click()
  await page.getByRole('button', { name: 'Pause' }).click()
  await page.locator('#beacon').getByRole('button', { name: 'Verify' }).first().click()
  await expect(out.locator('.verdict')).toContainText('Signature valid')
  const gt2 = await out.locator('.hexdiff-row .hex').allInnerTexts()
  // A new master secret means new GT elements for the same round number.
  expect(gt2[0]).not.toBe(gt[0])

  await page.getByRole('button', { name: 'Reset lab' }).click()
  await expect(out).not.toContainText('Signature valid')
  await expect(out.locator('.hexdiff-row')).toHaveCount(0)

  // Ticking must NOT retire it — rounds already published stay valid as the
  // beacon advances, and only replacing the beacon invalidates them.
  await page.getByRole('button', { name: 'Pause' }).click()
  await page.locator('#beacon').getByRole('button', { name: 'Verify' }).first().click()
  await expect(out.locator('.verdict')).toContainText('Signature valid')
  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  await expect(out.locator('.verdict')).toContainText('Signature valid')

  expect(errors).toEqual([])
})

/**
 * REGRESSION — a lock receipt outliving the vault it described.
 *
 * Found by this file. "Locked to round 9 — 245 bytes on the wire" sat directly
 * above a vault reading "Nothing locked yet" after a reset or a scheme switch
 * discarded every ciphertext: two surfaces of one panel disagreeing about
 * whether anything was locked, and quoting a round number that no longer meant
 * anything on the restarted chain.
 */
test('the lock receipt does not outlive the vault it described', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  const receipt = page.locator('#lock [aria-label="Lock result"]')

  await page.locator('#lock-message').fill('receipt staleness probe')
  await lock(page, 7)
  await expect(receipt.locator('.verdict')).toContainText('Locked to round')
  await expect(page.locator('#lock .vault-item')).toHaveCount(1)

  await page.getByRole('button', { name: 'Reset lab' }).click()
  await expect(page.locator('#lock .vault-item')).toHaveCount(0)
  await expect(receipt).toBeEmpty()
  // ...and the empty-vault note is the only thing claiming anything now.
  await expect(page.locator('#lock-vault')).toBeEmpty()

  // Same for a scheme switch, which also discards the vault.
  await page.getByRole('button', { name: 'Pause' }).click()
  await page.locator('#lock-message').fill('second receipt probe')
  await lock(page, 7)
  await expect(receipt.locator('.verdict')).toContainText('Locked to round')
  await page.locator('#clock-scheme').selectOption('chained')
  await expect(page.locator('#lock .vault-item')).toHaveCount(0)
  await expect(receipt).toBeEmpty()

  // A tick must not wipe a receipt that is still true. (A scheme switch leaves
  // the clock exactly as it found it, so it is still paused here.)
  await page.locator('#clock-scheme').selectOption('unchained')
  await expect(page.getByRole('button', { name: 'Resume' })).toBeVisible()
  await page.locator('#lock-message').fill('survives a tick')
  await lock(page, 9)
  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  await expect(receipt.locator('.verdict')).toContainText('Locked to round')

  expect(errors).toEqual([])
})

/**
 * The `[hidden]` trap: `[hidden]{display:none}` in the UA sheet loses to ANY
 * author `display`, so a panel shipping the attribute renders anyway and every
 * `el.hidden = true` against it is a silent no-op. This lab ships
 * `#app [hidden]{display:none!important}`; this holds it there.
 */
test('nothing carrying the hidden attribute is still rendered', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  // Drive the one element that actually toggles, in both directions.
  await expect(page.locator('#lock .note', { hasText: 'Nothing locked yet' })).toBeVisible()
  await page.locator('#lock-message').fill('hides the empty note')
  await lock(page, 3)

  const leaks = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[hidden]'))
      .filter((el) => getComputedStyle(el).display !== 'none')
      .map((el) => `${el.tagName.toLowerCase()}.${(el as HTMLElement).className}`),
  )
  expect(leaks, `elements marked hidden that still render: ${JSON.stringify(leaks)}`).toEqual([])
  await expect(page.locator('#lock .note', { hasText: 'Nothing locked yet' })).toBeHidden()

  expect(errors).toEqual([])
})

/**
 * Controls must survive the states that end a run. A halted beacon, a reset
 * lab and an opened ciphertext have all been places where a lab goes dead.
 */
test('the lab stays drivable after a halt and after a reset', async ({ page }) => {
  const errors = trackErrors(page)
  await openLab(page)

  await page.locator('#lock-message').fill('drivability probe')
  await lock(page, 25)

  await page.getByRole('button', { name: 'Halt the beacon now' }).click()
  await expect(page.locator('#outage .verdict-alarm')).toBeVisible()
  // While halted the clock controls are correctly disabled...
  await expect(page.getByRole('button', { name: 'Fast-forward 10 rounds' })).toBeDisabled()

  // ...and restarting brings them back rather than leaving the lab dead.
  await page.getByRole('button', { name: 'Restart the beacon' }).first().click()
  await expect(page.getByRole('button', { name: 'Fast-forward 10 rounds' })).toBeEnabled()
  await expect(page.locator('#lock .vault-item.is-stranded')).toHaveCount(0)
  await expect(page.locator('#outage .verdict-ok')).toBeVisible()

  const before = Number(await page.locator('#clock-round').innerText())
  await page.getByRole('button', { name: 'Fast-forward 10 rounds' }).click()
  expect(Number(await page.locator('#clock-round').innerText())).toBe(before + 10)

  // A reset returns the lab to a usable, running state.
  await page.getByRole('button', { name: 'Reset lab' }).click()
  await expect(page.locator('#lock .vault-item')).toHaveCount(0)
  await page.getByRole('button', { name: 'Pause' }).click()
  await expect(page.locator('#clock-round')).toHaveText('1')
  await page.locator('#lock-message').fill('after the reset')
  await lock(page, 2)
  await expect(page.locator('#lock .vault-item')).toHaveCount(1)

  expect(errors).toEqual([])
})
