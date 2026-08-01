/**
 * The beacon itself: a clock that signs the time.
 *
 * Two things get shown here that prose cannot carry. First, verification is
 * performed rather than claimed — both pairings are computed from disjoint
 * inputs and the two 576-byte GT elements are printed side by side. Second,
 * the chained/unchained switch: flip to a chained beacon and the "identity for
 * round n + 20" readout stops existing, because on a chained chain it genuinely
 * does not. That single missing value is the reason drand had to ship an
 * unchained network before timelock encryption could work at all.
 */

import { roundMessage, verificationSides, verifyRound } from '../core/beacon'
import { gtToBytes } from '../core/bls'
import { toHex } from '../core/bytes'
import {
  add,
  button,
  clear,
  el,
  elide,
  expert,
  hexBlock,
  hexDiff,
  honesty,
  labelledSelect,
  liveRegion,
  panel,
  stat,
  statRow,
  verdict,
} from './dom'
import { SPEEDS, state } from './state'

export function mountClock(host: HTMLElement): void {
  const section = panel(
    'beacon',
    'The beacon',
    'A public clock that signs every tick. Each round produces one deterministic BLS signature; that signature is the decryption key for anything locked to that round.',
  )

  // ---- The clock face -------------------------------------------------
  const face = el('div', { class: 'clockface' })
  const roundNumber = el('span', { class: 'clock-round', id: 'clock-round' })
  const roundState = el('span', { class: 'clock-state' })
  const roundIdentity = el('code', { class: 'clock-identity' })
  add(
    face,
    el(
      'div',
      {
        class: 'clock-readout',
        role: 'status',
        'aria-live': 'polite',
        'aria-label': 'Current beacon round',
      },
      el('span', { class: 'clock-label', text: 'LATEST ROUND' }),
      roundNumber,
      roundState,
    ),
    el(
      'div',
      { class: 'clock-side' },
      el('span', { class: 'clock-label', text: 'ITS SIGNATURE — THE KEY FOR THIS ROUND' }),
      roundIdentity,
    ),
  )

  const runBtn = button('Pause', () => (state.running ? state.stop() : state.start()), 'btn-small')
  const ffBtn = button('Fast-forward 10 rounds', () => state.fastForward(10), 'btn-small btn-quiet')
  ffBtn.title = 'You are the beacon operator on this page. Nobody holds this button on the real network.'
  const haltBtn = button(
    'Halt the beacon',
    () => (state.beacon.isHalted ? state.resume() : state.halt()),
    'btn-small btn-danger',
  )

  const speed = labelledSelect(
    'clock-speed',
    'Tick rate',
    SPEEDS.map((s) => ({ value: s.value, text: s.text })),
  )
  speed.select.value = '1000'
  speed.select.addEventListener('change', () => state.setSpeed(Number(speed.select.value)))

  const scheme = labelledSelect('clock-scheme', 'Chain scheme', [
    { value: 'unchained', text: 'Unchained — message = SHA-256(round)' },
    { value: 'chained', text: 'Chained — message = SHA-256(prev signature ‖ round)' },
  ])
  scheme.select.addEventListener('change', () => {
    state.setScheme(scheme.select.value === 'chained' ? 'chained' : 'unchained')
  })

  add(
    section,
    face,
    el('div', { class: 'controls' }, runBtn, ffBtn, haltBtn, speed.wrap, scheme.wrap),
    el('p', {
      class: 'note',
      text: 'Fast-forward exists because on this page you own the beacon’s secret. On drand, the only way to reach round n + 10 is to wait 30 seconds.',
    }),
  )

  // ---- Can you address the future? ------------------------------------
  const futureBox = el('div', { class: 'subpanel', id: 'clock-future' })
  add(
    section,
    futureBox,
  )

  // ---- Published rounds -----------------------------------------------
  const roundsBox = el('div', { class: 'subpanel' })
  const roundsList = el('ul', { class: 'roundlist', role: 'list' })
  const verifyOut = liveRegion('Verification result')
  add(
    roundsBox,
    el('h3', { text: 'Published rounds' }),
    el('p', {
      class: 'note',
      text: 'Newest first. Verifying computes both halves of e(σ, G₂) = e(H₁(m), P_pub) independently and prints the two group elements.',
    }),
    roundsList,
    verifyOut,
  )
  add(section, roundsBox)

  add(
    section,
    honesty(
      'The real quicknet chain is signed by a threshold key split across the League of Entropy — around twenty independent organisations, no one of which can produce a round alone. This page holds one scalar in one tab. The signatures have the same shape and verify the same way; what is missing is the distributed trust that makes them hard to forge. ',
      'The known-answer tests in this repo close that gap from the other side: they verify four signatures the real network actually published, against the real quicknet group public key.',
    ),
    expert(
      'Why unchained was a prerequisite for timelock',
      el('p', {
        text: 'On a chained beacon, round n’s message contains round n−1’s signature. To write down what round n + 1000 will sign, you would need the 999 signatures in between — which is exactly the information you are waiting for. The identity is unknowable, so there is nothing to encrypt to.',
      }),
      el('p', {
        text: 'Unchained beacons sign the round number alone. The message for any round, however far away, is one SHA-256 away from a number you already know. drand shipped quicknet in 2023 with that scheme, three-second rounds, and signatures in G1 — and timelock encryption became a thing you could actually deploy.',
      }),
    ),
  )
  host.appendChild(section)

  // ---- rendering ------------------------------------------------------
  function renderFace(): void {
    roundNumber.textContent = String(state.round)
    roundState.textContent = state.beacon.isHalted
      ? 'halted — no further rounds'
      : state.running
        ? `ticking every ${(state.speedMillis / 1000).toFixed(1)} s`
        : 'paused'
    runBtn.textContent = state.running ? 'Pause' : 'Resume'
    runBtn.disabled = state.beacon.isHalted
    ffBtn.disabled = state.beacon.isHalted
    haltBtn.textContent = state.beacon.isHalted ? 'Restart the beacon' : 'Halt the beacon'
    // Changing hex is the motion, and it is the mechanism: these 48 bytes are
    // the freshly minted decryption key for the round just published.
    const latest = state.beacon.at(state.round)
    roundIdentity.textContent = latest
      ? elide(toHex(latest.signature.toBytes()), 32, 16)
      : '— no round published yet —'
  }

  function renderFuture(): void {
    clear(futureBox)
    const target = state.round + 20
    add(futureBox, el('h3', { text: `Can you address round ${target} today?` }))
    if (state.scheme === 'unchained') {
      const identity = roundMessage(target, 'unchained')
      add(
        futureBox,
        verdict('ok', 'Yes', 'the identity is a pure function of the round number'),
        el('p', { class: 'mono-line', text: `identity = SHA-256(uint64_be(${target}))` }),
        hexBlock(toHex(identity), `Identity for round ${target}`),
        el('p', {
          class: 'note',
          text: 'Nobody needed a network, a secret, or a signature to produce those 32 bytes. That is what makes them a usable encryption target.',
        }),
      )
    } else {
      add(
        futureBox,
        verdict(
          'alarm',
          'No',
          `round ${target}'s message contains round ${target - 1}'s signature, which does not exist`,
        ),
        el('p', { class: 'mono-line', text: `identity = SHA-256(σ_${target - 1} ‖ uint64_be(${target}))` }),
        hexBlock('— undefined until the beacon gets there —', `Identity for round ${target}`),
        el('p', {
          class: 'note',
          text: 'A chained beacon is a perfectly good randomness source. It just cannot be used as an IBE authority for the future, because the future has no addresses yet.',
        }),
      )
    }
  }

  function renderRounds(): void {
    clear(roundsList)
    const recent = state.beacon.recent(6)
    if (recent.length === 0) {
      roundsList.appendChild(el('li', { role: 'listitem', class: 'note' }, 'No rounds published yet.'))
      return
    }
    for (const round of recent) {
      const item = el('li', { class: 'rounditem', role: 'listitem' })
      add(
        item,
        el(
          'div',
          { class: 'rounditem-head' },
          el('span', { class: 'rounditem-number', text: `round ${round.round}` }),
          button(
            'Verify',
            () => showVerification(round.round),
            'btn-small btn-quiet',
          ),
        ),
        el(
          'div',
          { class: 'rounditem-body' },
          el('span', { class: 'rounditem-label', text: 'message' }),
          el('code', { class: 'rounditem-hex', text: elide(toHex(round.message), 24, 12) }),
          el('span', { class: 'rounditem-label', text: 'signature' }),
          el('code', { class: 'rounditem-hex', text: elide(toHex(round.signature.toBytes()), 24, 12) }),
        ),
      )
      roundsList.appendChild(item)
    }
  }

  function showVerification(roundNo: number): void {
    const round = state.beacon.at(roundNo)
    clear(verifyOut)
    if (!round) {
      verifyOut.appendChild(verdict('warn', 'No such round', 'the beacon has not published it'))
      return
    }
    const key = state.beacon.keys.publicKey
    const ok = verifyRound(key, round.message, round.signature)
    const sides = verificationSides(key, round.message, round.signature)
    add(
      verifyOut,
      el('h4', { text: `Round ${roundNo} — both sides of the pairing equation` }),
      statRow(
        stat('Signature', `${round.signature.toBytes().length} B in G1`),
        stat('Public key', `${key.toBytes().length} B in G2`),
        stat('GT element', `${gtToBytes(sides.left).length} B`),
      ),
      hexDiff(
        toHex(gtToBytes(sides.left)),
        toHex(gtToBytes(sides.right)),
        'e(σ, G₂) — from the signature',
        'e(H₁(m), P_pub) — from the round number and the group key',
      ),
      verdict(
        ok ? 'ok' : 'alarm',
        ok ? 'Signature valid' : 'Signature invalid',
        ok
          ? 'two disjoint computations landed on the same element of GT'
          : 'the two sides disagree',
      ),
    )
  }

  state.subscribe(() => {
    renderFace()
    renderFuture()
    renderRounds()
  })
  renderFace()
  renderFuture()
  renderRounds()
}
