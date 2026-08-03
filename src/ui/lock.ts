/**
 * The core interaction: lock a message to a round that has not happened yet,
 * then watch the beacon walk toward it.
 *
 * Two buttons per item, on purpose. "Open it" is the honest path and reports
 * that there is simply nothing to decrypt with yet. "Force it with the latest
 * signature" is the break-it-yourself path: it feeds a genuine, correctly
 * signed beacon round — just the wrong one — to the genuine decryptor, and the
 * Fujisaki–Okamoto check rejects it in front of you. A learner who has watched
 * a real signature bounce understands the lock better than one who read a
 * banner saying it would.
 */

import { toHex } from '../core/bytes'
import { ciphertextOverhead, serializeCiphertext } from '../core/tlock'
import { NONCE_BYTES, TAG_BYTES } from '../core/envelope'
import {
  add,
  button,
  clear,
  el,
  elide,
  expert,
  hexBlock,
  honesty,
  liveRegion,
  meter,
  panel,
  stat,
  statRow,
  verdict,
} from './dom'
import { state, type LockedItem, type OpenOutcome } from './state'

const PRESETS = [
  { label: 'Embargoed press release', text: 'Q3 results: revenue up 14%. Under embargo until the bell.' },
  { label: 'Sealed bid', text: 'Bid: 4,250,000 — sealed until the auction closes.' },
  { label: 'Dead-man switch', text: 'If you are reading this, the check-in did not happen.' },
]

export function mountLock(host: HTMLElement): void {
  const section = panel(
    'lock',
    'Lock a secret to a future round',
    'Write something, choose how far ahead to lock it, and try to open it early. The refusal you get back is real: it comes from the same decryptor that will succeed later, given the same ciphertext and a different 48 bytes.',
  )

  const message = el('textarea', {
    id: 'lock-message',
    rows: '3',
    class: 'textarea',
    spellcheck: 'false',
  })
  message.value = PRESETS[0]!.text

  const preset = el('select', { id: 'lock-preset' })
  for (const [i, p] of PRESETS.entries()) {
    preset.appendChild(el('option', { value: String(i), text: p.label }))
  }
  preset.addEventListener('change', () => {
    message.value = PRESETS[Number(preset.value)]!.text
  })

  const ahead = el('input', {
    type: 'range',
    id: 'lock-ahead',
    min: '1',
    max: '30',
    step: '1',
    value: '8',
  })
  const aheadOut = el('output', { class: 'ctl-readout', for: 'lock-ahead' })

  const lockBtn = button('Lock it', () => void doLock())
  const controls = el(
    'div',
    { class: 'controls' },
    el(
      'div',
      { class: 'ctl' },
      el('label', { class: 'ctl-label', for: 'lock-preset', text: 'Example' }),
      preset,
    ),
    el(
      'div',
      { class: 'ctl ctl-range' },
      el('label', { class: 'ctl-label', for: 'lock-ahead', text: 'Rounds from now' }),
      ahead,
      aheadOut,
    ),
    lockBtn,
  )

  const messageWrap = el(
    'div',
    { class: 'ctl ctl-wide' },
    el('label', { class: 'ctl-label', for: 'lock-message', text: 'Message to lock' }),
    message,
  )

  const status = liveRegion('Lock result')
  const vault = el('div', { class: 'vault', id: 'lock-vault' })
  const vaultEmpty = el('p', {
    class: 'note',
    text: 'Nothing locked yet.',
  })

  add(
    section,
    messageWrap,
    controls,
    status,
    el('h3', { text: 'Locked ciphertexts' }),
    vaultEmpty,
    vault,
    honesty(
      'Real: the BLS12-381 pairing arithmetic, the identity-based encryption, the AES-256-GCM envelope, and every accept/reject decision. ',
      'Simulated: the beacon itself, which is a ',
      el('code', { text: 'setInterval' }),
      ' in this tab holding one secret scalar, not twenty machines on three continents holding threshold shares. Nothing here reaches the network.',
    ),
    expert(
      'What is actually in a locked item',
      el('p', {
        text:
          'Exactly what real tlock does. A fresh AES-256 key seals the text with GCM; the timelock covers only that 32-byte key, so the pairing work is a fixed cost no matter how long the message is. The target round is bound into the AEAD as associated data, so an attacker cannot relabel a ciphertext with a nearer unlock time — the tag stops verifying.',
      }),
      el('p', {
        text:
          'The timelock ciphertext is a triple (U, V, W): U is a 96-byte G2 point, V and W are each 32 bytes here. The round number travels in the clear beside it, because the point of the scheme is that everybody knows when it opens; what they cannot do is arrive early.',
      }),
    ),
  )
  host.appendChild(section)

  function renderAhead(): void {
    const n = Number(ahead.value)
    const seconds = ((n * state.speedMillis) / 1000).toFixed(1)
    aheadOut.textContent = `${n} → opens at round ${state.round + n} (≈ ${seconds} s from now)`
  }
  ahead.addEventListener('input', renderAhead)

  /**
   * The chain epoch the lock receipt above the vault was written under, or
   * null when nothing is shown. A scheme switch or a lab reset discards every
   * ciphertext, so a receipt reading "Locked to round 9" would otherwise sit
   * directly above a vault reading "Nothing locked yet" — two surfaces of one
   * panel disagreeing about whether anything is locked, and a round number
   * that no longer means anything on the restarted chain.
   */
  let statusEpoch: number | null = null

  function renderStatus(): void {
    if (statusEpoch === null || statusEpoch === state.chainEpoch) return
    statusEpoch = null
    clear(status)
  }

  async function doLock(): Promise<void> {
    const text = message.value.trim()
    clear(status)
    statusEpoch = state.chainEpoch
    if (!text) {
      status.appendChild(verdict('warn', 'Nothing to lock', 'type a message first'))
      return
    }
    const target = state.round + Number(ahead.value)
    try {
      const item = await state.lock(PRESETS[Number(preset.value)]!.label, text, target)
      clear(status)
      add(
        status,
        verdict(
          'locked',
          `Locked to round ${target}`,
          `${serializeCiphertext(item.keyCiphertext).length + item.payload.ciphertext.length + NONCE_BYTES} bytes on the wire`,
        ),
        el('p', {
          class: 'note',
          text: `The AES key is gone from this page — the only copy is inside V and W, masked by a group element that needs the beacon's round-${target} signature to reconstruct.`,
        }),
      )
    } catch (error) {
      clear(status)
      status.appendChild(
        verdict('warn', 'Cannot lock', error instanceof Error ? error.message : String(error)),
      )
    }
  }

  function renderVault(): void {
    clear(vault)
    vaultEmpty.hidden = state.items.length > 0
    for (const item of state.items) vault.appendChild(renderItem(item))
  }

  function renderItem(item: LockedItem): HTMLElement {
    const remaining = item.targetRound - state.round
    const span = Math.max(1, item.targetRound - item.lockedAtRound)
    const elapsed = Math.max(0, Math.min(span, state.round - item.lockedAtRound))
    const reached = state.round >= item.targetRound
    const stranded = state.beacon.isHalted && !reached

    const card = el('article', {
      class: `vault-item ${item.opened !== null ? 'is-open' : stranded ? 'is-stranded' : reached ? 'is-ready' : 'is-locked'}`,
    })
    const result = liveRegion(`Result for ${item.label}`)

    const head = el(
      'header',
      { class: 'vault-head' },
      el('h4', { class: 'vault-title', text: item.label }),
      el('span', {
        class: 'vault-badge',
        text:
          item.opened !== null
            ? 'open'
            : stranded
              ? 'stranded'
              : reached
                ? 'ready'
                : `${remaining} round${remaining === 1 ? '' : 's'} to go`,
      }),
    )

    add(
      card,
      head,
      meter(
        `Round ${item.lockedAtRound} → ${item.targetRound}`,
        elapsed,
        span,
        reached ? `reached at round ${item.targetRound}` : `now at round ${state.round}`,
      ),
      statRow(
        stat('Target round', String(item.targetRound)),
        stat('Identity', `SHA-256(${item.targetRound})`),
        stat('Plaintext', `${item.plaintextBytes} B`),
        stat('Timelock overhead', `${ciphertextOverhead(32)} B`),
        stat('AEAD overhead', `${NONCE_BYTES + TAG_BYTES} B`),
      ),
      hexBlock(
        elide(toHex(serializeCiphertext(item.keyCiphertext)), 64, 24),
        `Timelock ciphertext for ${item.label}`,
      ),
    )

    if (item.opened !== null) {
      add(
        card,
        verdict('ok', 'Opened', `with the beacon’s round-${item.targetRound} signature`),
        el('blockquote', { class: 'plaintext', text: item.opened }),
      )
    } else {
      const openBtn = button(
        `Open with round ${item.targetRound}`,
        () => void run(() => state.tryOpen(item)),
        'btn-small',
      )
      const forceBtn = button(
        'Force it with the latest signature',
        () => void forceLatest(),
        'btn-small btn-quiet',
      )
      forceBtn.title = 'Feed a genuine beacon signature for a different round to the real decryptor'
      forceBtn.disabled = state.round < 1
      add(card, el('div', { class: 'vault-actions' }, openBtn, forceBtn), result)

      async function run(fn: () => Promise<OpenOutcome>): Promise<void> {
        report(await fn())
      }

      async function forceLatest(): Promise<void> {
        const latest = state.beacon.at(state.round)
        if (!latest) {
          report({ status: 'stranded' })
          return
        }
        const outcome = await state.openWith(item, latest.signature)
        clear(result)
        if (outcome.status === 'rejected') {
          add(
            result,
            verdict(
              'ok',
              'Rejected — as it should be',
              `round ${state.round}’s signature is real, and it is not round ${item.targetRound}’s`,
            ),
            el('p', {
              class: 'note',
              text: 'The decryptor recomputed r from what it recovered and rebuilt U = r·G₂. It did not match the U in the ciphertext, so it returned nothing rather than a plausible-looking 32 bytes.',
            }),
          )
        } else if (outcome.status === 'opened') {
          // Only reachable when the latest round IS the target round. The
          // state change already re-rendered this card in its opened form.
          add(result, verdict('ok', 'Opened', 'the latest round is the target round'))
        } else {
          report(outcome)
        }
      }

      function report(outcome: OpenOutcome): void {
        clear(result)
        switch (outcome.status) {
          case 'opened':
            // The card has already been re-rendered in its opened form by the
            // state notification; this line is for the live region.
            add(result, verdict('ok', 'Opened', 'the beacon published the round'))
            break
          case 'too-early':
            add(
              result,
              verdict(
                'locked',
                'Nothing to decrypt with',
                `the beacon is at round ${state.round}; round ${item.targetRound} is ${outcome.roundsRemaining} away`,
              ),
              el('p', {
                class: 'note',
                text: 'This is not a rejected attempt. The key material for that round has not been created by anyone, anywhere, yet.',
              }),
            )
            break
          case 'stranded':
            add(
              result,
              verdict(
                'alarm',
                'Stranded',
                'the beacon has halted before reaching this round — see the outage exhibit',
              ),
            )
            break
          case 'rejected':
            add(result, verdict('alarm', 'Rejected', outcome.reason))
            break
        }
      }
    }

    return card
  }

  state.subscribe(() => {
    renderAhead()
    renderVault()
    renderStatus()
  })
  renderAhead()
  renderVault()
}
