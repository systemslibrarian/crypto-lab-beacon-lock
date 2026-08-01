/**
 * The price of not making anyone grind.
 *
 * A time-lock puzzle is a promise you can keep alone: the secret is inside the
 * ciphertext, and enough electricity always gets it out. A beacon lock moves
 * the key outside the ciphertext, into a public event that has not happened —
 * and if that event never happens, there is no amount of anything that
 * recovers the plaintext. Not "computationally infeasible". Absent.
 *
 * The brief asks for this to be shown rather than warned about, so halting the
 * beacon here really does halt the beacon the rest of the page is using, and
 * the stranded ciphertexts really are the ones you locked upstairs.
 */

import { add, button, clear, el, expert, honesty, liveRegion, panel, stat, verdict } from './dom'
import { state } from './state'

export function mountOutage(host: HTMLElement): void {
  const section = panel(
    'outage',
    'What if the beacon dies?',
    'The honest failure mode, demonstrated rather than disclaimed. Stop the beacon and every ciphertext waiting on a later round becomes permanently unopenable.',
  )

  const haltBtn = button('Halt the beacon now', () => {
    if (state.beacon.isHalted) state.resume()
    else state.halt()
  }, 'btn-danger')

  const out = liveRegion('Outage status')
  const stats = el('div', { class: 'statrow' })

  add(
    section,
    el('p', {
      text: 'The decryption key for round n is the beacon’s signature on round n. If the beacon stops at round m, then for every ciphertext locked to a round after m, that signature is never produced by anyone. The mask it would have reconstructed cannot be reached any other way — that is what the security of the scheme means, and security does not switch off because the failure is now yours.',
    }),
    el('div', { class: 'controls' }, haltBtn),
    stats,
    out,
    el('h3', { text: 'The trade, stated plainly' }),
    el(
      'div',
      { class: 'tradegrid' },
      tradeCard(
        'What a beacon lock buys',
        [
          'No work for anybody — no electricity, no ASIC race, no melted GPU.',
          'The unlock instant is a wall-clock time you can print on an invitation, not an estimate that depends on who is opening it.',
          'A thousand recipients all open at the same moment, from one 48-byte publication.',
          'Nobody can buy their way in early.',
        ],
        'ok',
      ),
      tradeCard(
        'What it costs',
        [
          'A liveness assumption: the beacon must still be running when the round arrives.',
          'A trust assumption: the operators must not sign a future round early and privately.',
          'The failure is total rather than graceful — a dead beacon means the plaintext is gone, not delayed.',
          'You inherit the beacon’s governance, jurisdiction and funding as part of your threat model.',
        ],
        'alarm',
      ),
    ),
    el('h3', { text: 'What is actually done about it' }),
    el(
      'ul',
      { class: 'rules' },
      el('li', {
        text: 'Distribute the operator. drand’s League of Entropy is roughly twenty independent organisations across separate jurisdictions, running a t-of-n threshold key: a minority going offline changes nothing, and a minority turning malicious cannot sign early.',
      }),
      el('li', {
        text: 'Do not depend on one chain. Split the key with secret sharing and timelock each share to a different beacon, so any two of three surviving networks is enough. The scheme composes — each share is just another 32 bytes to lock.',
      }),
      el('li', {
        text: 'Belt and braces: give the same plaintext a compute-bound fallback. Timelock it to the beacon and hide a copy behind a VDF sized for the same date. The beacon path opens on time; the expensive path is there if the beacon is not.',
      }),
      el('li', {
        text: 'Be honest about horizon. A round three days out and a round thirty years out are the same arithmetic and very different bets. drand has been running since 2019; nobody has run a beacon for thirty years.',
      }),
    ),
    honesty(
      'This exhibit halts a beacon that lives in your browser tab, which is not evidence about how likely the real League of Entropy is to stop. It is evidence about what happens to your ciphertext if it does — and that consequence is exact, not probabilistic.',
    ),
    expert(
      'Why you cannot just wait longer',
      el('p', {
        text: 'With a time-lock puzzle, "unopenable" is a statement about a budget: the secret is inside, and the only question is how many squarings you are willing to pay for. With a beacon lock the secret is not inside. Recovering it means producing s·H₁(m) without s, which is the computational Diffie–Hellman problem in G1 on BLS12-381 — roughly 2¹²⁶ work, and no amount of patience converts into progress against it.',
      }),
      el('p', {
        text: 'This is also the sharp line between timelock encryption and witness encryption. A witness-encrypted ciphertext opens for anyone who can produce a witness for some NP statement, whenever they manage it. A timelocked one opens when a particular key gets published, and never otherwise. Different guarantee, different failure.',
      }),
    ),
  )
  host.appendChild(section)

  function render(): void {
    const halted = state.beacon.isHalted
    haltBtn.textContent = halted ? 'Restart the beacon' : 'Halt the beacon now'

    const stranded = state.items.filter((i) => i.opened === null && i.targetRound > state.round)
    clear(stats)
    add(
      stats,
      stat('Beacon', halted ? `halted at round ${state.haltedAtRound ?? state.round}` : 'running', halted ? 'alarm' : 'ok'),
      stat('Ciphertexts waiting', String(stranded.length), stranded.length > 0 && halted ? 'alarm' : 'idle'),
      stat('Recoverable by brute force', halted && stranded.length > 0 ? 'none' : '—', halted && stranded.length > 0 ? 'alarm' : 'idle'),
    )

    clear(out)
    if (!halted) {
      add(
        out,
        verdict('ok', 'Beacon running', 'every locked ciphertext still has a scheduled unlock time'),
      )
      return
    }
    if (stranded.length === 0) {
      add(
        out,
        verdict(
          'warn',
          'Beacon halted, nothing stranded',
          'lock something to a future round in the exhibit above and halt it again',
        ),
      )
      return
    }
    add(
      out,
      verdict(
        'alarm',
        `${stranded.length} ciphertext${stranded.length === 1 ? '' : 's'} permanently locked`,
        `the beacon stopped at round ${state.haltedAtRound ?? state.round}`,
      ),
    )
    const list = el('ul', { class: 'rules', role: 'list' })
    for (const item of stranded) {
      list.appendChild(
        el('li', { role: 'listitem' }, `${item.label} — needed round ${item.targetRound}, which will never be signed.`),
      )
    }
    add(
      out,
      list,
      el('p', {
        class: 'note',
        text: 'Restarting the beacon here would rescue them, because this beacon is a timer you own. That button is the one thing on this page with no real-world counterpart.',
      }),
    )
  }

  state.subscribe(render)
  render()
}

function tradeCard(title: string, points: string[], tone: 'ok' | 'alarm'): HTMLElement {
  const card = el('div', { class: `tradecard tradecard-${tone}` })
  add(
    card,
    el(
      'h4',
      { class: 'tradecard-title' },
      el('span', { 'aria-hidden': 'true', text: tone === 'ok' ? '✓ ' : '✗ ' }),
      title,
    ),
  )
  const list = el('ul', { class: 'tradecard-list', role: 'list' })
  for (const p of points) list.appendChild(el('li', { role: 'listitem', text: p }))
  card.appendChild(list)
  return card
}
