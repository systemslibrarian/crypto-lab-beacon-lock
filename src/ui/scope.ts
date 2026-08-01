/**
 * Honest scoping. What is real, what is simulated, what this page does not
 * prove, and where the neighbouring labs pick up.
 */

import kat from '../fixtures/kat.json'
import { CURVE } from '../core/bls'
import { add, el, panel } from './dom'

export function mountScope(host: HTMLElement): void {
  const section = panel(
    'scope',
    'Scope, and what this does not prove',
    'A teaching demo, not production cryptography. Here is the exact boundary.',
  )

  const table = el('table', { class: 'datatable' })
  add(
    table,
    el(
      'thead',
      {},
      el(
        'tr',
        {},
        el('th', { scope: 'col', text: 'Component' }),
        el('th', { scope: 'col', text: 'Status' }),
        el('th', { scope: 'col', text: 'Notes' }),
      ),
    ),
  )
  const rows: Array<[string, 'real' | 'simulated', string]> = [
    ['BLS12-381 arithmetic and pairings', 'real', '@noble/curves — the same library used in production Ethereum tooling.'],
    ['RFC 9380 hash-to-curve (H₁)', 'real', `Gated by ${kat.hashToG1.vectors.length} known-answer tests from the RFC, under the RFC's own domain separation tag.`],
    ['Boneh–Franklin FullIdent IBE', 'real', 'Hand-rolled, including the Fujisaki–Okamoto check that makes the wrong key a rejection rather than garbage.'],
    ['Byte-compatibility with drand tlock', 'real', `Proven, not claimed: this repo decrypts a real ciphertext from the drand/tlock test corpus (round ${kat.tlockInterop.round} on ${kat.tlockInterop.beaconId}) and recovers the exact key the Go implementation locked.`],
    ['AES-256-GCM envelope', 'real', 'WebCrypto. The target round is bound in as associated data.'],
    ['Beacon round encoding and verification', 'real', `Byte-exact drand quicknet — proven by verifying ${kat.drandQuicknet.rounds.length} signatures the real League of Entropy published.`],
    ['The beacon itself', 'simulated', 'A setInterval in this tab holding one secret scalar. The real chain is a t-of-n threshold key across ~20 organisations.'],
    ['Network access', 'simulated', 'None. The drand values in this repo are static fixtures captured once; the page makes no requests.'],
    ['Threshold key generation', 'simulated', 'Out of scope entirely — a single keygen stands in for the DKG ceremony.'],
    ['Wall-clock scale', 'simulated', 'Rounds tick in seconds so a demo fits in a browser session. Real quicknet rounds are 3 s apart and the interesting horizons are months.'],
  ]
  const body = el('tbody')
  for (const [component, status, notes] of rows) {
    add(
      body,
      el(
        'tr',
        {},
        el('th', { scope: 'row', text: component }),
        el(
          'td',
          { class: status === 'real' ? 'cell-ok' : 'cell-warn' },
          el('span', { 'aria-hidden': 'true', text: status === 'real' ? '✓ ' : '~ ' }),
          status === 'real' ? 'real' : 'simulated',
        ),
        el('td', { class: 'cell-prose', text: notes }),
      ),
    )
  }
  table.appendChild(body)

  add(
    section,
    el('div', { class: 'tablewrap', tabindex: '0', role: 'region', 'aria-label': 'What is real and what is simulated' }, table),
    el('h3', { text: 'What this page does not prove' }),
    el(
      'ul',
      { class: 'rules' },
      el('li', {
        text: 'That the construction is secure. It is a faithful implementation of a published scheme, not an audited one, and it has had no side-channel analysis whatsoever — the JavaScript here is not constant-time and does not claim to be.',
      }),
      el('li', {
        text: `That BLS12-381 is strong enough for your horizon. Its conjectured security is about ${CURVE.securityBits} bits after the 2016 exTNFS improvements, down from the 128 originally claimed. A ciphertext locked for thirty years is a bet on that number holding for thirty years.`,
      }),
      el('li', {
        text: 'That timelock encryption is post-quantum. It is not. A cryptographically relevant quantum computer recovers the beacon’s secret from its public key and retroactively opens every ciphertext ever locked to that chain. There is no drop-in pairing-free replacement.',
      }),
      el('li', {
        text: 'That the beacon will behave. Punctuality and non-collusion are assumptions about an organisation, and no amount of mathematics on this page addresses them.',
      }),
      el('li', {
        text: 'Anything about randomness quality. A timelock needs the beacon to be on time and honest; it does not care whether the output is unpredictable.',
      }),
    ),
    el('h3', { text: 'Explicit non-goals' }),
    el(
      'ul',
      { class: 'rules' },
      el('li', {
        text: 'No live drand queries. The chain parameters and four round signatures in this repo were captured once and are shipped as static fixtures so the lab runs offline.',
      }),
      el('li', {
        text: 'Not witness encryption. Witness encryption opens for whoever can produce a witness to an NP statement, whenever they manage it. This opens when specific key material is published, and never otherwise — a different guarantee with a different failure mode.',
      }),
      el('li', {
        text: 'No distributed key generation ceremony. The interesting engineering in a real beacon is the DKG and the threshold signing; this lab replaces both with one scalar so the IBE structure stays visible.',
      }),
      el('li', {
        text: 'No age file format. The IBE layer is byte-compatible with drand tlock — this repo opens a real .tle stanza — but it does not implement age’s armor, HKDF or ChaCha20-Poly1305 STREAM, so it cannot read or write .tle files end to end.',
      }),
    ),
    el('h3', { text: 'Where to go next' }),
    el(
      'ul',
      { class: 'rules' },
      el(
        'li',
        {},
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-ibe-gate/', text: 'crypto-lab-ibe-gate' }),
        ' — the same Boneh–Franklin scheme with a human identity instead of a round number, and a private key generator instead of a clock. This lab is that lab with the authority replaced by a timer.',
      ),
      el(
        'li',
        {},
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-time-lock-puzzle/', text: 'crypto-lab-time-lock-puzzle' }),
        ' — the 1996 answer: hide the secret behind sequential squaring and make the opener pay.',
      ),
      el(
        'li',
        {},
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-vdf/', text: 'crypto-lab-vdf' }),
        ' — the same grind, made checkable, so the world pays for it once.',
      ),
      el(
        'li',
        {},
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/', text: 'crypto-lab-threshold-decrypt' }),
        ' — what the League of Entropy is actually doing with that master secret.',
      ),
    ),
    el('p', {
      class: 'honesty',
      text: 'Not production cryptography. Nothing on this page has been audited, and no key material here should protect anything you care about.',
    }),
  )
  host.appendChild(section)
}
