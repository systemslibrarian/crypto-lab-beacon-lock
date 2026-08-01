/**
 * The plain-language on-ramp. No math, no hex, before anything else on the
 * page — §2 of the lab standard calls this the single highest-leverage fix,
 * and it is the only panel a visitor is guaranteed to read.
 */

import { add, el, expert, glossary, panel } from './dom'

export function mountIntro(host: HTMLElement): void {
  const section = panel('intro', 'Send a message to the future')

  add(
    section,
    el('p', {
      class: 'lede-big',
      text:
        'You can encrypt something today so that nobody — including you — can read it until a specific moment next week. No trusted escrow holding a copy, no "please delete this on Tuesday" promise, no server deciding when to hand it over.',
    }),
    el('p', {
      text:
        'The trick is to borrow a clock that already exists in public. A randomness beacon publishes a fresh signed number every few seconds, forever, on a fixed schedule. Encrypt to a round that has not happened yet, and the signature the beacon will publish for that round turns out to be exactly the decryption key. Until then the key does not exist anywhere, because nobody has signed that round yet.',
    }),
    el('p', {
      text:
        'That is the whole idea, and the surprising part is that nobody has to do any work to make you wait. Two older answers to the same problem make somebody grind through a pile of computation. This one just waits, and so does everyone else, at exactly the same speed.',
    }),
  )

  const three = el('div', { class: 'threeup' })
  const models: Array<[string, string, string]> = [
    [
      'Make one person grind',
      'Time-lock puzzle',
      'Hide the secret behind a few trillion sequential squarings. Whoever wants it, pays for it — and a faster machine pays less.',
    ],
    [
      'Make the work reusable',
      'Verifiable delay function',
      'Same grind, but the answer comes with a short proof, so the world only has to do it once.',
    ],
    [
      'Make everybody wait',
      'Beacon timelock',
      'Nobody grinds at all. The key arrives on a public schedule and arrives for everyone at the same instant.',
    ],
  ]
  for (const [kicker, name, body] of models) {
    three.appendChild(
      el(
        'div',
        { class: 'threeup-card' },
        el('span', { class: 'threeup-kicker', text: kicker }),
        el('h3', { class: 'threeup-name', text: name }),
        el('p', { class: 'threeup-body', text: body }),
      ),
    )
  }
  add(
    section,
    el('h3', { text: 'Three ways to delay a secret' }),
    three,
    el('p', {
      class: 'note',
      text: 'The comparison exhibit below lets you turn the adversary’s hardware up and watch which of the three still holds.',
    }),
  )

  add(
    section,
    expert(
      'The one-line version for someone who already knows IBE',
      el('p', {
        text:
          'Beacon timelock is Boneh–Franklin identity-based encryption with the identity set to a future round number. The beacon is the private key generator; it extracts exactly one identity key per round, publicly, on a timer, and it cannot be persuaded to extract early. The "IBE private key" for round n is the beacon’s BLS signature on round n — the same bytes anybody can download the moment they exist.',
      }),
      el('p', {
        text:
          'It is emphatically not witness encryption. There is no NP statement and no obligation to find a witness: the release condition is "this specific key material got published", not "somebody proved something".',
      }),
    ),
    expert(
      'Words this page uses',
      glossary([
        [
          'Beacon',
          'A service that publishes a fresh, unpredictable, publicly verifiable random value on a fixed schedule. drand is the one this lab models.',
        ],
        [
          'Round',
          'One tick of the beacon, numbered from 1. drand’s quicknet chain publishes round n three seconds after round n−1, forever.',
        ],
        [
          'BLS signature',
          'A signature scheme where a signature is a single curve point, signatures add together, and verification is one pairing check. It is what lets twenty machines jointly sign without any of them holding the key.',
        ],
        [
          'Pairing',
          'A function e(P, Q) taking two curve points to a third kind of number, with the property that scalars slide across it: e(a·P, b·Q) = e(P, Q)^(a·b). Everything on this page is that one line.',
        ],
        [
          'IBE',
          'Identity-based encryption. You encrypt to an arbitrary string — an email address, a date, a round number — and an authority holding a master secret can extract the matching decryption key.',
        ],
        [
          'Identity',
          'The string a ciphertext is addressed to. Here it is SHA-256 of the target round number, which is why anyone can compute it in advance.',
        ],
      ]),
    ),
  )

  host.appendChild(section)
}
