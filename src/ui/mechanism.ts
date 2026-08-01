/**
 * The headline mechanism, stepped rather than asserted.
 *
 * Everything else on the page is an application of one line:
 *
 *     e(Q, s·G₂)^r  =  e(Q, G₂)^(s·r)  =  e(s·Q, r·G₂)
 *      └─ sender ─┘                       └─ receiver ─┘
 *
 * The sender walks the left path using only public data. The beacon later
 * publishes s·Q. The receiver walks the right path. Neither ever holds what
 * the other held, and they arrive at the same 576-byte element of GT. Step 6
 * prints both and compares them digit by digit — that comparison is the entire
 * point of this exhibit, and it is why the panel refuses to simply say "they
 * are equal".
 *
 * This runs its own standalone beacon so it holds still while you step through
 * it; the ticking clock upstairs would otherwise move under your feet.
 */

import { beaconKeygen, roundMessage, signRound } from '../core/beacon'
import { g2Base, gtEqual, gtToBytes, hashToG1, pairing } from '../core/bls'
import { toHex, xor } from '../core/bytes'
import { encrypt, h2, h4 } from '../core/tlock'
import {
  add,
  button,
  clear,
  el,
  elide,
  expert,
  hexBlock,
  hexDiff,
  panel,
  stat,
  statRow,
  verdict,
} from './dom'

const TARGET_ROUND = 4_500_000

interface Run {
  readonly round: number
  readonly identity: Uint8Array
  readonly Q: ReturnType<typeof hashToG1>
  readonly publicKey: ReturnType<typeof g2Base>
  readonly secret: bigint
  readonly r: bigint
  readonly U: ReturnType<typeof g2Base>
  readonly senderMask: ReturnType<typeof pairing>
  readonly signature: ReturnType<typeof signRound>
  readonly receiverMask: ReturnType<typeof pairing>
  readonly V: Uint8Array
  readonly W: Uint8Array
  readonly sigma: Uint8Array
  readonly plaintext: Uint8Array
}

function buildRun(): Run {
  const keys = beaconKeygen()
  const identity = roundMessage(TARGET_ROUND, 'unchained')
  const plaintext = new Uint8Array(32)
  crypto.getRandomValues(plaintext)

  const { ciphertext, trace } = encrypt(
    keys.publicKey,
    identity,
    plaintext,
    TARGET_ROUND,
    'mechanism',
  )
  const signature = signRound(keys.secret, identity)

  return {
    round: TARGET_ROUND,
    identity,
    Q: trace.Q,
    publicKey: keys.publicKey,
    secret: keys.secret,
    r: trace.r,
    U: ciphertext.U,
    senderMask: trace.maskGT,
    signature,
    receiverMask: pairing(signature, ciphertext.U),
    V: ciphertext.V,
    W: ciphertext.W,
    sigma: trace.sigma,
    plaintext,
  }
}

interface Step {
  readonly title: string
  readonly actor: 'setup' | 'sender' | 'beacon' | 'receiver'
  readonly algebra: string
  render(host: HTMLElement, run: Run): void
}

const STEPS: readonly Step[] = [
  {
    title: 'The beacon has a key pair, and publishes half of it',
    actor: 'setup',
    algebra: 'P_pub = s · G₂',
    render(host, run) {
      add(
        host,
        el('p', {
          text: 'One scalar s, held by the beacon operator and never published. Its public counterpart P_pub is a point in G2 that anybody can download. In IBE terms this is the master key pair; on drand it is the group public key, and s is split across the League of Entropy so no single node ever holds it.',
        }),
        statRow(
          stat('Master secret s', 'held by the beacon — never leaves it', 'warn'),
          stat('Group public key', `${run.publicKey.toBytes().length} B in G2`, 'ok'),
        ),
        hexBlock(elide(toHex(run.publicKey.toBytes()), 64, 24), 'Group public key P_pub'),
      )
    },
  },
  {
    title: 'Name a future moment — that name is the identity',
    actor: 'sender',
    algebra: 'm = SHA-256( uint64_be(round) )',
    render(host, run) {
      add(
        host,
        el('p', {
          text: `The sender picks round ${run.round.toLocaleString()} — roughly a hundred and fifty days out at three seconds a round — and hashes the number. No secret, no network, no permission. On an unchained beacon this is the whole of "addressing the future".`,
        }),
        hexBlock(toHex(run.identity), 'Identity bytes for the target round'),
        el('p', {
          class: 'note',
          text: 'In ordinary IBE this slot holds "alice@example.com". Here it holds a timestamp. The scheme cannot tell the difference, which is exactly why the substitution works.',
        }),
      )
    },
  },
  {
    title: 'Put the identity on the curve',
    actor: 'sender',
    algebra: 'Q = H₁(m) ∈ G1',
    render(host, run) {
      add(
        host,
        el('p', {
          text: 'RFC 9380 hash-to-curve maps those 32 bytes to a point in G1 — the same map, under the same domain separation tag, that drand uses when it signs. Nobody knows a scalar q with Q = q·G₁, which is what stops anyone from short-cutting to the signature.',
        }),
        hexBlock(toHex(run.Q.toBytes()), 'Q, the round’s point in G1'),
      )
    },
  },
  {
    title: 'Encrypt to it — the sender’s half of the pairing',
    actor: 'sender',
    algebra: 'U = r · G₂    mask = e(Q, P_pub)^r',
    render(host, run) {
      add(
        host,
        el('p', {
          text: 'The sender draws a one-time scalar r, publishes U = r·G₂ inside the ciphertext, and derives a masking element of GT by pairing the round’s point against the beacon’s public key, then raising to r. The mask is used and discarded; r is destroyed. Neither is ever transmitted.',
        }),
        statRow(
          stat('U (in the ciphertext)', `${run.U.toBytes().length} B in G2`, 'ok'),
          stat('r (destroyed)', `${run.r.toString(16).length * 4} bits`, 'warn'),
          stat('mask (never sent)', `${gtToBytes(run.senderMask).length} B in GT`, 'warn'),
        ),
        hexBlock(elide(toHex(run.U.toBytes()), 64, 24), 'U — the sender’s ephemeral public value'),
        el('p', {
          class: 'note',
          text: 'At this instant the ciphertext exists and nothing in the universe can open it. The other half of the pairing needs s·Q, and nobody has signed that round.',
        }),
      )
    },
  },
  {
    title: 'Wait. Nobody can help you.',
    actor: 'sender',
    algebra: '⏳',
    render(host) {
      const table = el('table', { class: 'datatable' })
      add(
        table,
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', { scope: 'col', text: 'Who' }),
            el('th', { scope: 'col', text: 'Holds' }),
            el('th', { scope: 'col', text: 'Can open it early?' }),
          ),
        ),
      )
      const body = el('tbody')
      const rows: Array<[string, string, string]> = [
        ['The sender', 'nothing — r and the mask were destroyed', 'No'],
        ['The recipient', 'the ciphertext', 'No'],
        ['The beacon operator', 's, and the schedule', 'Yes — by signing early'],
        ['An adversary with a warehouse of GPUs', 'the ciphertext', 'No'],
      ]
      for (const [who, holds, can] of rows) {
        add(
          body,
          el(
            'tr',
            {},
            el('th', { scope: 'row', text: who }),
            el('td', { text: holds }),
            el('td', { class: can === 'No' ? 'cell-ok' : 'cell-alarm' }, `${can === 'No' ? '✓ ' : '✗ '}${can}`),
          ),
        )
      }
      table.appendChild(body)
      add(
        host,
        el('p', {
          text: 'Note which row is the exception. Extra hardware buys the adversary nothing at all — there is no computation to accelerate. The only party who can shorten the wait is the beacon operator, and the entire design of drand is about making that a group of twenty organisations rather than one.',
        }),
        el('div', { class: 'tablewrap', tabindex: '0', role: 'region', 'aria-label': 'Who can open the ciphertext early' }, table),
      )
    },
  },
  {
    title: 'The round arrives. The beacon signs it in public.',
    actor: 'beacon',
    algebra: 'σ = s · Q',
    render(host, run) {
      add(
        host,
        el('p', {
          text: 'This is an ordinary beacon round — the same 48 bytes the network would publish anyway, for anyone who wanted randomness. It is also, without any modification, the IBE private key for this identity. That coincidence is the whole scheme.',
        }),
        hexBlock(toHex(run.signature.toBytes()), 'The beacon’s signature for the target round'),
        el('p', {
          class: 'note',
          text: 'The beacon did not know this ciphertext existed. It signs the round for everybody, once, and every ciphertext addressed to that round becomes openable at the same instant.',
        }),
      )
    },
  },
  {
    title: 'Both halves land on the same element of GT',
    actor: 'receiver',
    algebra: 'e(Q, P_pub)^r  =  e(σ, U)',
    render(host, run) {
      const left = toHex(gtToBytes(run.senderMask))
      const right = toHex(gtToBytes(run.receiverMask))
      add(
        host,
        el('p', {
          text: 'The sender reached this element months ago from (Q, P_pub, r). The receiver reaches it now from (σ, U). The two inputs share no secret and never met. Bilinearity says both are e(Q, G₂)^(s·r) — here are the bytes.',
        }),
        hexDiff(
          left,
          right,
          'Sender: e(Q, P_pub)^r',
          'Receiver: e(σ, U)',
        ),
        verdict(
          gtEqual(run.senderMask, run.receiverMask) ? 'ok' : 'alarm',
          gtEqual(run.senderMask, run.receiverMask) ? 'Same group element' : 'Divergence',
          '1152 hex digits, computed twice from disjoint inputs',
        ),
      )
    },
  },
  {
    title: 'Unmask — and check that you were not lied to',
    actor: 'receiver',
    algebra: 'σ = V ⊕ H₂(mask)    M = W ⊕ H₄(σ)    U ?= H₃(σ, M)·G₂',
    render(host, run) {
      const recovered = xor(run.W, h4(xor(run.V, h2(run.receiverMask, run.V.length)), run.W.length))
      add(
        host,
        el('p', {
          text: 'Two XORs recover the message. The third line is the Fujisaki–Okamoto check, and it is not optional: without it any curve point produces some 32-byte output and the receiver has no way to know it was handed garbage. With it, a wrong round, a flipped bit or a fabricated key are all refused.',
        }),
        hexDiff(toHex(run.plaintext), toHex(recovered), 'What was locked', 'What came out'),
        verdict('ok', 'Opened', 'and the FO check confirmed the ciphertext was consistent'),
      )
    },
  },
]

export function mountMechanism(host: HTMLElement): void {
  const section = panel(
    'mechanism',
    'The mechanism, one step at a time',
    'Eight steps from "name a future round" to "the plaintext is on screen". Step through them — the sixth is the one worth the ticket price.',
  )

  let run = buildRun()
  let index = 0

  const track = el('ol', { class: 'steptrack', role: 'list' })
  const body = el('div', {
    class: 'stepbody',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Current step',
  })

  const backBtn = button('Back', () => go(index - 1), 'btn-quiet btn-small')
  const nextBtn = button('Next step', () => go(index + 1), 'btn-small')
  const endBtn = button('Jump to the comparison', () => go(6), 'btn-quiet btn-small')
  const rerollBtn = button(
    'Fresh randomness',
    () => {
      run = buildRun()
      render()
    },
    'btn-quiet btn-small',
  )
  rerollBtn.title = 'Draw a new beacon key, a new r and a new message, and replay the same eight steps'

  add(
    section,
    track,
    body,
    el('div', { class: 'controls' }, backBtn, nextBtn, endBtn, rerollBtn),
    expert(
      'Why this is exactly Boneh–Franklin',
      el('p', {
        text: 'Compare with the 2001 paper. Setup produces (s, s·G₂); Extract(ID) returns s·H₁(ID); Encrypt draws r and sends (r·G₂, σ ⊕ H₂(e(H₁(ID), P_pub)^r), M ⊕ H₄(σ)); Decrypt pairs the extracted key against the first component. The only substitution this page makes is what goes into ID — a round number instead of an email address — and who runs Extract: a public timer instead of a company.',
      }),
      el('p', {
        text: 'FullIdent rather than BasicIdent, so the scheme is CCA-secure in the random oracle model and the decryptor can tell a bad ciphertext from a good one. Group layout follows drand quicknet: identities and signatures in G1, keys and U in G2.',
      }),
    ),
    expert(
      'What this does NOT prove',
      el('p', {
        text: 'That the beacon will keep running, that its operators will not collude to sign early, and that the discrete-log and bilinear Diffie–Hellman assumptions on BLS12-381 hold. It also does not prove anything about the beacon’s randomness quality — a timelock needs the beacon to be punctual and honest, not unpredictable.',
      }),
    ),
  )
  host.appendChild(section)

  function go(next: number): void {
    index = Math.max(0, Math.min(STEPS.length - 1, next))
    render()
  }

  function render(): void {
    clear(track)
    for (const [i, step] of STEPS.entries()) {
      const done = i < index
      const current = i === index
      const node = el(
        'li',
        {
          class: `stepdot ${current ? 'is-current' : done ? 'is-done' : 'is-pending'}`,
          role: 'listitem',
        },
        el('span', { class: 'stepdot-index', 'aria-hidden': 'true', text: String(i + 1) }),
        el('span', { class: 'stepdot-actor', text: step.actor }),
      )
      node.title = step.title
      track.appendChild(node)
    }

    const step = STEPS[index]!
    clear(body)
    add(
      body,
      el(
        'div',
        { class: `stepcard actor-${step.actor}` },
        el(
          'div',
          { class: 'stepcard-head' },
          el('span', { class: 'stepcard-count', text: `Step ${index + 1} of ${STEPS.length}` }),
          el('span', { class: `stepcard-actor actor-tag-${step.actor}`, text: step.actor }),
        ),
        el('h3', { class: 'stepcard-title', text: step.title }),
        el('p', { class: 'stepcard-algebra', text: step.algebra }),
      ),
    )
    const detail = el('div', { class: 'stepdetail' })
    step.render(detail, run)
    body.appendChild(detail)

    backBtn.disabled = index === 0
    nextBtn.disabled = index === STEPS.length - 1
    nextBtn.textContent = index === STEPS.length - 1 ? 'Done' : 'Next step'
  }

  render()
}
