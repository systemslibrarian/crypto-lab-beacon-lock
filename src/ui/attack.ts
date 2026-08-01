/**
 * Break it yourself.
 *
 * Every entry runs against the same `decrypt()` and the same AES-GCM the rest
 * of the page uses — there is no separate "demo verifier" that is easier to
 * fool. Pick an attack, watch the real code refuse it, and read what refused.
 *
 * One entry succeeds: the beacon operator signing a round before its time.
 * It renders as ALARM, not as success, because the colour on this page tracks
 * whether the system held, not whether the function returned a value.
 */

import { beaconKeygen, roundMessage, signRound } from '../core/beacon'
import { G1, g2Base, hashToG1, randomScalar, type G1Point, type G2Point } from '../core/bls'
import { beU64, toHex } from '../core/bytes'
import { flipBit } from './bits'
import { open, seal } from '../core/envelope'
import { decrypt, encrypt } from '../core/tlock'
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
  panel,
  stat,
  statRow,
  verdict,
  type Tone,
} from './dom'

const TARGET = 100
const PLAINTEXT = 'The vote tally is 61–39. Sealed until the polls close.'

interface AttackResult {
  readonly tone: Tone
  readonly headline: string
  readonly detail: string
  readonly explain: string
  readonly evidence?: { label: string; value: string }
}

interface Attack {
  readonly id: string
  readonly label: string
  readonly premise: string
  run(): Promise<AttackResult>
}

export function mountAttack(host: HTMLElement): void {
  const section = panel(
    'attack',
    'Break it yourself',
    'A ciphertext locked to round 100, a beacon that has only reached round 60, and nine ways to try to read it early. Every one runs against the real decryptor.',
  )

  // A dedicated scenario, so attacks are reproducible and independent of the
  // ticking clock upstairs.
  const keys = beaconKeygen()
  const identity = roundMessage(TARGET, 'unchained')
  const aad = beU64(TARGET)
  const sealedKey = new Uint8Array(32)
  crypto.getRandomValues(sealedKey)

  /** A fresh ciphertext per attempt, so one attack never contaminates the next. */
  const build = async () => {
    const payload = await seal(sealedKey, PLAINTEXT, aad)
    const { ciphertext } = encrypt(keys.publicKey, identity, sealedKey, TARGET, 'attack-lab')
    return { ciphertext, payload }
  }

  const select = el('select', { id: 'attack-choice' })
  const out = liveRegion('Attack result')
  const stats = el('div', { class: 'statrow' })

  const attacks: Attack[] = [
    {
      id: 'wrong-round',
      label: 'Use the beacon’s genuine signature for round 60',
      premise: 'A real, valid, correctly signed round — just not the right one.',
      async run() {
        const { ciphertext } = await build()
        const result = decrypt(signRound(keys.secret, roundMessage(60, 'unchained')), ciphertext)
        return refusal(
          result.ok,
          'the recomputed U did not match the U in the ciphertext',
          'Signatures are not interchangeable. σ₆₀ pairs with U to give e(Q₆₀, G₂)^(s·r), and the ciphertext was masked with e(Q₁₀₀, G₂)^(s·r). Different identity, different group element, and the Fujisaki–Okamoto check notices.',
        )
      },
    },
    {
      id: 'forge-sig',
      label: 'Forge a signature from a scalar you choose',
      premise: 'Pick your own secret k and compute k·H₁(round 100). It is a well-formed G1 point.',
      async run() {
        const { ciphertext } = await build()
        const k = randomScalar()
        const forged = hashToG1(identity).multiply(k) as G1Point
        const result = decrypt(forged, ciphertext)
        return refusal(
          result.ok,
          'well-formed, on the curve, in the subgroup — and still wrong',
          'The point is valid; it is simply not s·Q. Producing s·Q from Q and s·G₂ is the computational Diffie–Hellman problem in G1, which is what the scheme’s security reduces to. Being able to make points is not the hard part.',
          { label: 'Your forged “signature”', value: elide(toHex(forged.toBytes()), 48, 16) },
        )
      },
    },
    {
      id: 'identity-point',
      label: 'Offer the identity element as the signature',
      premise: 'The degenerate input every implementation should reject.',
      async run() {
        const { ciphertext } = await build()
        return refusal(
          decrypt(G1.Point.ZERO, ciphertext).ok,
          'the point at infinity pairs to the identity of GT, which unmasks nothing',
          'Worth trying because plenty of real code has crashed or silently accepted here. This path computes the pairing, derives a σ, derives a message, and then fails the consistency check like any other wrong input — no special case, no exception.',
        )
      },
    },
    {
      id: 'flip-v',
      label: 'Flip one bit in V',
      premise: 'You cannot open it, but perhaps you can corrupt it usefully.',
      async run() {
        const { ciphertext } = await build()
        const V = flipBit(ciphertext.V, 0, 1)
        return refusal(
          decrypt(signRound(keys.secret, identity), { ...ciphertext, V }).ok,
          'one flipped bit in V, and the ciphertext no longer opens at all',
          'V carries σ, and σ determines r through H₃. Change σ by a bit and the recomputed r is unrelated, so r·G₂ lands nowhere near U. This is the FO transform doing what it was designed for: making the ciphertext non-malleable rather than merely private.',
        )
      },
    },
    {
      id: 'flip-w',
      label: 'Flip one bit in W',
      premise: 'The component that actually carries the message.',
      async run() {
        const { ciphertext } = await build()
        const W = flipBit(ciphertext.W, 3, 0x40)
        return refusal(
          decrypt(signRound(keys.secret, identity), { ...ciphertext, W }).ok,
          'the message is bound into r, so editing it invalidates the ciphertext',
          'Without the FO transform this would be a clean bit-flip on the plaintext — the classic malleability of a one-time pad. With it, r = H₃(σ, M) covers the message, so a flipped plaintext bit changes r and the check fails.',
        )
      },
    },
    {
      id: 'swap-u',
      label: 'Substitute your own U',
      premise: 'Replace the sender’s ephemeral point with r′·G₂ for an r′ you know.',
      async run() {
        const { ciphertext } = await build()
        const U = g2Base().multiply(randomScalar()) as G2Point
        return refusal(
          decrypt(signRound(keys.secret, identity), { ...ciphertext, U }).ok,
          'knowing r′ does not help without also being able to remask V and W',
          'You can certainly build a U you understand. What you cannot do is make V and W consistent with it, because that would require the mask e(Q₁₀₀, P_pub)^r′ — computable — and then a σ and M whose H₃ returns your r′, which is the preimage problem you started with.',
        )
      },
    },
    {
      id: 'relabel',
      label: 'Relabel the ciphertext with an earlier round',
      premise: 'Leave the crypto alone and just edit the header to say round 60.',
      async run() {
        const { ciphertext, payload } = await build()
        // The timelock ciphertext itself carries no authenticated round, but the
        // AEAD does: the round is its associated data.
        const relabelled = { ...ciphertext, round: 60 }
        const result = decrypt(signRound(keys.secret, roundMessage(60, 'unchained')), relabelled)
        if (result.ok) {
          const text = await open(result.message, payload, beU64(60))
          return {
            tone: 'ok',
            headline: 'Rejected',
            detail: 'the AEAD tag is computed over the round number',
            explain: `Even in the branch where the timelock happened to open, the envelope would not: ${text === null ? 'AES-GCM returned nothing' : 'it returned the plaintext'}. Binding the round in as associated data is what stops a ciphertext being re-dated.`,
          }
        }
        return refusal(
          false,
          'the identity is derived from the round, so relabelling changes what key is needed',
          'The header is not a label the decryptor trusts — it is an instruction about which identity to use. Point it at round 60 and you are simply asking for a different ciphertext, which this is not. The AEAD tag over the round number closes the same door from the other side.',
        )
      },
    },
    {
      id: 'edit-payload',
      label: 'Edit the AES payload',
      premise: 'Change the sealed text and hope it opens to something you prefer.',
      async run() {
        const { ciphertext, payload } = await build()
        const tampered = flipBit(payload.ciphertext, 5, 0xff)
        const result = decrypt(signRound(keys.secret, identity), ciphertext)
        if (!result.ok) return refusal(false, 'unexpected', 'unexpected')
        const text = await open(result.message, { ...payload, ciphertext: tampered }, aad)
        return {
          tone: text === null ? 'ok' : 'alarm',
          headline: text === null ? 'Rejected' : 'Accepted — this would be a bug',
          detail:
            text === null
              ? 'AES-256-GCM authenticated the payload and refused'
              : 'the AEAD returned a plaintext for edited input',
          explain:
            'The timelock is only responsible for the key. Integrity of the message is the envelope’s job, and GCM’s tag does it — this is the same reason you do not ship raw CTR mode.',
        }
      },
    },
    {
      id: 'operator',
      label: 'Be the beacon operator and sign round 100 early',
      premise: 'The one attack that works. It is not a break of the maths.',
      async run() {
        const { ciphertext, payload } = await build()
        const result = decrypt(signRound(keys.secret, identity), ciphertext)
        if (!result.ok) return refusal(false, 'unexpected', 'unexpected')
        const text = await open(result.message, payload, aad)
        return {
          tone: 'alarm',
          headline: 'Opened early',
          detail: 'holding s, the operator can extract any identity’s key at any time',
          explain:
            'Nothing was broken. IBE hands the master secret holder every private key by construction, and a timelock beacon is an IBE authority that has merely promised to extract on schedule. This is why drand is a threshold system across twenty organisations rather than a service: the assumption is not "the operator is honest", it is "a threshold of twenty independent operators do not collude".',
          evidence: { label: 'Recovered plaintext', value: text ?? '(envelope refused)' },
        }
      },
    },
  ]

  for (const a of attacks) select.appendChild(el('option', { value: a.id, text: a.label }))

  const runBtn = button('Run it against the real decryptor', () => void runSelected())
  select.addEventListener('change', () => void runSelected())

  add(
    section,
    statRow(
      stat('Ciphertext locked to', `round ${TARGET}`),
      stat('Beacon has reached', 'round 60'),
      stat('Decryptor', 'the same decrypt() the rest of the page uses'),
    ),
    el(
      'div',
      { class: 'controls' },
      el(
        'div',
        { class: 'ctl ctl-wide' },
        el('label', { class: 'ctl-label', for: 'attack-choice', text: 'Attack' }),
        select,
      ),
      runBtn,
    ),
    stats,
    out,
    honesty(
      'Eight of these nine fail, and they fail for reasons you can read. The ninth succeeds and is coloured as an alarm even though decryption returned a plaintext, because what the colour tracks on this page is whether the system held — not what the function returned.',
    ),
    expert(
      'What would actually break this',
      el(
        'ul',
        { class: 'rules' },
        el('li', {
          text: 'Solving computational Diffie–Hellman in G1 on BLS12-381 — deriving s·Q from (Q, s·G₂). Around 2¹²⁶ work classically, and this is the assumption the whole scheme sits on.',
        }),
        el('li', {
          text: 'A large-scale quantum computer. Shor’s algorithm recovers s from s·G₂, and every ciphertext ever locked to that chain opens at once, retroactively. Timelock encryption is not post-quantum, and nobody has a pairing-free replacement with the same properties.',
        }),
        el('li', {
          text: 'Compromising a threshold of the beacon’s operators, who could then extract far-future round keys quietly and never publish that they did.',
        }),
        el('li', {
          text: 'A weakness in RFC 9380 hash-to-curve that made H₁ predictable in the wrong way — which is why the DST string is part of the spec and not a parameter.',
        }),
      ),
    ),
  )
  host.appendChild(section)

  async function runSelected(): Promise<void> {
    const attack = attacks.find((a) => a.id === select.value) ?? attacks[0]!
    clear(out)
    clear(stats)
    const result = await attack.run()
    clear(out)
    add(
      out,
      el('p', { class: 'claim', text: attack.premise }),
      verdict(result.tone, result.headline, result.detail),
      el('p', { class: 'explain', text: result.explain }),
      result.evidence
        ? el(
            'div',
            {},
            el('h4', { text: result.evidence.label }),
            hexBlock(result.evidence.value, result.evidence.label),
          )
        : null,
    )
  }

  void runSelected()
}

function refusal(
  succeeded: boolean,
  detail: string,
  explain: string,
  evidence?: { label: string; value: string },
): AttackResult {
  return {
    // A refusal is the system holding, so it reads as OK. If one of these ever
    // succeeded it would be an alarm, and the label says so.
    tone: succeeded ? 'alarm' : 'ok',
    headline: succeeded ? 'Accepted — this would be a break' : 'Rejected',
    detail,
    explain,
    ...(evidence ? { evidence } : {}),
  }
}
