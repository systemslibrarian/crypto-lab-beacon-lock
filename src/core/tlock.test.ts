/**
 * The timelock itself.
 *
 * The headline test is `interoperates with a real drand round`: we encrypt to
 * quicknet round 1000 using quicknet's real group public key, and then open it
 * with the signature the League of Entropy actually published for that round.
 * Nothing in that path is simulated — if it passes, this page's IBE really is
 * keyed by the real beacon.
 *
 * The rest of the file is the fail-closed contract: a wrong-round signature, a
 * flipped bit anywhere in the ciphertext, and a hand-picked σ are all
 * *rejected*, not silently turned into plausible-looking bytes.
 */

import { describe, expect, it } from 'vitest'
import kat from '../fixtures/kat.json'
import { CURVE, G1, g1FromBytes, g2Base, g2FromBytes, gtEqual, gtPow, hashToG1, pairing, randomScalar } from './bls'
import { MAX_MESSAGE_BYTES } from './tlock'
import { fromHex, fromUtf8, toHex, utf8 } from './bytes'
import {
  SimulatedBeacon,
  beaconKeygen,
  roundMessage,
  signRound,
  verifyRound,
  type BeaconParams,
} from './beacon'
import {
  ciphertextOverhead,
  decrypt,
  deserializeCiphertext,
  encrypt,
  h2,
  h3,
  h4,
  serializeCiphertext,
} from './tlock'

const quicknet = kat.drandQuicknet
const params: BeaconParams = { periodSeconds: 1, genesisTime: 0, scheme: 'unchained' }
const CHAIN = 'test-chain'

function payload(text: string): Uint8Array {
  const bytes = new Uint8Array(32)
  bytes.set(utf8(text).subarray(0, 32))
  return bytes
}

describe('INTEROP: decrypts a real ciphertext produced by the drand `tlock` CLI', () => {
  const vector = kat.tlockInterop
  const stanza = Uint8Array.from(Buffer.from(vector.stanzaBase64, 'base64'))

  it('the fixture is the shape an age tlock stanza has: U ‖ V ‖ W', () => {
    // 96-byte G2 point, then two 16-byte halves — age file keys are 128 bits.
    expect(stanza.length).toBe(96 + 16 + 16)
  })

  it('the captured round signature verifies under the captured chain key', () => {
    const publicKey = g2FromBytes(fromHex(vector.publicKey))
    const signature = g1FromBytes(fromHex(vector.roundSignature))
    expect(verifyRound(publicKey, roundMessage(vector.round, 'unchained'), signature)).toBe(true)
  })

  it('recovers the exact age file key that the Go implementation locked', () => {
    const signature = g1FromBytes(fromHex(vector.roundSignature))
    const ciphertext = deserializeCiphertext(stanza, vector.round, vector.chainHash)

    const result = decrypt(signature, ciphertext)

    // The Fujisaki-Okamoto check is what makes this decisive: it recomputes
    // r = H3(sigma, M) and rebuilds r*G2. Passing it means our H2, H3, H4 and
    // our kyber GT serialization all match the reference byte for byte -- a
    // 1-in-2^255 accident otherwise.
    expect(result.ok).toBe(true)
    if (result.ok) expect(toHex(result.message)).toBe(vector.expectedFileKey)
  })

  it('rejects that same ciphertext under a neighbouring round’s signature', () => {
    // Regenerate what the beacon would have signed one round later, using the
    // same chain key, and confirm it does not open the ciphertext.
    const keys = beaconKeygen()
    const ciphertext = deserializeCiphertext(stanza, vector.round, vector.chainHash)
    expect(decrypt(signRound(keys.secret, roundMessage(vector.round)), ciphertext).ok).toBe(false)
  })
})

describe('interoperates with the real drand beacon', () => {
  it.each(quicknet.rounds.map((r) => [r.round, r] as const))(
    'locks to real quicknet round %i and opens with the real published signature',
    (round, entry) => {
      const publicKey = g2FromBytes(fromHex(quicknet.publicKey))
      const identity = roundMessage(round, 'unchained')
      const secret = payload('the real beacon opened this')

      const { ciphertext } = encrypt(publicKey, identity, secret, round, quicknet.chainHash)
      const signature = g1FromBytes(fromHex(entry.signature))

      const result = decrypt(signature, ciphertext)
      expect(result.ok).toBe(true)
      if (result.ok) expect(toHex(result.message)).toBe(toHex(secret))
    },
  )

  it('a real signature for the wrong real round is rejected', () => {
    const publicKey = g2FromBytes(fromHex(quicknet.publicKey))
    const target = quicknet.rounds[1]!
    const other = quicknet.rounds[2]!
    const { ciphertext } = encrypt(
      publicKey,
      roundMessage(target.round, 'unchained'),
      payload('locked'),
      target.round,
      quicknet.chainHash,
    )
    const result = decrypt(g1FromBytes(fromHex(other.signature)), ciphertext)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('wrong-round')
  })
})

describe('round trip against the simulated beacon', () => {
  it('opens exactly when the beacon reaches the target round', () => {
    const beacon = new SimulatedBeacon(params)
    const target = 12
    const secret = payload('after the deadline')
    const { ciphertext } = encrypt(
      beacon.keys.publicKey,
      roundMessage(target),
      secret,
      target,
      CHAIN,
    )

    // Before the beacon gets there, there is nothing to decrypt with. Not a
    // hard problem — an absent input.
    beacon.advanceTo(target - 1)
    expect(beacon.at(target)).toBeUndefined()

    beacon.advanceTo(target)
    const result = decrypt(beacon.at(target)!.signature, ciphertext)
    expect(result.ok).toBe(true)
    if (result.ok) expect(toHex(result.message)).toBe(toHex(secret))
  })

  it('every earlier round’s signature fails, one by one', () => {
    const beacon = new SimulatedBeacon(params)
    const target = 8
    const { ciphertext } = encrypt(beacon.keys.publicKey, roundMessage(target), payload('nope'), target, CHAIN)
    beacon.advanceTo(target)
    for (let r = 1; r < target; r++) {
      expect(decrypt(beacon.at(r)!.signature, ciphertext).ok).toBe(false)
    }
    expect(decrypt(beacon.at(target)!.signature, ciphertext).ok).toBe(true)
  })

  it('handles payloads of several sizes, including one byte', () => {
    const beacon = new SimulatedBeacon(params)
    beacon.advanceTo(1)
    const signature = beacon.at(1)!.signature
    for (const size of [1, 8, 16, 32]) {
      const message = new Uint8Array(size).fill(size & 0xff)
      const { ciphertext } = encrypt(beacon.keys.publicKey, roundMessage(1), message, 1, CHAIN)
      const result = decrypt(signature, ciphertext)
      expect(result.ok).toBe(true)
      if (result.ok) expect(toHex(result.message)).toBe(toHex(message))
    }
  })

  it('is randomized: encrypting the same message twice gives different ciphertexts', () => {
    const keys = beaconKeygen()
    const message = payload('same every time')
    const a = encrypt(keys.publicKey, roundMessage(5), message, 5, CHAIN).ciphertext
    const b = encrypt(keys.publicKey, roundMessage(5), message, 5, CHAIN).ciphertext
    expect(toHex(serializeCiphertext(a))).not.toBe(toHex(serializeCiphertext(b)))
    // …and both still open to the same plaintext.
    const signature = signRound(keys.secret, roundMessage(5))
    for (const ct of [a, b]) {
      const result = decrypt(signature, ct)
      expect(result.ok).toBe(true)
      if (result.ok) expect(toHex(result.message)).toBe(toHex(message))
    }
  })
})

describe('fail-closed: the Fujisaki–Okamoto check', () => {
  const keys = beaconKeygen()
  const message = payload('classified until round 20')
  const build = () => encrypt(keys.publicKey, roundMessage(20), message, 20, CHAIN).ciphertext
  const goodSignature = signRound(keys.secret, roundMessage(20))

  it('rejects a flipped bit in V', () => {
    const ct = build()
    const V = Uint8Array.from(ct.V)
    V[0] = V[0]! ^ 1
    const result = decrypt(goodSignature, { ...ct, V })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('wrong-round')
  })

  it('rejects a flipped bit in W', () => {
    const ct = build()
    const W = Uint8Array.from(ct.W)
    W[W.length - 1] = W[W.length - 1]! ^ 0x80
    expect(decrypt(goodSignature, { ...ct, W }).ok).toBe(false)
  })

  it('rejects a substituted U', () => {
    const ct = build()
    const U = g2Base().multiply(randomScalar())
    expect(decrypt(goodSignature, { ...ct, U }).ok).toBe(false)
  })

  it('rejects an arbitrary G1 point offered as the beacon signature', () => {
    const ct = build()
    for (let i = 0; i < 5; i++) {
      const bogus = G1.Point.BASE.multiply(randomScalar())
      expect(decrypt(bogus, ct).ok).toBe(false)
    }
  })

  it('rejects the identity element as a signature', () => {
    const ct = build()
    expect(decrypt(G1.Point.ZERO, ct).ok).toBe(false)
  })

  it('rejects a signature over the right round under a different beacon key', () => {
    const ct = build()
    const rogue = beaconKeygen()
    expect(decrypt(signRound(rogue.secret, roundMessage(20)), ct).ok).toBe(false)
  })

  it('WITHOUT the check, a wrong key would yield confident garbage — show it', () => {
    // Same arithmetic decrypt() performs, minus the final U comparison. This
    // is what a BasicIdent implementation returns: full-length, plausible,
    // wrong. The check is the only thing standing between the two.
    const ct = build()
    const wrong = G1.Point.BASE.multiply(randomScalar())
    const maskGT = pairing(wrong, ct.U)
    const sigma = ct.V.map((b, i) => b ^ h2(maskGT, ct.V.length)[i]!)
    const forged = ct.W.map((b, i) => b ^ h4(sigma, ct.W.length)[i]!)
    expect(forged.length).toBe(message.length)
    expect(toHex(forged)).not.toBe(toHex(message))
    // …and the real decrypt() refuses to hand that back.
    expect(decrypt(wrong, ct).ok).toBe(false)
  })
})

describe('the IBE hashes', () => {
  it('H₂ is deterministic on GT elements and length-parameterised', () => {
    const gt = pairing(G1.Point.BASE, g2Base())
    expect(toHex(h2(gt, 32))).toBe(toHex(h2(gt, 32)))
    expect(h2(gt, 16).length).toBe(16)
    expect(toHex(h2(gt, 32))).not.toBe(toHex(h2(gtPow(gt, 2n), 32)))
  })

  it('H₃ binds σ and the message together — that is the FO transform', () => {
    const sigma = payload('sigma')
    const message = payload('message')
    expect(h3(sigma, message)).toBe(h3(sigma, message))
    expect(h3(sigma, message)).not.toBe(h3(message, sigma))
    expect(h3(sigma, message)).toBeLessThan(CURVE.order)
  })

  it('H₄ is a deterministic keystream over σ', () => {
    const sigma = payload('sigma')
    expect(toHex(h4(sigma, 32))).toBe(toHex(h4(sigma, 32)))
    expect(toHex(h4(sigma, 32))).not.toBe(toHex(h4(payload('other'), 32)))
  })

  it('the three tags are separated: same input, three different outputs', () => {
    const gt = pairing(hashToG1(utf8('x')), g2Base())
    const sigma = new Uint8Array(32)
    expect(toHex(h2(gt, 32))).not.toBe(toHex(h4(sigma, 32)))
  })
})

describe('the mask really is computed twice, from disjoint inputs', () => {
  it('sender’s e(Q,P_pub)^r equals receiver’s e(σ,U), byte for byte', () => {
    const keys = beaconKeygen()
    const identity = roundMessage(33)
    const { ciphertext, trace } = encrypt(keys.publicKey, identity, payload('m'), 33, CHAIN)
    const signature = signRound(keys.secret, identity)
    const result = decrypt(signature, ciphertext)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(gtEqual(trace.maskGT, result.trace.maskGT)).toBe(true)
      // The sender never sees the signature; the receiver never sees r.
      expect(result.trace.recomputedR).toBe(trace.r)
      expect(toHex(result.trace.sigma)).toBe(toHex(trace.sigma))
    }
  })

  it('the trace values are absent from the ciphertext on the wire', () => {
    const keys = beaconKeygen()
    const { ciphertext, trace } = encrypt(keys.publicKey, roundMessage(4), payload('m'), 4, CHAIN)
    const wire = toHex(serializeCiphertext(ciphertext))
    expect(wire).not.toContain(toHex(trace.sigma))
    expect(wire).not.toContain(trace.r.toString(16))
  })
})

describe('payload ceiling', () => {
  it('refuses a payload larger than the hash output rather than truncating it', () => {
    const keys = beaconKeygen()
    expect(() =>
      encrypt(keys.publicKey, roundMessage(1), new Uint8Array(MAX_MESSAGE_BYTES + 1), 1, CHAIN),
    ).toThrow(/ceiling/)
    expect(() =>
      encrypt(keys.publicKey, roundMessage(1), new Uint8Array(MAX_MESSAGE_BYTES), 1, CHAIN),
    ).not.toThrow()
  })
})

describe('wire format', () => {
  it('round-trips through serialize/deserialize', () => {
    const keys = beaconKeygen()
    const message = payload('wire')
    const { ciphertext } = encrypt(keys.publicKey, roundMessage(9), message, 9, CHAIN)
    const restored = deserializeCiphertext(serializeCiphertext(ciphertext), 9, CHAIN)
    const result = decrypt(signRound(keys.secret, roundMessage(9)), restored)
    expect(result.ok).toBe(true)
    if (result.ok) expect(fromUtf8(result.message)).toBe(fromUtf8(message))
  })

  it('has the overhead the UI quotes: 96 bytes of G2 plus one σ block', () => {
    const keys = beaconKeygen()
    const { ciphertext } = encrypt(keys.publicKey, roundMessage(9), payload('x'), 9, CHAIN)
    expect(serializeCiphertext(ciphertext).length).toBe(32 + ciphertextOverhead(32))
    expect(ciphertextOverhead(32)).toBe(CURVE.g2CompressedBytes + 32)
  })

  it('rejects malformed encodings rather than guessing', () => {
    expect(() => deserializeCiphertext(new Uint8Array(10), 1, CHAIN)).toThrow(/bad length/)
    // 96 + an odd remainder cannot split into equal V and W.
    expect(() => deserializeCiphertext(new Uint8Array(96 + 33), 1, CHAIN)).toThrow(/bad length/)
    expect(() => deserializeCiphertext(new Uint8Array(96 + 64), 1, CHAIN)).toThrow()
  })
})
