/**
 * Curve-level known-answer tests.
 *
 * Two independent things are pinned here:
 *   1. the BLS12-381 parameters this lab quotes on screen are the published
 *      ones (draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1), and
 *   2. our hash-to-G1 is RFC 9380's BLS12381G1_XMD:SHA-256_SSWU_RO_, matched
 *      against the RFC's own vectors under the RFC's own DST.
 *
 * (2) is the load-bearing one: H₁ is where a round number becomes an IBE
 * identity, so a wrong H₁ is a demo that teaches a scheme nobody else uses.
 */

import { describe, expect, it } from 'vitest'
import kat from '../fixtures/kat.json'
import { CURVE, G1, G2, g2Base, gtEqual, gtPow, hashToG1, hashToScalar, pairing, randomScalar } from './bls'
import { g1FromBytes, g2FromBytes } from './bls'
import { fromHex, utf8 } from './bytes'

const hex = (n: bigint) => `0x${n.toString(16).padStart(96, '0')}`

describe('BLS12-381 parameters match the published curve', () => {
  it('field prime and group order', () => {
    expect(hex(CURVE.fieldPrime)).toBe(kat.curve.fieldPrime)
    expect(`0x${CURVE.order.toString(16)}`).toBe(kat.curve.groupOrder)
  })

  it('G1 generator', () => {
    const g = G1.Point.BASE.toAffine()
    expect(hex(g.x)).toBe(kat.curve.g1x)
    expect(hex(g.y)).toBe(kat.curve.g1y)
  })

  it('G2 generator', () => {
    const g = G2.Point.BASE.toAffine()
    expect(hex(g.x.c0)).toBe(kat.curve.g2x0)
    expect(hex(g.x.c1)).toBe(kat.curve.g2x1)
    expect(hex(g.y.c0)).toBe(kat.curve.g2y0)
    expect(hex(g.y.c1)).toBe(kat.curve.g2y1)
  })

  it('generators have the stated prime order', () => {
    expect(G1.Point.BASE.multiply(CURVE.order - 1n).add(G1.Point.BASE).is0()).toBe(true)
    expect(G2.Point.BASE.multiply(CURVE.order - 1n).add(G2.Point.BASE).is0()).toBe(true)
  })

  it('serialized sizes are the ones the UI quotes', () => {
    expect(G1.Point.BASE.toBytes().length).toBe(CURVE.g1CompressedBytes)
    expect(G2.Point.BASE.toBytes().length).toBe(CURVE.g2CompressedBytes)
    expect(pairing(G1.Point.BASE, G2.Point.BASE)).toBeDefined()
  })
})

describe(`RFC 9380 J.9.1 hash-to-G1 — ${kat.hashToG1.vectors.length} known-answer tests`, () => {
  it.each(kat.hashToG1.vectors.map((v) => [v.msg.slice(0, 24) || '(empty)', v] as const))(
    'msg %s',
    (_label, vector) => {
      const point = hashToG1(utf8(vector.msg), kat.hashToG1.dst).toAffine()
      expect(hex(point.x)).toBe(vector.x)
      expect(hex(point.y)).toBe(vector.y)
    },
  )

  it('lands in the prime-order subgroup, not merely on the curve', () => {
    for (const vector of kat.hashToG1.vectors) {
      const point = hashToG1(utf8(vector.msg), kat.hashToG1.dst)
      expect(() => point.assertValidity()).not.toThrow()
      expect(point.multiply(CURVE.order - 1n).add(point).is0()).toBe(true)
    }
  })

  it('separates domains: the same message under drand’s DST is a different point', () => {
    const underRfcDst = hashToG1(utf8('abc'), kat.hashToG1.dst)
    const underDrandDst = hashToG1(utf8('abc'))
    expect(underRfcDst.equals(underDrandDst)).toBe(false)
  })
})

describe('bilinearity — the single property the whole demo rests on', () => {
  it('e(a·P, b·Q) == e(P, Q)^(a·b)', () => {
    const a = randomScalar()
    const b = randomScalar()
    const P = G1.Point.BASE
    const Q = G2.Point.BASE
    const left = pairing(P.multiply(a), Q.multiply(b))
    const right = gtPow(pairing(P, Q), (a * b) % CURVE.order)
    expect(gtEqual(left, right)).toBe(true)
  })

  it('is non-degenerate: e(G1, G2) is not the identity', () => {
    const e = pairing(G1.Point.BASE, G2.Point.BASE)
    expect(gtEqual(e, gtPow(e, 0n))).toBe(false)
  })

  it('the two orderings a timelock uses agree: e(s·Q, r·G₂) == e(Q, s·G₂)^r', () => {
    const s = randomScalar()
    const r = randomScalar()
    const Q = hashToG1(utf8('round 42'))
    const receiver = pairing(Q.multiply(s), g2Base().multiply(r))
    const sender = gtPow(pairing(Q, g2Base().multiply(s)), r)
    expect(gtEqual(receiver, sender)).toBe(true)
  })
})

describe('scalars', () => {
  it('randomScalar stays inside [1, order-1]', () => {
    for (let i = 0; i < 32; i++) {
      const s = randomScalar()
      expect(s).toBeGreaterThan(0n)
      expect(s).toBeLessThan(CURVE.order)
    }
  })

  it('randomScalar does not repeat', () => {
    const seen = new Set<bigint>()
    for (let i = 0; i < 32; i++) seen.add(randomScalar())
    expect(seen.size).toBe(32)
  })

  it('hashToScalar is deterministic, in range, and domain-separated', () => {
    const msg = utf8('the message')
    expect(hashToScalar(msg, 'DST-A')).toBe(hashToScalar(msg, 'DST-A'))
    expect(hashToScalar(msg, 'DST-A')).not.toBe(hashToScalar(msg, 'DST-B'))
    expect(hashToScalar(msg, 'DST-A')).toBeLessThan(CURVE.order)
  })
})

describe('deserialization is strict', () => {
  it('accepts a real point and rejects garbage of the right length', () => {
    expect(() => g1FromBytes(G1.Point.BASE.toBytes())).not.toThrow()
    expect(() => g2FromBytes(G2.Point.BASE.toBytes())).not.toThrow()
    expect(() => g1FromBytes(fromHex('ff'.repeat(48)))).toThrow()
    expect(() => g2FromBytes(fromHex('ff'.repeat(96)))).toThrow()
  })

  it('rejects a truncated encoding rather than padding it', () => {
    expect(() => g1FromBytes(G1.Point.BASE.toBytes().subarray(0, 47))).toThrow()
  })
})
