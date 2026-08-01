/**
 * The flagship known-answer tests: real League of Entropy rounds.
 *
 * src/fixtures/kat.json holds four signatures captured from drand's public
 * `quicknet` chain, plus that chain's real group public key. Nothing in this
 * repo produced them. If `verifyRound` accepts all four under the real key —
 * and rejects them under a shifted round number — then our round encoding, our
 * hash-to-curve DST, our group layout (signatures in G1, keys in G2) and our
 * pairing equation all match the network byte for byte.
 *
 * These are static fixtures. The lab makes no network requests at runtime.
 */

import { describe, expect, it } from 'vitest'
import kat from '../fixtures/kat.json'
import { g1FromBytes, g2FromBytes, type G2Point } from './bls'
import { fromHex, toHex } from './bytes'
import {
  SimulatedBeacon,
  beaconKeygen,
  roundAtTime,
  roundMessage,
  signRound,
  timeOfRound,
  verificationSides,
  verifyRound,
  type BeaconParams,
} from './beacon'
import { gtEqual } from './bls'

const quicknet = kat.drandQuicknet
const quicknetKey: G2Point = g2FromBytes(fromHex(quicknet.publicKey))

describe(`drand quicknet — ${quicknet.rounds.length} real-network known-answer tests`, () => {
  it('the published group public key is a valid G2 point in the prime-order subgroup', () => {
    expect(() => g2FromBytes(fromHex(quicknet.publicKey))).not.toThrow()
    expect(toHex(quicknetKey.toBytes())).toBe(quicknet.publicKey)
  })

  it.each(quicknet.rounds.map((r) => [r.round, r] as const))(
    'round %i verifies under the real quicknet key',
    (_round, entry) => {
      const message = roundMessage(entry.round, 'unchained')
      const signature = g1FromBytes(fromHex(entry.signature))
      expect(verifyRound(quicknetKey, message, signature)).toBe(true)
    },
  )

  it.each(quicknet.rounds.map((r) => [r.round, r] as const))(
    'round %i is rejected against the neighbouring round’s message',
    (_round, entry) => {
      const signature = g1FromBytes(fromHex(entry.signature))
      expect(verifyRound(quicknetKey, roundMessage(entry.round + 1, 'unchained'), signature)).toBe(false)
      // Round 1 has no predecessor to test against.
      if (entry.round > 1) {
        expect(verifyRound(quicknetKey, roundMessage(entry.round - 1, 'unchained'), signature)).toBe(false)
      }
    },
  )

  it('a real signature does not verify under a different group key', () => {
    const first = quicknet.rounds[0]!
    const impostor = beaconKeygen().publicKey
    const signature = g1FromBytes(fromHex(first.signature))
    expect(verifyRound(impostor, roundMessage(first.round, 'unchained'), signature)).toBe(false)
  })

  it('the two pairings in the verification equation are computed independently', () => {
    const first = quicknet.rounds[0]!
    const sides = verificationSides(
      quicknetKey,
      roundMessage(first.round, 'unchained'),
      g1FromBytes(fromHex(first.signature)),
    )
    // Same GT element, reached from disjoint inputs: one from (σ, G₂), the
    // other from (H₁(m), P_pub). This is what the mechanism panel displays.
    expect(gtEqual(sides.left, sides.right)).toBe(true)
  })
})

describe('round → identity encoding', () => {
  it('is a pure function of the round number for unchained beacons', () => {
    expect(toHex(roundMessage(1000))).toBe(toHex(roundMessage(1000)))
    expect(toHex(roundMessage(1000))).not.toBe(toHex(roundMessage(1001)))
    expect(roundMessage(1000).length).toBe(32)
  })

  it('needs the previous signature for chained beacons — which is why they cannot timelock', () => {
    expect(() => roundMessage(2, 'chained')).toThrow(/previous signature/)
    const prev = fromHex('aa'.repeat(48))
    expect(toHex(roundMessage(2, 'chained', prev))).not.toBe(toHex(roundMessage(2, 'unchained')))
  })

  it('a chained message changes when the previous signature changes', () => {
    const a = roundMessage(2, 'chained', fromHex('aa'.repeat(48)))
    const b = roundMessage(2, 'chained', fromHex('ab'.repeat(48)))
    expect(toHex(a)).not.toBe(toHex(b))
  })

  it('refuses round 0 and non-integers', () => {
    expect(() => roundMessage(0)).toThrow()
    expect(() => roundMessage(-5)).toThrow()
    expect(() => roundMessage(1.5)).toThrow()
  })
})

describe('quicknet schedule arithmetic', () => {
  const params: BeaconParams = {
    periodSeconds: quicknet.periodSeconds,
    genesisTime: quicknet.genesisTime,
    scheme: 'unchained',
  }

  it('round 1 lands exactly at genesis', () => {
    expect(timeOfRound(params, 1)).toBe(quicknet.genesisTime)
    expect(roundAtTime(params, quicknet.genesisTime)).toBe(1)
  })

  it('is the inverse of itself on round boundaries', () => {
    for (const round of [1, 2, 1000, 30_926_039]) {
      expect(roundAtTime(params, timeOfRound(params, round))).toBe(round)
    }
  })

  it('does not advance mid-period', () => {
    expect(roundAtTime(params, quicknet.genesisTime + quicknet.periodSeconds - 1)).toBe(1)
    expect(roundAtTime(params, quicknet.genesisTime + quicknet.periodSeconds)).toBe(2)
  })

  it('reports round 0 before genesis', () => {
    expect(roundAtTime(params, quicknet.genesisTime - 1)).toBe(0)
  })
})

describe('SimulatedBeacon', () => {
  const params: BeaconParams = { periodSeconds: 1, genesisTime: 0, scheme: 'unchained' }

  it('signs what it publishes, and the signatures verify', () => {
    const beacon = new SimulatedBeacon(params)
    beacon.advanceTo(5)
    for (let r = 1; r <= 5; r++) {
      const round = beacon.at(r)!
      expect(round).toBeDefined()
      expect(verifyRound(beacon.keys.publicKey, round.message, round.signature)).toBe(true)
    }
  })

  it('FAIL-CLOSED: there is no way to obtain a future round early', () => {
    const beacon = new SimulatedBeacon(params)
    beacon.advanceTo(10)
    expect(beacon.at(11)).toBeUndefined()
    expect(beacon.at(1_000_000)).toBeUndefined()
    expect(beacon.latestRound).toBe(10)
  })

  it('a halted beacon publishes nothing further — the ciphertext is stranded, not delayed', () => {
    const beacon = new SimulatedBeacon(params)
    beacon.advanceTo(10)
    beacon.halt()
    expect(beacon.advanceTo(100)).toEqual([])
    expect(beacon.at(11)).toBeUndefined()
    expect(beacon.latestRound).toBe(10)
    beacon.resume()
    expect(beacon.advanceTo(12)).toHaveLength(2)
  })

  it('is deterministic: the same key produces the same signature for a round', () => {
    const keys = beaconKeygen()
    const a = new SimulatedBeacon(params, keys)
    const b = new SimulatedBeacon(params, keys)
    a.advanceTo(3)
    b.advanceTo(3)
    expect(toHex(a.at(3)!.signature.toBytes())).toBe(toHex(b.at(3)!.signature.toBytes()))
  })

  it('walks a chained beacon in order, and its round messages depend on history', () => {
    const chained = new SimulatedBeacon({ ...params, scheme: 'chained' })
    chained.advanceTo(3)
    expect(toHex(chained.at(3)!.message)).not.toBe(toHex(roundMessage(3, 'unchained')))
    // Two chained beacons with different keys diverge from round 2 onward,
    // because round 2's message contains round 1's signature.
    const other = new SimulatedBeacon({ ...params, scheme: 'chained' })
    other.advanceTo(3)
    expect(toHex(chained.at(1)!.message)).toBe(toHex(other.at(1)!.message))
    expect(toHex(chained.at(2)!.message)).not.toBe(toHex(other.at(2)!.message))
  })

  it('a chained chain seeds round 1 from the published genesis seed', () => {
    const seeded = new SimulatedBeacon({
      ...params,
      scheme: 'chained',
      genesisSeed: fromHex('11'.repeat(32)),
    })
    const unseeded = new SimulatedBeacon({ ...params, scheme: 'chained' })
    seeded.advanceTo(1)
    unseeded.advanceTo(1)
    expect(toHex(seeded.at(1)!.message)).not.toBe(toHex(unseeded.at(1)!.message))
  })

  it('reports recent rounds newest-first and resets cleanly', () => {
    const beacon = new SimulatedBeacon(params)
    beacon.advanceTo(5)
    expect(beacon.recent(3).map((r) => r.round)).toEqual([5, 4, 3])
    beacon.reset()
    expect(beacon.latestRound).toBe(0)
    expect(beacon.at(1)).toBeUndefined()
  })
})

describe('signing', () => {
  it('a signature is the secret times the round point — the IBE key extraction', () => {
    const keys = beaconKeygen()
    const message = roundMessage(7)
    expect(verifyRound(keys.publicKey, message, signRound(keys.secret, message))).toBe(true)
  })

  it('rejects a signature made under a different secret', () => {
    const message = roundMessage(7)
    const honest = beaconKeygen()
    const rogue = beaconKeygen()
    expect(verifyRound(honest.publicKey, message, signRound(rogue.secret, message))).toBe(false)
  })
})
