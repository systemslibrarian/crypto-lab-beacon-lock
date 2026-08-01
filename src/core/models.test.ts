/**
 * The three-model comparison is a claim about scaling, so it gets tested like
 * one. The headline assertion is the last describe block: beacon opening time
 * is invariant under adversary hardware, and the other two are not.
 */

import { describe, expect, it } from 'vitest'
import {
  MODELS,
  evaluate,
  evaluateAll,
  formatCount,
  formatDuration,
  measureSquaringRate,
  modelById,
  type Calibration,
  type Scenario,
} from './models'

const calibration: Calibration = { squaringsPerSecond: 1_000_000, modulusBits: 2048, sampleMillis: 120 }
const base: Scenario = {
  targetDelaySeconds: 3600,
  adversarySpeedup: 1,
  parties: 1,
  beaconAlive: true,
}

describe('model catalogue', () => {
  it('holds the three delay strategies', () => {
    expect(MODELS.map((m) => m.id)).toEqual(['puzzle', 'vdf', 'beacon'])
    expect(modelById('beacon').needsThirdParty).toBe(true)
    expect(modelById('puzzle').needsThirdParty).toBe(false)
    expect(modelById('vdf').survivesOutage).toBe(true)
    expect(modelById('beacon').survivesOutage).toBe(false)
  })

  it('refuses an unknown id', () => {
    // @ts-expect-error deliberately out of the union
    expect(() => modelById('vdf2')).toThrow(/unknown model/)
  })
})

describe('THE headline property: only the beacon ignores the adversary’s hardware', () => {
  it.each([1, 10, 1000, 100_000])('at %i× hardware', (speedup) => {
    const scenario = { ...base, adversarySpeedup: speedup }
    const [puzzle, vdf, beacon] = evaluateAll(scenario, calibration)

    // Compute-bound delay is denominated in the opener's hardware.
    expect(puzzle!.earliestOpenSeconds).toBeCloseTo(base.targetDelaySeconds / speedup, 6)
    expect(vdf!.earliestOpenSeconds).toBeCloseTo(base.targetDelaySeconds / speedup, 6)

    // Event-bound delay is denominated in seconds. Same answer every time.
    expect(beacon!.earliestOpenSeconds).toBe(base.targetDelaySeconds)
  })

  it('a 1000× adversary shortens the puzzle by 1000× and the beacon by nothing', () => {
    const slow = evaluate('puzzle', base, calibration).earliestOpenSeconds!
    const fast = evaluate('puzzle', { ...base, adversarySpeedup: 1000 }, calibration).earliestOpenSeconds!
    expect(slow / fast).toBeCloseTo(1000, 6)

    const beaconSlow = evaluate('beacon', base, calibration).earliestOpenSeconds
    const beaconFast = evaluate('beacon', { ...base, adversarySpeedup: 1000 }, calibration).earliestOpenSeconds
    expect(beaconSlow).toBe(beaconFast)
  })
})

describe('the price of that property: liveness', () => {
  it('a dead beacon means never — not "slower"', () => {
    const dead = evaluate('beacon', { ...base, beaconAlive: false }, calibration)
    expect(dead.earliestOpenSeconds).toBeNull()
    expect(formatDuration(dead.earliestOpenSeconds)).toBe('never')
  })

  it('the compute-bound models are unaffected by the beacon dying', () => {
    for (const id of ['puzzle', 'vdf'] as const) {
      expect(evaluate(id, { ...base, beaconAlive: false }, calibration).earliestOpenSeconds).toBe(
        evaluate(id, base, calibration).earliestOpenSeconds,
      )
    }
  })
})

describe('work burned', () => {
  it('the beacon burns none', () => {
    const beacon = evaluate('beacon', { ...base, parties: 500 }, calibration)
    expect(beacon.sequentialSquarings).toBe(0)
    expect(beacon.totalSquarings).toBe(0)
  })

  it('a puzzle makes every interested party grind separately', () => {
    const one = evaluate('puzzle', base, calibration)
    const many = evaluate('puzzle', { ...base, parties: 100 }, calibration)
    expect(many.totalSquarings).toBe(one.totalSquarings * 100)
  })

  it('a VDF makes one party grind and the rest check a proof', () => {
    const one = evaluate('vdf', base, calibration)
    const many = evaluate('vdf', { ...base, parties: 100 }, calibration)
    expect(many.totalSquarings).toBeLessThan(one.totalSquarings * 1.001)
    expect(many.sequentialSquarings).toBe(one.sequentialSquarings)
  })

  it('verification is the axis that separates a puzzle from a VDF', () => {
    const puzzle = evaluate('puzzle', base, calibration)
    const vdf = evaluate('vdf', base, calibration)
    // Checking a puzzle answer means redoing the puzzle; checking a VDF proof
    // does not depend on T at all.
    expect(puzzle.verifySquarings).toBe(puzzle.sequentialSquarings)
    expect(vdf.verifySquarings).toBeLessThan(vdf.sequentialSquarings / 1000)
    const longer = evaluate('vdf', { ...base, targetDelaySeconds: 86_400 }, calibration)
    expect(longer.verifySquarings).toBe(vdf.verifySquarings)
  })

  it('difficulty tracks the measured rate, so T is this machine’s T', () => {
    const fast = evaluate('puzzle', base, { ...calibration, squaringsPerSecond: 2_000_000 })
    const slow = evaluate('puzzle', base, calibration)
    expect(fast.sequentialSquarings).toBe(slow.sequentialSquarings * 2)
    // …but the wall-clock delay at 1× is the same by construction.
    expect(fast.earliestOpenSeconds).toBe(slow.earliestOpenSeconds)
  })
})

describe('measureSquaringRate', () => {
  it('measures a plausible rate on a real modulus', () => {
    const result = measureSquaringRate(2048, 30)
    expect(result.squaringsPerSecond).toBeGreaterThan(100)
    expect(result.modulusBits).toBe(2048)
    expect(result.sampleMillis).toBeGreaterThanOrEqual(30)
  })

  it('a wider modulus is not faster', () => {
    const narrow = measureSquaringRate(1024, 30).squaringsPerSecond
    const wide = measureSquaringRate(4096, 30).squaringsPerSecond
    expect(wide).toBeLessThanOrEqual(narrow * 1.5)
  })
})

describe('formatting', () => {
  it('picks a readable unit', () => {
    expect(formatDuration(0.0004)).toBe('400 µs')
    expect(formatDuration(0.25)).toBe('250 ms')
    expect(formatDuration(45)).toBe('45 s')
    expect(formatDuration(600)).toBe('10 min')
    expect(formatDuration(7200)).toBe('2.0 h')
    expect(formatDuration(86_400 * 10)).toBe('10 days')
    expect(formatDuration(86_400 * 365.25 * 3)).toBe('3.0 years')
    expect(formatDuration(null)).toBe('never')
    expect(formatDuration(Infinity)).toBe('never')
  })

  it('abbreviates large counts', () => {
    expect(formatCount(0)).toBe('0')
    expect(formatCount(999)).toBe('999')
    expect(formatCount(1500)).toBe('1.5K')
    expect(formatCount(3.6e9)).toBe('3.6B')
  })
})
