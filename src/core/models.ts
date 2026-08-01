/**
 * Three ways to delay a secret — modelled, not asserted.
 *
 *   time-lock puzzle  make ONE person grind        (Rivest–Shamir–Wagner 1996)
 *   VDF               make ONE person grind, once, provably, for everyone
 *   beacon timelock   make NOBODY grind; everybody waits for a public event
 *
 * The first two buy delay with computation, so their delay is denominated in
 * the opener's hardware: a rival with a faster machine opens sooner, in exact
 * proportion. The third buys delay with a public schedule, so its delay is
 * denominated in seconds, and no amount of silicon moves it.
 *
 * What that costs you is symmetrical and worth stating plainly: puzzle and VDF
 * need no third party and always eventually open; the beacon needs a live,
 * honest beacon and never opens if that beacon stops.
 *
 * The squaring rate below is MEASURED in the visitor's own browser rather than
 * assumed, so the numbers on screen are that machine's numbers. What is
 * modelled is the scaling, not the wall clock: a real ASIC's advantage over
 * this browser's BigInt loop is the slider, and the slider is labelled as an
 * assumption because it is one.
 */

export type ModelId = 'puzzle' | 'vdf' | 'beacon'

export interface ModelProfile {
  readonly id: ModelId
  readonly name: string
  readonly spec: string
  /** One line: how the delay is actually enforced. */
  readonly mechanism: string
  readonly needsThirdParty: boolean
  /** Does the secret still open if the service/network behind it disappears? */
  readonly survivesOutage: boolean
}

export const MODELS: readonly ModelProfile[] = [
  {
    id: 'puzzle',
    name: 'Time-lock puzzle',
    spec: 'Rivest–Shamir–Wagner 1996',
    mechanism: 'Repeated squaring mod N. The maker knows φ(N) and skips ahead; the opener cannot.',
    needsThirdParty: false,
    survivesOutage: true,
  },
  {
    id: 'vdf',
    name: 'Verifiable delay function',
    spec: 'Boneh–Bonneau–Bünz–Fisch 2018',
    mechanism: 'The same sequential squaring, plus a short proof so the answer is checkable without redoing it.',
    needsThirdParty: false,
    survivesOutage: true,
  },
  {
    id: 'beacon',
    name: 'Beacon timelock',
    spec: 'drand · IBE',
    mechanism: 'No work at all. The key is a signature the beacon publishes on a fixed schedule.',
    needsThirdParty: true,
    survivesOutage: false,
  },
]

export function modelById(id: ModelId): ModelProfile {
  const m = MODELS.find((x) => x.id === id)
  if (!m) throw new Error(`unknown model ${id}`)
  return m
}

export interface Calibration {
  /** Modular squarings per second, measured on this machine. */
  readonly squaringsPerSecond: number
  readonly modulusBits: number
  readonly sampleMillis: number
}

export interface Scenario {
  /** The delay the designer wants, at reference (1×) hardware. */
  readonly targetDelaySeconds: number
  /** How much faster the adversary's hardware is than the reference. */
  readonly adversarySpeedup: number
  /** How many independent parties want the secret when it opens. */
  readonly parties: number
  /** Whether the beacon is still producing rounds. */
  readonly beaconAlive: boolean
}

export interface Outcome {
  readonly model: ModelProfile
  /** Seconds until the adversary can read it. `null` means never. */
  readonly earliestOpenSeconds: number | null
  /** Sequential squarings on the critical path to one opening. */
  readonly sequentialSquarings: number
  /** Squarings burned across all interested parties. */
  readonly totalSquarings: number
  /** Squaring-equivalents to check somebody else's claimed answer. */
  readonly verifySquarings: number
}

/**
 * Wesolowski verification is two exponentiations with ~λ-bit exponents, so
 * roughly 2λ squarings. λ = 128 here. It is O(log T) — flat against T, which
 * is the entire contribution of the VDF line of work.
 */
const VDF_VERIFY_SQUARINGS = 256

/**
 * A BLS pairing check costs about a millisecond, which is nothing, but it is
 * not a squaring. Expressed here in squaring-equivalents purely so the three
 * models land on one axis; the UI labels it as a conversion, not a measurement.
 */
const PAIRING_VERIFY_SQUARING_EQUIVALENT = 20_000

export function evaluate(id: ModelId, scenario: Scenario, calibration: Calibration): Outcome {
  const model = modelById(id)
  const { targetDelaySeconds, adversarySpeedup, parties, beaconAlive } = scenario
  const T = Math.round(targetDelaySeconds * calibration.squaringsPerSecond)

  switch (id) {
    case 'puzzle':
      return {
        model,
        // T sequential squarings at `speedup` times the reference rate.
        earliestOpenSeconds: targetDelaySeconds / adversarySpeedup,
        sequentialSquarings: T,
        // No proof exists, so every interested party grinds the puzzle itself.
        totalSquarings: T * parties,
        // "Verifying" someone's claimed answer means redoing the whole thing.
        verifySquarings: T,
      }
    case 'vdf':
      return {
        model,
        earliestOpenSeconds: targetDelaySeconds / adversarySpeedup,
        sequentialSquarings: T,
        // One evaluator grinds; everyone else checks the proof.
        totalSquarings: T + VDF_VERIFY_SQUARINGS * Math.max(0, parties - 1),
        verifySquarings: VDF_VERIFY_SQUARINGS,
      }
    case 'beacon':
      return {
        model,
        // The one row in this table that ignores `adversarySpeedup` entirely.
        earliestOpenSeconds: beaconAlive ? targetDelaySeconds : null,
        sequentialSquarings: 0,
        totalSquarings: 0,
        verifySquarings: PAIRING_VERIFY_SQUARING_EQUIVALENT,
      }
  }
}

export function evaluateAll(scenario: Scenario, calibration: Calibration): Outcome[] {
  return MODELS.map((m) => evaluate(m.id, scenario, calibration))
}

/**
 * Measure this machine's modular squaring rate: x ← x² mod N on a real
 * `modulusBits`-bit modulus, counted for `budgetMillis`.
 *
 * BigInt is not a competitive implementation and we never pretend it is — it
 * is the *reference* rate, the 1× on the slider. Reporting a rate we measured
 * beats quoting a rate we imagined.
 */
export function measureSquaringRate(modulusBits = 2048, budgetMillis = 120): Calibration {
  // A fixed odd modulus of the right size. Not a factoring challenge — the
  // point is the width of the numbers, since that is what sets the cost.
  const N = (1n << BigInt(modulusBits - 1)) | 1n | (1n << BigInt(modulusBits - 3))
  let x = 3n
  let count = 0
  const batch = 64
  const start = performance.now()
  let elapsed = 0
  do {
    for (let i = 0; i < batch; i++) x = (x * x) % N
    count += batch
    elapsed = performance.now() - start
  } while (elapsed < budgetMillis)
  // Keep the optimiser honest about the loop actually running.
  if (x === 0n) throw new Error('unreachable')
  return {
    squaringsPerSecond: Math.max(1, Math.round((count / elapsed) * 1000)),
    modulusBits,
    sampleMillis: Math.round(elapsed),
  }
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null) return 'never'
  if (!Number.isFinite(seconds)) return 'never'
  if (seconds < 1e-3) return `${(seconds * 1e6).toFixed(0)} µs`
  if (seconds < 1) return `${(seconds * 1e3).toFixed(0)} ms`
  if (seconds < 90) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`
  const minutes = seconds / 60
  if (minutes < 90) return `${minutes.toFixed(minutes < 10 ? 1 : 0)} min`
  const hours = minutes / 60
  if (hours < 48) return `${hours.toFixed(hours < 10 ? 1 : 0)} h`
  const days = hours / 24
  if (days < 730) return `${days.toFixed(days < 10 ? 1 : 0)} days`
  return `${(days / 365.25).toFixed(1)} years`
}

export function formatCount(n: number): string {
  if (n === 0) return '0'
  if (n < 1000) return n.toFixed(0)
  const units = ['', 'K', 'M', 'B', 'T', 'P']
  const tier = Math.min(units.length - 1, Math.floor(Math.log10(n) / 3))
  return `${(n / 1000 ** tier).toFixed(1)}${units[tier]}`
}
