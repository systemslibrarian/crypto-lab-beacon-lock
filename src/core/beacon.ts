/**
 * A drand-shaped randomness beacon.
 *
 * A beacon is a public clock that signs the time. Every `period` seconds it
 * emits round n and a BLS signature over a message derived from n. Because the
 * signing key is a threshold key held by the League of Entropy, no single node
 * can produce a round early, and because the signature is deterministic,
 * everyone who fetches round n gets the same 48 bytes.
 *
 * Two schemes matter here, and the difference is the entire reason timelock
 * encryption is possible at all:
 *
 *   chained   — message = SHA-256( prevSignature ‖ round ).  You cannot write
 *               down the message for round n+1000 today, because it depends on
 *               999 signatures that do not exist yet. No timelock.
 *   unchained — message = SHA-256( round ).  The message for *any* future round
 *               is computable right now, by anyone. That computable-in-advance
 *               message is the IBE identity a ciphertext gets locked to.
 *
 * drand's `quicknet` chain is unchained, on purpose, and shipping it is what
 * made practical timelock encryption available on a public network.
 *
 * Signature verification is the pairing equation, written out rather than
 * delegated: e(σ, G₂) == e(H₁(m), P_pub).
 */

import { sha256 } from '@noble/hashes/sha2.js'
import {
  DRAND_SIG_DST,
  g2Base,
  gtEqual,
  hashToG1,
  pairing,
  randomScalar,
  type G1Point,
  type G2Point,
} from './bls'
import { beU64, concat } from './bytes'

export type BeaconScheme = 'unchained' | 'chained'

export interface BeaconParams {
  /** Seconds between rounds. quicknet uses 3. */
  readonly periodSeconds: number
  /** Unix seconds of round 1. */
  readonly genesisTime: number
  readonly scheme: BeaconScheme
  /**
   * Chained chains only: round 1 has no predecessor, so drand seeds the chain
   * with a published `genesis_seed` and hashes that in the previous
   * signature's place. Unchained chains have no use for it.
   */
  readonly genesisSeed?: Uint8Array
}

export interface BeaconKeys {
  /**
   * The group secret. On the real network this never exists in one place: it
   * is shared across ~20 nodes and only ever used as t-of-n threshold shares.
   * Holding it as one scalar is this lab's single largest simplification, and
   * it is stated on the page.
   */
  readonly secret: bigint
  readonly publicKey: G2Point
}

export interface BeaconRound {
  readonly round: number
  /** The signed message — SHA-256 of the round encoding. This is the identity. */
  readonly message: Uint8Array
  readonly signature: G1Point
}

export function beaconKeygen(): BeaconKeys {
  const secret = randomScalar()
  return { secret, publicKey: g2Base().multiply(secret) as G2Point }
}

/**
 * The message a beacon signs for a given round.
 *
 * Note what `unchained` does *not* take: any secret, any prior state, any
 * network access. `roundMessage(1_000_000)` is a pure function of the number
 * one million, so a sender can compute it for a round a month away.
 */
export function roundMessage(
  round: number,
  scheme: BeaconScheme = 'unchained',
  previousSignature?: Uint8Array,
): Uint8Array {
  if (!Number.isInteger(round) || round < 1) throw new Error(`roundMessage: bad round ${round}`)
  if (scheme === 'unchained') return sha256(beU64(round))
  if (!previousSignature) throw new Error('roundMessage: chained scheme needs the previous signature')
  return sha256(concat(previousSignature, beU64(round)))
}

/** H₁(m) — the round's point in G1. Both the signer and the sender compute this. */
export function roundPoint(message: Uint8Array): G1Point {
  return hashToG1(message, DRAND_SIG_DST)
}

/** σ = s · H₁(m). A plain BLS signature; determinism is what makes it a beacon. */
export function signRound(secret: bigint, message: Uint8Array): G1Point {
  return roundPoint(message).multiply(secret) as G1Point
}

/**
 * e(σ, G₂) == e(H₁(m), P_pub)
 *
 * Both sides are computed independently and compared as GT elements; the UI
 * shows the two 576-byte results side by side rather than asserting equality.
 */
export function verifyRound(publicKey: G2Point, message: Uint8Array, signature: G1Point): boolean {
  return gtEqual(pairing(signature, g2Base()), pairing(roundPoint(message), publicKey))
}

/** The two GT elements behind `verifyRound`, for the side-by-side readout. */
export function verificationSides(
  publicKey: G2Point,
  message: Uint8Array,
  signature: G1Point,
): { left: ReturnType<typeof pairing>; right: ReturnType<typeof pairing> } {
  return {
    left: pairing(signature, g2Base()),
    right: pairing(roundPoint(message), publicKey),
  }
}

export function roundAtTime(params: BeaconParams, unixSeconds: number): number {
  if (unixSeconds < params.genesisTime) return 0
  return Math.floor((unixSeconds - params.genesisTime) / params.periodSeconds) + 1
}

export function timeOfRound(params: BeaconParams, round: number): number {
  return params.genesisTime + (round - 1) * params.periodSeconds
}

/**
 * A running beacon. Pure state — no timers, no I/O; the UI drives `advanceTo`
 * from a `setInterval` so the core stays testable and the simulated clock is
 * visibly a local one.
 *
 * `halt()` models the failure the brief asks us to show honestly: if the
 * League of Entropy stops producing rounds, every ciphertext locked to a round
 * beyond the last one published is unopenable. Not "hard to open" — unopenable,
 * because the decryption key is a signature that now will never exist.
 */
export class SimulatedBeacon {
  readonly params: BeaconParams
  readonly keys: BeaconKeys
  private readonly history = new Map<number, BeaconRound>()
  private latest = 0
  private halted = false
  private readonly genesisSeed: Uint8Array

  constructor(params: BeaconParams, keys: BeaconKeys = beaconKeygen()) {
    this.params = params
    this.keys = keys
    this.genesisSeed = params.genesisSeed ?? new Uint8Array(32)
  }

  get latestRound(): number {
    return this.latest
  }

  get isHalted(): boolean {
    return this.halted
  }

  halt(): void {
    this.halted = true
  }

  resume(): void {
    this.halted = false
  }

  /** Produce every round up to `target`. Chained schemes require the walk. */
  advanceTo(target: number): BeaconRound[] {
    if (this.halted) return []
    const produced: BeaconRound[] = []
    for (let r = this.latest + 1; r <= target; r++) {
      // Round 1 of a chained chain hashes the published genesis seed where a
      // predecessor's signature would otherwise go.
      const previous =
        this.history.get(r - 1)?.signature.toBytes() ?? (r === 1 ? this.genesisSeed : undefined)
      const message = roundMessage(r, this.params.scheme, previous)
      const round: BeaconRound = { round: r, message, signature: signRound(this.keys.secret, message) }
      this.history.set(r, round)
      produced.push(round)
      this.latest = r
    }
    return produced
  }

  /**
   * A published round, or `undefined` if the beacon has not reached it.
   * Returning `undefined` rather than signing on demand is the fail-closed
   * rule the whole demo rests on: there is no back door that produces a future
   * signature early, not even for the UI.
   */
  at(round: number): BeaconRound | undefined {
    return this.history.get(round)
  }

  /** Rounds already published, newest first. */
  recent(count: number): BeaconRound[] {
    const out: BeaconRound[] = []
    for (let r = this.latest; r > 0 && out.length < count; r--) {
      const round = this.history.get(r)
      if (round) out.push(round)
    }
    return out
  }

  reset(): void {
    this.history.clear()
    this.latest = 0
    this.halted = false
  }
}
