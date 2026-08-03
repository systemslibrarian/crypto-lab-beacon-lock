/**
 * Shared lab state: one beacon, one vault of locked ciphertexts, one clock.
 *
 * Every panel reads the same beacon. That is deliberate — the point of the
 * demo is that a single public clock unlocks everybody's ciphertexts at once,
 * so a per-panel beacon would quietly teach the wrong thing.
 *
 * The clock is a `setInterval` in this file and nowhere else. It is the only
 * simulated component in the lab, and the page says so beside it.
 */

import {
  SimulatedBeacon,
  roundMessage,
  type BeaconParams,
  type BeaconRound,
  type BeaconScheme,
} from '../core/beacon'
import { open, randomKey, seal, type SealedPayload } from '../core/envelope'
import { measureSquaringRate, type Calibration } from '../core/models'
import { beU64 } from '../core/bytes'
import { decrypt, encrypt, type EncryptTrace, type TimelockCiphertext } from '../core/tlock'
import type { G1Point } from '../core/bls'

export interface LockedItem {
  readonly id: string
  readonly label: string
  readonly targetRound: number
  readonly lockedAtRound: number
  /** The timelock ciphertext — over the 32-byte AES key, not the text. */
  readonly keyCiphertext: TimelockCiphertext
  /** The AES-GCM envelope holding the actual message. */
  readonly payload: SealedPayload
  /** Sender-side intermediates. Never transmitted; held for the mechanism panel. */
  readonly trace: EncryptTrace
  readonly plaintextBytes: number
  opened: string | null
}

export type OpenOutcome =
  | { readonly status: 'opened'; readonly message: string }
  | { readonly status: 'too-early'; readonly roundsRemaining: number }
  | { readonly status: 'rejected'; readonly reason: string }
  | { readonly status: 'stranded' }

/** Demo tick speeds. The label is honest about which one is the real network. */
export const SPEEDS = [
  { value: '3000', text: '3 s per round (real quicknet speed)' },
  { value: '1000', text: '1 s per round' },
  { value: '400', text: '0.4 s per round' },
] as const

const DEFAULT_PERIOD_SECONDS = 3

class LabState {
  private listeners = new Set<() => void>()
  private timer: number | null = null
  private tickMillis = 1000
  private nextId = 1

  scheme: BeaconScheme = 'unchained'
  beacon = new SimulatedBeacon(this.paramsFor('unchained'))
  readonly items: LockedItem[] = []
  calibration: Calibration | null = null
  /** Set when the visitor halts the beacon, so the UI can narrate the outage. */
  haltedAtRound: number | null = null

  /**
   * Bumped every time the chain itself is replaced — a scheme switch or a lab
   * reset, both of which draw a fresh master secret and discard the vault.
   *
   * Panels that render a one-shot result (a verified round, a lock receipt)
   * keep the epoch they were computed under and retire themselves when it
   * moves. Without this a verdict outlives its inputs: the beacon panel went on
   * printing "Signature valid" plus two 576-byte GT elements belonging to a key
   * pair that no longer exists anywhere on the page, and the lock panel went on
   * saying "Locked to round 9" beside a vault reading "Nothing locked yet".
   *
   * A tick must NOT bump this. Rounds already published stay valid as the
   * beacon advances; only replacing the beacon invalidates them.
   */
  chainEpoch = 0

  private paramsFor(scheme: BeaconScheme): BeaconParams {
    return { periodSeconds: DEFAULT_PERIOD_SECONDS, genesisTime: 0, scheme }
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  notify(): void {
    for (const fn of this.listeners) fn()
  }

  get round(): number {
    return this.beacon.latestRound
  }

  get running(): boolean {
    return this.timer !== null
  }

  get speedMillis(): number {
    return this.tickMillis
  }

  start(): void {
    if (this.timer !== null) return
    this.timer = window.setInterval(() => this.tick(), this.tickMillis)
    this.notify()
  }

  stop(): void {
    if (this.timer === null) return
    window.clearInterval(this.timer)
    this.timer = null
    this.notify()
  }

  setSpeed(millis: number): void {
    this.tickMillis = millis
    if (this.timer !== null) {
      this.stop()
      this.start()
    } else {
      this.notify()
    }
  }

  private tick(): void {
    if (this.beacon.isHalted) return
    this.beacon.advanceTo(this.beacon.latestRound + 1)
    this.notify()
  }

  /**
   * Jump the beacon forward. This button exists because on this page *you* are
   * the beacon operator; on the real network nobody holds it. The UI says so
   * next to the control.
   */
  fastForward(rounds: number): void {
    if (this.beacon.isHalted) return
    this.beacon.advanceTo(this.beacon.latestRound + rounds)
    this.notify()
  }

  halt(): void {
    this.beacon.halt()
    this.haltedAtRound = this.beacon.latestRound
    this.stop()
    this.notify()
  }

  resume(): void {
    this.beacon.resume()
    this.haltedAtRound = null
    this.notify()
  }

  /**
   * Switching schemes restarts the chain: a chained beacon's round messages
   * depend on its own history, so they are not comparable across a switch.
   */
  setScheme(scheme: BeaconScheme): void {
    if (scheme === this.scheme) return
    this.scheme = scheme
    this.beacon = new SimulatedBeacon(this.paramsFor(scheme))
    this.items.length = 0
    this.haltedAtRound = null
    this.chainEpoch++
    this.beacon.advanceTo(1)
    this.notify()
  }

  roundAt(round: number): BeaconRound | undefined {
    return this.beacon.at(round)
  }

  /** Lazily measured once, then cached — it costs ~120 ms of real squaring. */
  calibrate(): Calibration {
    if (!this.calibration) this.calibration = measureSquaringRate(2048, 120)
    return this.calibration
  }

  /**
   * Lock a message to a future round.
   *
   * Hybrid, exactly as real tlock does it: a fresh AES-256 key seals the text,
   * and the timelock covers only that 32-byte key. The round number is bound
   * into the AEAD as associated data, so the header cannot be relabelled.
   */
  async lock(label: string, plaintext: string, targetRound: number): Promise<LockedItem> {
    const identity = this.messageForRound(targetRound)
    const key = randomKey()
    const aad = beU64(targetRound)
    const payload = await seal(key, plaintext, aad)
    const { ciphertext, trace } = encrypt(
      this.beacon.keys.publicKey,
      identity,
      key,
      targetRound,
      'simulated-chain',
    )
    // The key is gone from this scope the moment we return; only the timelock
    // ciphertext and the sealed payload are retained.
    key.fill(0)

    const item: LockedItem = {
      id: `lock-${this.nextId++}`,
      label,
      targetRound,
      lockedAtRound: this.round,
      keyCiphertext: ciphertext,
      payload,
      trace,
      plaintextBytes: new TextEncoder().encode(plaintext).length,
      opened: null,
    }
    this.items.unshift(item)
    this.notify()
    return item
  }

  /**
   * The identity for a round.
   *
   * Unchained: a pure function of the number, computable for any future round.
   * Chained: only defined once the previous signature exists — which is
   * precisely why a chained beacon cannot support timelock encryption. We
   * surface that as a thrown error rather than inventing a placeholder.
   */
  messageForRound(round: number): Uint8Array {
    if (this.scheme === 'unchained') {
      return roundMessage(round, 'unchained')
    }
    const published = this.beacon.at(round)
    if (!published) {
      throw new Error(
        `A chained beacon has no message for round ${round} yet — it depends on ${round - 1} signatures that do not exist.`,
      )
    }
    return published.message
  }

  /** Attempt to open an item with whatever the beacon has actually published. */
  async tryOpen(item: LockedItem): Promise<OpenOutcome> {
    const published = this.beacon.at(item.targetRound)
    if (!published) {
      if (this.beacon.isHalted) return { status: 'stranded' }
      return { status: 'too-early', roundsRemaining: item.targetRound - this.round }
    }
    return this.openWith(item, published.signature)
  }

  /** Open with an arbitrary G1 point — the break-it-yourself path. */
  async openWith(item: LockedItem, signature: G1Point): Promise<OpenOutcome> {
    const result = decrypt(signature, item.keyCiphertext)
    if (!result.ok) {
      return { status: 'rejected', reason: result.reason }
    }
    // `result.message` is the recovered 32-byte AES key.
    const message = await open(result.message, item.payload, beU64(item.targetRound))
    if (message === null) {
      return { status: 'rejected', reason: 'tampered' }
    }
    item.opened = message
    this.notify()
    return { status: 'opened', message }
  }

  /** Back to exactly the state the page loads in — including a running clock. */
  reset(): void {
    this.stop()
    this.beacon = new SimulatedBeacon(this.paramsFor(this.scheme))
    this.items.length = 0
    this.haltedAtRound = null
    this.chainEpoch++
    this.beacon.advanceTo(1)
    this.start()
  }
}

export const state = new LabState()
