/**
 * Timelock encryption = Boneh–Franklin IBE with the clock as the identity.
 *
 * The trick, stated once plainly: an IBE ciphertext is addressed to an
 * arbitrary string, and only the authority holding the master secret can
 * extract that string's private key. Point the identity at a *future beacon
 * round* instead of at a person, and the authority becomes the beacon. It
 * extracts exactly one key per round, on schedule, in public, and it cannot be
 * hurried. The "private key" for round n is literally the beacon's signature
 * on round n — the same 48 bytes anyone can download afterward.
 *
 *   IBE                         timelock
 *   ────────────────────────    ──────────────────────────────
 *   master public key  P_pub  = the beacon's group public key
 *   identity           ID     = SHA-256(round number)
 *   key extraction     d_ID   = the beacon's signature on that round
 *   authority          PKG    = the League of Entropy, on a timer
 *
 * Scheme: Boneh–Franklin FullIdent (CRYPTO 2001, §4.2) — BasicIdent plus the
 * Fujisaki–Okamoto transform. The FO part is the `r` recomputation in
 * `decrypt`: it turns "wrong key produces garbage" into "wrong key is
 * *detected*", which is what lets this page reject a wrong-round signature
 * instead of silently emitting noise.
 *
 * Correctness rests on bilinearity, and on nothing else:
 *
 *   sender    computes   e(Q_ID, P_pub)^r  =  e(Q_ID, s·G₂)^r  =  e(Q_ID, G₂)^(s·r)
 *   receiver  computes   e(σ_ID, U)        =  e(s·Q_ID, r·G₂)  =  e(Q_ID, G₂)^(s·r)
 *
 * Two parties, no shared secret, no interaction, no communication after the
 * ciphertext — and the receiver's half is unavailable until the beacon ticks.
 *
 * INTEROP HONESTY: this is the same construction drand's `tlock` implements,
 * and the beacon half is byte-exact drand quicknet (gated by KATs against real
 * League of Entropy rounds). The H2/H3/H4 hashes below use this lab's own
 * domain-separation tags rather than kyber's, so ciphertexts produced here are
 * NOT byte-compatible with the `tlock` CLI. Same scheme, different wire format.
 */

import {
  CURVE,
  g2Base,
  g2FromBytes,
  gtPow,
  gtToBytes,
  hashToG1,
  hashToScalar,
  pairing,
  randomScalar,
  type G1Point,
  type G2Point,
  type GTElement,
} from './bls'
import { DRAND_SIG_DST } from './bls'
import { concat, xor } from './bytes'
import { xmd } from './xmd'

const H2_DST = 'CRYPTO-LAB-BEACON-LOCK-IBE-H2'
const H3_DST = 'CRYPTO-LAB-BEACON-LOCK-IBE-H3'
const H4_DST = 'CRYPTO-LAB-BEACON-LOCK-IBE-H4'

/** H₂: GT → n bytes. Masks σ with the pairing result. */
export function h2(gt: GTElement, n: number): Uint8Array {
  return xmd(gtToBytes(gt), H2_DST, n)
}

/** H₃: (σ, M) → scalar. The Fujisaki–Okamoto binding: r is a function of what it encrypts. */
export function h3(sigma: Uint8Array, message: Uint8Array): bigint {
  return hashToScalar(concat(sigma, message), H3_DST)
}

/** H₄: σ → n bytes. The one-time pad over the message itself. */
export function h4(sigma: Uint8Array, n: number): Uint8Array {
  return xmd(sigma, H4_DST, n)
}

export interface TimelockCiphertext {
  /** U = r·G₂ — 96 compressed bytes. */
  readonly U: G2Point
  /** V = σ ⊕ H₂(e(Q_ID, P_pub)^r). */
  readonly V: Uint8Array
  /** W = M ⊕ H₄(σ). */
  readonly W: Uint8Array
  /** Metadata, public and unauthenticated by design — it tells you when, not what. */
  readonly round: number
  readonly chainHash: string
}

/**
 * Everything the encryptor computed on the way. Kept OUT of the ciphertext:
 * `r`, `σ` and the GT mask are destroyed the moment a real sender finishes.
 * The UI holds this only so the mechanism panel can prove — byte for byte —
 * that the receiver's independently-derived mask is the same group element.
 */
export interface EncryptTrace {
  readonly identity: Uint8Array
  readonly Q: G1Point
  readonly Gid: GTElement
  readonly r: bigint
  readonly sigma: Uint8Array
  readonly maskGT: GTElement
  readonly h2Mask: Uint8Array
}

export interface EncryptResult {
  readonly ciphertext: TimelockCiphertext
  readonly trace: EncryptTrace
}

/**
 * Encrypt to an identity. `identity` is the beacon's round message — see
 * `roundMessage()` in beacon.ts — but the scheme neither knows nor cares that
 * it is a clock reading; that is the whole elegance.
 */
export function encrypt(
  publicKey: G2Point,
  identity: Uint8Array,
  message: Uint8Array,
  round: number,
  chainHash: string,
): EncryptResult {
  const Q = hashToG1(identity, DRAND_SIG_DST)
  const Gid = pairing(Q, publicKey)

  // σ is the FO transform's "coins". |σ| = |M| keeps the XOR structure uniform.
  const sigma = new Uint8Array(message.length)
  crypto.getRandomValues(sigma)

  const r = h3(sigma, message)
  const U = g2Base().multiply(r) as G2Point

  const maskGT = gtPow(Gid, r)
  const h2Mask = h2(maskGT, sigma.length)
  const V = xor(sigma, h2Mask)
  const W = xor(message, h4(sigma, message.length))

  return {
    ciphertext: { U, V, W, round, chainHash },
    trace: { identity, Q, Gid, r, sigma, maskGT, h2Mask },
  }
}

export type DecryptFailure =
  | 'wrong-round'
  | 'tampered'
  | 'malformed'
  | 'no-signature'

export interface DecryptTrace {
  readonly maskGT: GTElement
  readonly sigma: Uint8Array
  readonly recomputedR: bigint
  readonly recomputedU: G2Point
}

export type DecryptResult =
  | { readonly ok: true; readonly message: Uint8Array; readonly trace: DecryptTrace }
  | { readonly ok: false; readonly reason: DecryptFailure; readonly trace?: DecryptTrace }

/**
 * Decrypt with the beacon's signature for the target round.
 *
 * Fail-closed: the Fujisaki–Okamoto check at the end (`U == r'·G₂`) is not
 * optional decoration. Without it, *any* G1 point decrypts to *some* byte
 * string, and the demo would happily print noise as if it were plaintext.
 * With it, a signature for the wrong round, a flipped bit in V or W, and a
 * hand-forged σ are all rejected rather than guessed at.
 */
export function decrypt(signature: G1Point, ct: TimelockCiphertext): DecryptResult {
  let maskGT: GTElement
  try {
    maskGT = pairing(signature, ct.U)
  } catch {
    return { ok: false, reason: 'malformed' }
  }

  const sigma = xor(ct.V, h2(maskGT, ct.V.length))
  const message = xor(ct.W, h4(sigma, ct.W.length))
  const recomputedR = h3(sigma, message)
  const recomputedU = g2Base().multiply(recomputedR) as G2Point
  const trace: DecryptTrace = { maskGT, sigma, recomputedR, recomputedU }

  if (!recomputedU.equals(ct.U)) {
    // The check cannot tell us *which* input was wrong — it only says the
    // triple is inconsistent. The UI reports it as "rejected", not as a
    // diagnosis, because claiming more would be a lie about what was verified.
    return { ok: false, reason: 'wrong-round', trace }
  }
  return { ok: true, message, trace }
}

/** Wire encoding: U ‖ V ‖ W. Round and chain hash travel in the header. */
export function serializeCiphertext(ct: TimelockCiphertext): Uint8Array {
  return concat(ct.U.toBytes(), ct.V, ct.W)
}

export function deserializeCiphertext(
  bytes: Uint8Array,
  round: number,
  chainHash: string,
): TimelockCiphertext {
  const g2 = CURVE.g2CompressedBytes
  if (bytes.length < g2 + 2 || (bytes.length - g2) % 2 !== 0) {
    throw new Error(`deserializeCiphertext: bad length ${bytes.length}`)
  }
  const bodyLength = (bytes.length - g2) / 2
  return {
    U: g2FromBytes(bytes.subarray(0, g2)),
    V: bytes.slice(g2, g2 + bodyLength),
    W: bytes.slice(g2 + bodyLength),
    round,
    chainHash,
  }
}

/** Ciphertext overhead in bytes: the G2 element plus one σ-sized block. */
export function ciphertextOverhead(messageBytes: number): number {
  return CURVE.g2CompressedBytes + messageBytes
}

/** A fresh scalar, exported so the mechanism panel can re-run the sender's coin flip. */
export { randomScalar }
