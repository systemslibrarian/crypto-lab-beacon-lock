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
 * INTEROP: this is byte-compatible with drand's `tlock`. H₂/H₃/H₄ below are
 * kyber's `encrypt/ibe` functions reimplemented exactly — same tags, same
 * SHA-256 truncation, same rejection-sampling loop, same GT serialization —
 * and the group layout is `EncryptCCAonG2` (master key in G2, identities in G1,
 * U in G2), which is what quicknet uses.
 *
 * That claim is gated, not asserted: `tlock.test.ts` decrypts a real ciphertext
 * from the drand/tlock test corpus using the real testnet beacon signature, and
 * the Fujisaki–Okamoto check at the end of `decrypt` makes a wrong H₂, H₃, H₄
 * or GT encoding a 1-in-2²⁵⁵ accident rather than something that quietly works.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import {
  CURVE,
  g2Base,
  g2FromBytes,
  gtPow,
  gtToKyberBytes,
  hashToG1,
  pairing,
  randomScalar,
  type G1Point,
  type G2Point,
  type GTElement,
} from './bls'
import { DRAND_SIG_DST } from './bls'
import { concat, os2ip, utf8, xor } from './bytes'

const H2_TAG = utf8('IBE-H2')
const H3_TAG = utf8('IBE-H3')
const H4_TAG = utf8('IBE-H4')

/**
 * The scheme masks with SHA-256 output, so a payload can never exceed the hash
 * size. Real tlock relies on this too: it timelocks a 16-byte age file key.
 */
export const MAX_MESSAGE_BYTES = 32

/**
 * H₂: GT → n bytes. `SHA-256("IBE-H2" ‖ gt)` truncated.
 *
 * The GT bytes must be kyber's serialization, not noble's — see
 * `gtToKyberBytes`. This is the single place where the two libraries' Fp12
 * layouts have to be reconciled, and getting it wrong produces ciphertexts
 * that look perfect and interoperate with nothing.
 */
export function h2(gt: GTElement, n: number): Uint8Array {
  return sha256(concat(H2_TAG, gtToKyberBytes(gt))).slice(0, n)
}

/**
 * H₃: (σ, M) → scalar. The Fujisaki–Okamoto binding — r is a function of
 * exactly what it encrypts, which is what makes the ciphertext non-malleable.
 *
 * kyber does not reduce modulo the group order; it rejection-samples, and the
 * iteration counter is a LITTLE-endian uint16 while the candidate scalar is
 * read BIG-endian. The top bit is masked off first because BLS12-381's scalar
 * field is 255 bits inside a 256-bit canonical encoding. Reproduced here
 * faithfully, quirks included, because interoperability lives in the quirks.
 */
export function h3(sigma: Uint8Array, message: Uint8Array): bigint {
  const buffer = sha256(concat(H3_TAG, sigma, message))
  // 256-bit canonical encoding over a 255-bit field ⇒ one bit to mask.
  const toMask = 1
  for (let i = 1; i < 65535; i++) {
    const counter = Uint8Array.from([i & 0xff, (i >> 8) & 0xff])
    const hashed = Uint8Array.from(sha256(concat(counter, buffer)))
    hashed[0] = hashed[0]! >> toMask
    const candidate = os2ip(hashed)
    if (candidate < CURVE.order && candidate !== 0n) return candidate
  }
  throw new Error('h3: rejection sampling failure')
}

/** H₄: σ → n bytes. `SHA-256("IBE-H4" ‖ σ)` truncated — the pad over the message. */
export function h4(sigma: Uint8Array, n: number): Uint8Array {
  return sha256(concat(H4_TAG, sigma)).slice(0, n)
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
  if (message.length > MAX_MESSAGE_BYTES) {
    throw new Error(
      `encrypt: payload is ${message.length} bytes; the scheme masks with SHA-256 output, so ${MAX_MESSAGE_BYTES} is the ceiling. Timelock a symmetric key and seal the payload under it.`,
    )
  }
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
