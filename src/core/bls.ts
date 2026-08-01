/**
 * BLS12-381 handles, in the shape drand uses.
 *
 * Division of labour, per §1 of the lab standard ("hand-roll the inspectable
 * teaching parts; a named, justified library for the rest"):
 *
 *   @noble/curves owns  — Fp/Fp2/Fp12 arithmetic, the curve group law, the
 *                         SSWU map in hash-to-curve, and the optimal-Ate
 *                         pairing. Nobody learns anything from a hand-written
 *                         Miller loop, and a wrong one would be a liability.
 *   this lab owns       — the round → identity encoding, BLS sign/verify as an
 *                         explicit pairing equation, the kyber GT serialization,
 *                         and the whole IBE (src/core/tlock.ts).
 *
 * The teaching subject is the timelock construction, and every line of that is
 * readable here.
 *
 * Group layout is drand "quicknet" (scheme `bls-unchained-g1-rfc9380`):
 * signatures live in G1 (48 compressed bytes), public keys in G2 (96 bytes).
 * That is the opposite of the more familiar Ethereum layout, and it is the
 * cheap direction for a beacon that publishes a signature every three seconds.
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381.js'
import { os2ip } from './bytes'

export type G1Point = InstanceType<typeof bls.G1.Point>
export type G2Point = InstanceType<typeof bls.G2.Point>
export type GTElement = ReturnType<typeof bls.pairing>

/** Curve facts the UI quotes. Verified against the library in bls.test.ts. */
export const CURVE = {
  /** Prime order of G1, G2 and GT — the scalar field. ~255 bits. */
  order: bls.fields.Fr.ORDER,
  /** Base field prime. 381 bits, which is where the curve gets its name. */
  fieldPrime: bls.fields.Fp.ORDER,
  g1CompressedBytes: 48,
  g2CompressedBytes: 96,
  gtBytes: 576,
  /** Conjectured security after the 2016 exTNFS improvements dropped it from 128. */
  securityBits: 126,
} as const

/**
 * RFC 9380 suite tag drand signs under. The `_NUL_` suffix is the "basic"
 * BLS scheme of draft-irtf-cfrg-bls-signature (no proof-of-possession, no
 * message augmentation). Changing one byte of this string yields a different,
 * incompatible beacon — which is the point of domain separation.
 */
export const DRAND_SIG_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_'

export const G1 = bls.G1
export const G2 = bls.G2
export const Fp12 = bls.fields.Fp12

/** G2 generator — the base point every public key is a multiple of. */
export function g2Base(): G2Point {
  return bls.G2.Point.BASE as G2Point
}

/** H1: bytes → G1, RFC 9380 hash-to-curve. This is the IBE identity map. */
export function hashToG1(msg: Uint8Array, dst: string = DRAND_SIG_DST): G1Point {
  return bls.G1.hashToCurve(msg, { DST: dst }) as G1Point
}

export function pairing(p: G1Point, q: G2Point): GTElement {
  return bls.pairing(p, q)
}

export function gtToBytes(gt: GTElement): Uint8Array {
  return Fp12.toBytes(gt)
}

/**
 * The GT encoding drand's kyber produces — which is what the IBE's H₂ hashes,
 * so getting it wrong means ciphertexts that are structurally correct and
 * mutually unintelligible.
 *
 * kyber's BLS12-381 backend serializes the Fp12 tower in the opposite
 * coefficient order to @noble/curves: where noble writes
 * c0.c0.c0 … c1.c2.c1, kyber writes c1.c2.c1 … c0.c0.c0. Each 48-byte Fp limb
 * is big-endian in both, so the conversion is exactly a reversal of the twelve
 * limbs — no byte-swapping inside them.
 *
 * This is not a guess. It was recovered by decrypting a real `tlock` ciphertext
 * from the drand/tlock test corpus and is pinned by a known-answer test
 * (`tlock.test.ts`), where the Fujisaki–Okamoto check makes a wrong encoding a
 * 1-in-2²⁵⁵ accident.
 */
export function gtToKyberBytes(gt: GTElement): Uint8Array {
  const raw = Fp12.toBytes(gt)
  const limb = 48
  const count = raw.length / limb
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < count; i++) {
    out.set(raw.subarray(i * limb, (i + 1) * limb), (count - 1 - i) * limb)
  }
  return out
}

export function gtPow(gt: GTElement, exponent: bigint): GTElement {
  return Fp12.pow(gt, exponent)
}

export function gtEqual(a: GTElement, b: GTElement): boolean {
  return Fp12.eql(a, b)
}

/**
 * A uniform scalar in [1, order-1].
 *
 * Rejection sampling, not `mod order`: reducing a 32-byte integer modulo a
 * 255-bit prime is biased toward small scalars, and "it's only a tiny bias" is
 * how nonce-reuse papers start. We draw 48 bytes and reduce, which puts the
 * bias below 2^-128 — the same margin RFC 9380 uses for hash_to_field.
 */
export function randomScalar(): bigint {
  const bytes = new Uint8Array(48)
  for (;;) {
    crypto.getRandomValues(bytes)
    const s = os2ip(bytes) % CURVE.order
    if (s !== 0n) return s
  }
}

/** Deserialize a compressed G1 point, rejecting anything off-curve or off-subgroup. */
export function g1FromBytes(bytes: Uint8Array): G1Point {
  const p = bls.G1.Point.fromBytes(bytes) as G1Point
  p.assertValidity()
  return p
}

/** Deserialize a compressed G2 point, rejecting anything off-curve or off-subgroup. */
export function g2FromBytes(bytes: Uint8Array): G2Point {
  const p = bls.G2.Point.fromBytes(bytes) as G2Point
  p.assertValidity()
  return p
}
