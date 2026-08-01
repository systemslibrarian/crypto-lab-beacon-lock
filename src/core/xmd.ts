/**
 * RFC 9380 §5.3.1 — expand_message_xmd, hand-rolled.
 *
 * This is the deterministic byte-stretcher underneath everything else on the
 * page: hash-to-curve uses it to reach a field element, and our IBE's H2/H3/H4
 * use it to reach a mask, a scalar and a keystream. It is short enough to read
 * in one sitting, which is exactly why it is written out here rather than
 * imported — §1 of the lab standard: hand-roll the inspectable internals.
 *
 * Gated by the RFC's own expand_message_xmd/SHA-256 test vectors
 * (see xmd.test.ts).
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { concat, i2osp, utf8, xor } from './bytes'

const B_IN_BYTES = 32 // SHA-256 output
const S_IN_BYTES = 64 // SHA-256 input block

/**
 * RFC 9380 §5.3.3: a DST longer than 255 bytes is itself hashed, so the
 * one-byte length prefix in DST_prime always fits.
 */
export function dstPrime(dst: Uint8Array): Uint8Array {
  const d = dst.length > 255 ? sha256(concat(utf8('H2C-OVERSIZE-DST-'), dst)) : dst
  return concat(d, i2osp(d.length, 1))
}

export function expandMessageXmd(msg: Uint8Array, dst: Uint8Array, lenInBytes: number): Uint8Array {
  const ell = Math.ceil(lenInBytes / B_IN_BYTES)
  if (ell > 255 || lenInBytes > 65535 || dst.length < 1) {
    throw new Error(`expand_message_xmd: refused (ell=${ell}, len=${lenInBytes})`)
  }

  const dstP = dstPrime(dst)
  const zPad = new Uint8Array(S_IN_BYTES)
  const msgPrime = concat(zPad, msg, i2osp(lenInBytes, 2), i2osp(0, 1), dstP)

  const b0 = sha256(msgPrime)
  const blocks: Uint8Array[] = [sha256(concat(b0, i2osp(1, 1), dstP))]
  for (let i = 2; i <= ell; i++) {
    blocks.push(sha256(concat(xor(b0, blocks[i - 2]!), i2osp(i, 1), dstP)))
  }
  return concat(...blocks).subarray(0, lenInBytes)
}

/** Convenience wrapper for the string DSTs used throughout this lab. */
export function xmd(msg: Uint8Array, dst: string, lenInBytes: number): Uint8Array {
  return expandMessageXmd(msg, utf8(dst), lenInBytes)
}
