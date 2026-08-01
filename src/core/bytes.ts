/**
 * Byte plumbing. Nothing clever — but every function here is on the path
 * between a beacon signature and a plaintext, so each one is tested.
 */

const HEX = '0123456789abcdef'

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += HEX[b >> 4]! + HEX[b & 15]!
  return out
}

export function fromHex(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex
  if (s.length % 2 !== 0) throw new Error(`fromHex: odd length ${s.length}`)
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) throw new Error(`fromHex: bad hex at ${i * 2}`)
    out[i] = byte
  }
  return out
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error(`xor: length mismatch ${a.length} vs ${b.length}`)
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!
  return out
}

/** RFC 8017 I2OSP — big-endian fixed-width integer encoding. */
export function i2osp(value: number, length: number): Uint8Array {
  if (value < 0 || value >= 256 ** length) throw new Error(`i2osp: ${value} does not fit in ${length} bytes`)
  const out = new Uint8Array(length)
  let v = value
  for (let i = length - 1; i >= 0; i--) {
    out[i] = v & 0xff
    v >>>= 8
  }
  return out
}

/** RFC 8017 OS2IP — big-endian bytes to a (possibly huge) integer. */
export function os2ip(bytes: Uint8Array): bigint {
  let v = 0n
  for (const b of bytes) v = (v << 8n) | BigInt(b)
  return v
}

/**
 * drand encodes a round number as a big-endian uint64 before hashing it.
 * This is the one place the "identity" of a future moment gets its bytes.
 */
export function beU64(round: number | bigint): Uint8Array {
  let v = BigInt(round)
  if (v < 0n || v > 0xffffffffffffffffn) throw new Error(`beU64: ${round} out of range`)
  const out = new Uint8Array(8)
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/**
 * Length-independent-ish equality. JavaScript cannot promise constant time, so
 * this is branch-free over the compared bytes and nothing more — we never
 * claim side-channel resistance for it, and the demo says so.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

/** Count of differing hex digits — used by the compare-both-sides readouts. */
export function hexDigitsDiffering(a: string, b: string): number {
  const width = Math.max(a.length, b.length)
  let n = 0
  for (let i = 0; i < width; i++) if (a[i] !== b[i]) n++
  return n
}
