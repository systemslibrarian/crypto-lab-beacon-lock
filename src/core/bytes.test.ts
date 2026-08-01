import { describe, expect, it } from 'vitest'
import {
  beU64,
  bytesEqual,
  concat,
  fromHex,
  fromUtf8,
  hexDigitsDiffering,
  i2osp,
  os2ip,
  toHex,
  utf8,
  xor,
} from './bytes'

describe('hex', () => {
  it('round-trips', () => {
    const bytes = Uint8Array.from([0, 1, 15, 16, 127, 128, 255])
    expect(toHex(bytes)).toBe('00010f107f80ff')
    expect(fromHex(toHex(bytes))).toEqual(bytes)
  })

  it('accepts a 0x prefix and rejects malformed input', () => {
    expect(fromHex('0xdeadbeef')).toEqual(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))
    expect(() => fromHex('abc')).toThrow(/odd length/)
    expect(() => fromHex('zz')).toThrow(/bad hex/)
  })
})

describe('utf8', () => {
  it('round-trips non-ASCII', () => {
    expect(fromUtf8(utf8('⏳ résumé 日本'))).toBe('⏳ résumé 日本')
  })
})

describe('beU64 — the round-number encoding drand hashes', () => {
  it('is big-endian and fixed width', () => {
    expect(toHex(beU64(0))).toBe('0000000000000000')
    expect(toHex(beU64(1))).toBe('0000000000000001')
    expect(toHex(beU64(1000))).toBe('00000000000003e8')
    expect(toHex(beU64(0xffffffffffffffffn))).toBe('ffffffffffffffff')
  })

  it('refuses out-of-range rounds rather than truncating', () => {
    expect(() => beU64(-1)).toThrow()
    expect(() => beU64(1n << 64n)).toThrow()
  })
})

describe('i2osp / os2ip', () => {
  it('round-trips', () => {
    expect(toHex(i2osp(1, 1))).toBe('01')
    expect(toHex(i2osp(65535, 2))).toBe('ffff')
    expect(os2ip(i2osp(300, 2))).toBe(300n)
    expect(os2ip(Uint8Array.from([1, 0]))).toBe(256n)
  })

  it('refuses values that do not fit', () => {
    expect(() => i2osp(256, 1)).toThrow(/does not fit/)
  })
})

describe('xor', () => {
  it('is its own inverse', () => {
    const a = Uint8Array.from([1, 2, 3, 4])
    const b = Uint8Array.from([0xff, 0x00, 0xa5, 0x5a])
    expect(xor(xor(a, b), b)).toEqual(a)
  })

  it('refuses mismatched lengths instead of silently truncating', () => {
    expect(() => xor(new Uint8Array(3), new Uint8Array(4))).toThrow(/length mismatch/)
  })
})

describe('concat', () => {
  it('preserves order and total length', () => {
    expect(toHex(concat(fromHex('aa'), fromHex('bbcc'), new Uint8Array(0)))).toBe('aabbcc')
  })
})

describe('bytesEqual', () => {
  it('distinguishes content and length', () => {
    expect(bytesEqual(fromHex('aabb'), fromHex('aabb'))).toBe(true)
    expect(bytesEqual(fromHex('aabb'), fromHex('aabc'))).toBe(false)
    expect(bytesEqual(fromHex('aabb'), fromHex('aa'))).toBe(false)
  })
})

describe('hexDigitsDiffering', () => {
  it('counts differing positions, including length overhang', () => {
    expect(hexDigitsDiffering('abcd', 'abcd')).toBe(0)
    expect(hexDigitsDiffering('abcd', 'abce')).toBe(1)
    expect(hexDigitsDiffering('ab', 'abcd')).toBe(2)
  })
})
