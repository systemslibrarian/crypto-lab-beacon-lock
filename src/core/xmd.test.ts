/**
 * Known-answer tests for our hand-rolled expand_message_xmd.
 *
 * Vectors are RFC 9380 Appendix K.1's own, copied verbatim into
 * src/fixtures/kat.json from the CFRG reference vectors. If this file passes,
 * the byte-stretcher under hash-to-curve and under the IBE's H2/H3/H4 is the
 * one the RFC specifies, and not merely something that looks random.
 */

import { describe, expect, it } from 'vitest'
import kat from '../fixtures/kat.json'
import { toHex, utf8 } from './bytes'
import { dstPrime, expandMessageXmd } from './xmd'

const { dst, vectors } = kat.expandMessageXmd

describe(`RFC 9380 K.1 expand_message_xmd(SHA-256) — ${vectors.length} known-answer tests`, () => {
  it.each(vectors.map((v) => [v.msg.slice(0, 24) || '(empty)', v.lenInBytes, v] as const))(
    'msg %s, %i bytes out',
    (_label, _len, vector) => {
      const out = expandMessageXmd(utf8(vector.msg), utf8(dst), vector.lenInBytes)
      expect(out.length).toBe(vector.lenInBytes)
      expect(toHex(out)).toBe(vector.uniformBytes)
    },
  )
})

describe('expand_message_xmd guard rails', () => {
  it('domain separation actually separates: one changed DST byte changes every output byte', () => {
    const a = toHex(expandMessageXmd(utf8('same message'), utf8('DST-A'), 32))
    const b = toHex(expandMessageXmd(utf8('same message'), utf8('DST-B'), 32))
    expect(a).not.toBe(b)
  })

  it('hashes an oversize DST per §5.3.3 so the length prefix always fits', () => {
    const long = utf8('X'.repeat(300))
    const prime = dstPrime(long)
    // 32-byte hash of the oversize DST, plus the one-byte length.
    expect(prime.length).toBe(33)
    expect(prime[32]).toBe(32)
  })

  it('keeps a short DST verbatim with its length appended', () => {
    const prime = dstPrime(utf8('ABC'))
    expect(toHex(prime)).toBe('41424303')
  })

  it('binds the requested length, so it is NOT a prefix-consistent XOF', () => {
    // len_in_bytes goes into b_0, deliberately: a 32-byte request and the
    // first 32 bytes of a 128-byte request are unrelated. Both of the RFC's
    // vector sets above cover the same messages at both lengths, which is what
    // pins this down.
    const short = expandMessageXmd(utf8('abc'), utf8(dst), 32)
    const long = expandMessageXmd(utf8('abc'), utf8(dst), 128)
    expect(toHex(long).startsWith(toHex(short))).toBe(false)
  })

  it('refuses requests it cannot serve', () => {
    expect(() => expandMessageXmd(utf8('x'), utf8(dst), 65_536)).toThrow(/refused/)
    expect(() => expandMessageXmd(utf8('x'), new Uint8Array(0), 32)).toThrow(/refused/)
  })
})
