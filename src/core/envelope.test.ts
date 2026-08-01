import { describe, expect, it } from 'vitest'
import { beU64, utf8 } from './bytes'
import { KEY_BYTES, NONCE_BYTES, TAG_BYTES, open, randomKey, seal } from './envelope'

const AAD = beU64(1234)

describe('AES-256-GCM envelope', () => {
  it('round-trips a message', async () => {
    const key = randomKey()
    const sealed = await seal(key, 'meet me at the usual place', AAD)
    expect(await open(key, sealed, AAD)).toBe('meet me at the usual place')
  })

  it('round-trips non-ASCII and empty payloads', async () => {
    const key = randomKey()
    for (const text of ['', '⏳', 'ünïcödé — 日本語 — 🎲']) {
      expect(await open(key, await seal(key, text, AAD), AAD)).toBe(text)
    }
  })

  it('uses a fresh nonce every time, so the same plaintext looks different', async () => {
    const key = randomKey()
    const a = await seal(key, 'identical', AAD)
    const b = await seal(key, 'identical', AAD)
    expect(a.nonce).not.toEqual(b.nonce)
    expect(a.ciphertext).not.toEqual(b.ciphertext)
  })

  it('carries exactly the GCM tag as overhead', async () => {
    const key = randomKey()
    const sealed = await seal(key, 'x'.repeat(100), AAD)
    expect(sealed.ciphertext.length).toBe(100 + TAG_BYTES)
    expect(sealed.nonce.length).toBe(NONCE_BYTES)
  })

  it('returns null for the wrong key', async () => {
    const sealed = await seal(randomKey(), 'secret', AAD)
    expect(await open(randomKey(), sealed, AAD)).toBeNull()
  })

  it('returns null when the payload is edited', async () => {
    const key = randomKey()
    const sealed = await seal(key, 'secret', AAD)
    const ciphertext = Uint8Array.from(sealed.ciphertext)
    ciphertext[0] = ciphertext[0]! ^ 1
    expect(await open(key, { ...sealed, ciphertext }, AAD)).toBeNull()
  })

  it('returns null when the nonce is edited', async () => {
    const key = randomKey()
    const sealed = await seal(key, 'secret', AAD)
    const nonce = Uint8Array.from(sealed.nonce)
    nonce[0] = nonce[0]! ^ 1
    expect(await open(key, { ...sealed, nonce }, AAD)).toBeNull()
  })

  it('binds the unlock round: relabelling the header breaks the tag', async () => {
    const key = randomKey()
    const sealed = await seal(key, 'opens at round 1234', beU64(1234))
    expect(await open(key, sealed, beU64(1234))).toBe('opens at round 1234')
    expect(await open(key, sealed, beU64(1235))).toBeNull()
  })

  it('refuses a key of the wrong size instead of padding it', async () => {
    await expect(seal(new Uint8Array(16), 'x', AAD)).rejects.toThrow(/32 bytes/)
  })

  it('produces keys of the size the timelock expects', () => {
    expect(randomKey().length).toBe(KEY_BYTES)
    expect(utf8('sanity').length).toBe(6)
  })
})
