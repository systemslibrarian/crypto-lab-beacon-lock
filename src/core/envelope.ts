/**
 * Hybrid envelope — AES-256-GCM under a timelocked key.
 *
 * The IBE above encrypts exactly |σ| bytes, and pairings are not cheap, so
 * nobody timelocks a document directly. Real tlock does what TLS, PGP and age
 * all do: draw a fresh symmetric key, seal the payload under it, and timelock
 * the key. The pairing work is a fixed 32 bytes regardless of whether the
 * payload is a password or a leaked archive.
 *
 * The AEAD is WebCrypto's — real AES-GCM, in the browser, not a stand-in.
 * Its tag is also what turns "someone edited the payload" into a clean
 * rejection instead of corrupted output.
 */

import { fromUtf8, utf8 } from './bytes'

export const KEY_BYTES = 32
export const NONCE_BYTES = 12
export const TAG_BYTES = 16

export interface SealedPayload {
  readonly nonce: Uint8Array
  readonly ciphertext: Uint8Array
}

export function randomKey(): Uint8Array {
  const key = new Uint8Array(KEY_BYTES)
  crypto.getRandomValues(key)
  return key
}

async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== KEY_BYTES) throw new Error(`envelope: key must be ${KEY_BYTES} bytes`)
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/**
 * Seal a message. The round number is bound in as additional authenticated
 * data, so a payload cannot be quietly re-labelled with a different unlock
 * time: change the header and the tag stops verifying.
 */
export async function seal(key: Uint8Array, plaintext: string, aad: Uint8Array): Promise<SealedPayload> {
  const nonce = new Uint8Array(NONCE_BYTES)
  crypto.getRandomValues(nonce)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource },
      await importKey(key),
      utf8(plaintext) as BufferSource,
    ),
  )
  return { nonce, ciphertext }
}

/** `null` on any authentication failure — wrong key, edited payload, edited AAD. */
export async function open(
  key: Uint8Array,
  payload: SealedPayload,
  aad: Uint8Array,
): Promise<string | null> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: payload.nonce as BufferSource, additionalData: aad as BufferSource },
      await importKey(key),
      payload.ciphertext as BufferSource,
    )
    return fromUtf8(new Uint8Array(plaintext))
  } catch {
    return null
  }
}
