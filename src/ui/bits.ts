/** Corruption helpers for the attack panel. Copy first — never mutate a live ciphertext. */

export function flipBit(bytes: Uint8Array, index: number, mask: number): Uint8Array {
  const copy = Uint8Array.from(bytes)
  const at = copy[index]
  if (at === undefined) throw new Error(`flipBit: index ${index} is past the end (${copy.length})`)
  copy[index] = at ^ mask
  return copy
}
