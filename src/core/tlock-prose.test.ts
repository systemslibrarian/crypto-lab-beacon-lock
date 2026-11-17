/* How this lab describes its relationship to real tlock.
 *
 * The expert panel was corrected to "The same hybrid pattern as real tlock,
 * with different parts: tlock timelocks a 16-byte age file key and age seals
 * the document with ChaCha20-Poly1305, while this page timelocks a 32-byte key
 * and seals the text with AES-256-GCM." The doc comment on `lock()` still said
 * "Hybrid, exactly as real tlock does it: a fresh AES-256 key seals the text" —
 * which claims the parts are the same when the panel beside it says they are
 * not.
 *
 * Doc comments are not rendered, so the e2e gate cannot reach them; read as
 * text instead.
 */
import { describe, expect, it } from 'vitest'

import state from '../ui/state.ts?raw'
import lock from '../ui/lock.ts?raw'

describe('the tlock comparison', () => {
  it('never claims this lab does it exactly as tlock does', () => {
    for (const [name, text] of [
      ['src/ui/state.ts', state],
      ['src/ui/lock.ts', lock],
    ] as const) {
      expect(text, `${name}`).not.toContain('exactly as real tlock does it')
    }
  })

  it('names the parts that differ, in the comment as well as on the page', () => {
    for (const [name, text] of [
      ['src/ui/state.ts', state],
      ['src/ui/lock.ts', lock],
    ] as const) {
      expect(text, `${name} says the pattern is shared`).toContain(
        'The same hybrid pattern as real tlock, with different parts',
      )
      expect(text, `${name} names tlock's age file key`).toContain('16-byte age file key')
      expect(text, `${name} names tlock's AEAD`).toContain('ChaCha20-Poly1305')
      expect(text, `${name} names this lab's key size`).toContain('32-byte key')
    }
  })
})
