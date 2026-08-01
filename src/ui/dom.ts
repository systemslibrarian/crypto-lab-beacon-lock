/** Tiny DOM helpers. No framework — the crypto is the interesting part. */

type Attrs = Record<string, string | number | boolean | undefined>
type Child = Node | string | null | undefined | Child[]

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue
    if (k === 'class') node.className = String(v)
    else if (k === 'text') node.textContent = String(v)
    else node.setAttribute(k, v === true ? '' : String(v))
  }
  append(node, children)
  return node
}

export function svg(tag: string, attrs: Attrs = {}, ...children: Child[]): SVGElement {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue
    if (k === 'text') node.textContent = String(v)
    else node.setAttribute(k, v === true ? '' : String(v))
  }
  append(node, children)
  return node
}

export function append(parent: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined) continue
    if (Array.isArray(c)) append(parent, c)
    else parent.appendChild(typeof c === 'string' ? document.createTextNode(c) : c)
  }
}

export function add(parent: Node, ...children: Child[]): void {
  append(parent, children)
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild)
}

/** A titled panel. Every exhibit is one of these. */
export function panel(id: string, heading: string, lede?: string): HTMLElement {
  const section = el('section', { class: 'panel', id, 'aria-labelledby': `${id}-h` })
  section.appendChild(el('h2', { id: `${id}-h`, text: heading }))
  if (lede) section.appendChild(el('p', { class: 'panel-lede', text: lede }))
  return section
}

/** Collapsed depth for the expert reader — progressive disclosure, §2. */
export function expert(summary: string, ...children: Child[]): HTMLDetailsElement {
  const d = el('details', { class: 'expert' })
  d.appendChild(el('summary', { text: summary }))
  append(d, children)
  return d
}

/** A scoping note: what this specific thing is not. */
export function honesty(...children: Child[]): HTMLElement {
  return el('p', { class: 'honesty' }, ...children)
}

/**
 * A monospace value display. Scrollable regions get tabindex + role + label
 * because axe (rightly) fails a keyboard-unreachable scroll container.
 */
export function hexBlock(text: string, label: string, extra = ''): HTMLElement {
  return el(
    'div',
    { class: `hexblock ${extra}`.trim(), tabindex: '0', role: 'group', 'aria-label': label },
    el('span', { class: 'hex', text }),
  )
}

/**
 * WCAG 1.4.1: never colour alone — every verdict is icon + word + colour, and
 * the icon is aria-hidden so the word carries the meaning.
 *
 * `tone` tracks SYSTEM INTEGRITY, not the boolean. A ciphertext that opened
 * when it should not have is `alarm`, even though decryption "succeeded".
 */
export type Tone = 'ok' | 'alarm' | 'warn' | 'idle' | 'locked'

const ICONS: Record<Tone, string> = { ok: '✓', alarm: '✗', warn: '!', idle: '·', locked: '⏳' }

export function verdict(tone: Tone, label: string, detail?: string): HTMLElement {
  return el(
    'p',
    { class: `verdict verdict-${tone}` },
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: ICONS[tone] }),
    el('strong', { text: label }),
    detail ? el('span', { class: 'verdict-detail', text: ` — ${detail}` }) : null,
  )
}

export function stat(label: string, value: string, tone: Tone = 'idle'): HTMLElement {
  return el(
    'div',
    { class: `stat stat-${tone}` },
    el('span', { class: 'stat-label', text: label }),
    el('span', { class: 'stat-value', text: value }),
  )
}

export function statRow(...stats: Child[]): HTMLElement {
  return el('div', { class: 'statrow' }, ...stats)
}

/** A labelled proportional bar. */
export function meter(label: string, value: number, max: number, valueText: string): HTMLElement {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0
  return el(
    'div',
    { class: 'meter' },
    el(
      'div',
      { class: 'meter-head' },
      el('span', { class: 'meter-label', text: label }),
      el('span', { class: 'meter-value', text: valueText }),
    ),
    el(
      'div',
      { class: 'meter-track', role: 'img', 'aria-label': `${label}: ${valueText}` },
      el('div', { class: 'meter-fill', style: `width:${pct}%` }),
    ),
  )
}

/** A live region for async / on-click results. */
export function liveRegion(label: string, extra = ''): HTMLElement {
  return el('div', {
    class: `live ${extra}`.trim(),
    role: 'status',
    'aria-live': 'polite',
    'aria-label': label,
  })
}

export function button(label: string, onClick: () => void, extra = ''): HTMLButtonElement {
  const b = el('button', { type: 'button', class: `btn ${extra}`.trim(), text: label })
  b.addEventListener('click', onClick)
  return b
}

export function labelledInput(
  id: string,
  labelText: string,
  value: string,
  attrs: Attrs = {},
): { wrap: HTMLElement; input: HTMLInputElement } {
  const input = el('input', { type: 'text', id, value, ...attrs })
  const wrap = el(
    'div',
    { class: 'ctl' },
    el('label', { class: 'ctl-label', for: id, text: labelText }),
    input,
  )
  return { wrap, input }
}

export function labelledSelect(
  id: string,
  labelText: string,
  options: Array<{ value: string; text: string }>,
): { wrap: HTMLElement; select: HTMLSelectElement } {
  const select = el('select', { id })
  for (const o of options) select.appendChild(el('option', { value: o.value, text: o.text }))
  const wrap = el(
    'div',
    { class: 'ctl' },
    el('label', { class: 'ctl-label', for: id, text: labelText }),
    select,
  )
  return { wrap, select }
}

export function labelledRange(
  id: string,
  labelText: string,
  attrs: Attrs,
): { wrap: HTMLElement; input: HTMLInputElement; readout: HTMLElement } {
  const input = el('input', { type: 'range', id, ...attrs })
  const readout = el('output', { class: 'ctl-readout', for: id })
  const wrap = el(
    'div',
    { class: 'ctl ctl-range' },
    el('label', { class: 'ctl-label', for: id, text: labelText }),
    input,
    readout,
  )
  return { wrap, input, readout }
}

/** Middle-elide a long hex string for display. */
export function elide(s: string, head = 32, tail = 16): string {
  if (s.length <= head + tail + 1) return s
  return `${s.slice(0, head)}…${s.slice(-tail)}`
}

/**
 * Show two hex strings with differing nibbles marked.
 *
 * This is the §2 "compute both sides and compare" primitive: equality is
 * *shown*, never asserted. Marks are boxed as well as coloured so they survive
 * greyscale and every flavour of colour-vision deficiency.
 */
export function hexDiff(
  a: string,
  b: string,
  labelA: string,
  labelB: string,
  unit = 'hex digits',
): HTMLElement {
  const width = Math.max(a.length, b.length)
  let differing = 0
  for (let i = 0; i < width; i++) if (a[i] !== b[i]) differing++
  // Marking every nibble when two values are unrelated is noise, so past a
  // third we say it in words and tint the block as a unit instead.
  const perNibble = differing > 0 && differing <= width / 3

  const wrap = el('div', { class: 'hexdiff' })
  for (const [text, label] of [
    [a, labelA],
    [b, labelB],
  ] as const) {
    const row = el('div', { class: 'hexdiff-row' })
    row.appendChild(el('span', { class: 'hexdiff-label', text: label }))
    const box = el('div', {
      class: `hexblock hexblock-tall ${differing === 0 ? 'hexblock-same' : 'hexblock-differs'}`,
      tabindex: '0',
      role: 'group',
      'aria-label': `${label} — ${text.length} ${unit}`,
    })
    const span = el('span', { class: 'hex' })
    if (perNibble) {
      const other = text === a ? b : a
      for (let i = 0; i < text.length; i++) {
        const ch = text[i]!
        if (other[i] !== ch) span.appendChild(el('mark', { class: 'nib', text: ch }))
        else span.appendChild(document.createTextNode(ch))
      }
    } else {
      span.textContent = text
    }
    box.appendChild(span)
    row.appendChild(box)
    wrap.appendChild(row)
  }
  wrap.appendChild(
    el(
      'p',
      { class: `hexdiff-summary ${differing === 0 ? 'hexdiff-equal' : 'hexdiff-unequal'}` },
      el('span', { 'aria-hidden': 'true', text: differing === 0 ? '✓ ' : '✗ ' }),
      differing === 0
        ? `Identical — all ${width} ${unit} match.`
        : `${differing} of ${width} ${unit} differ.`,
    ),
  )
  return wrap
}

/** A definition list of jargon, for the newcomer on-ramp. */
export function glossary(entries: Array<[string, string]>): HTMLElement {
  const dl = el('dl', { class: 'glossary' })
  for (const [term, def] of entries) {
    dl.appendChild(el('dt', { text: term }))
    dl.appendChild(el('dd', { text: def }))
  }
  return dl
}
