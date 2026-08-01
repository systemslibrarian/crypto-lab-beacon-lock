/**
 * Exhibit navigator. The page is long on purpose — each exhibit is the whole
 * story for somebody — so this is the map, plus the beacon status readout that
 * every panel depends on and the presenter controls.
 */

import { add, button, clear, el } from './dom'
import { state } from './state'

export const SECTIONS: ReadonlyArray<{ id: string; label: string }> = [
  { id: 'intro', label: 'Idea' },
  { id: 'lock', label: 'Lock a secret' },
  { id: 'beacon', label: 'The beacon' },
  { id: 'mechanism', label: 'Mechanism' },
  { id: 'compare', label: 'Three models' },
  { id: 'outage', label: 'If the beacon dies' },
  { id: 'attack', label: 'Break it' },
  { id: 'scope', label: 'Scope' },
]

export function mountNav(host: HTMLElement): void {
  const nav = el('nav', { class: 'labnav', 'aria-label': 'Exhibits' })
  const list = el('ul', { class: 'labnav-list' })
  const links = new Map<string, HTMLAnchorElement>()

  for (const section of SECTIONS) {
    const a = el('a', { class: 'labnav-link', href: `#${section.id}`, text: section.label })
    links.set(section.id, a)
    list.appendChild(el('li', {}, a))
  }

  // Narrow viewports get a menu instead of a horizontally scrolling strip.
  const select = el('select', { class: 'labnav-select', 'aria-label': 'Jump to an exhibit' })
  for (const section of SECTIONS) {
    select.appendChild(el('option', { value: section.id, text: section.label }))
  }
  select.addEventListener('change', () => {
    document.getElementById(select.value)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  })

  const resetBtn = button('Reset lab', () => state.reset(), 'btn-quiet btn-small')
  resetBtn.title = 'Restart the beacon at round 1 and discard every locked ciphertext'

  const status = el('p', {
    class: 'labnav-status',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Beacon status',
  })

  add(
    nav,
    el('div', { class: 'labnav-scroll' }, list),
    select,
    el('div', { class: 'labnav-actions' }, status, resetBtn),
  )
  host.appendChild(nav)

  function renderStatus(): void {
    clear(status)
    const locked = state.items.filter((i) => i.opened === null).length
    add(
      status,
      el('span', { class: 'labnav-round', text: `round ${state.round}` }),
      el('span', { class: 'labnav-sep', 'aria-hidden': 'true', text: '·' }),
      el('span', {
        text: state.beacon.isHalted ? 'beacon halted' : state.running ? 'ticking' : 'paused',
      }),
      el('span', { class: 'labnav-sep', 'aria-hidden': 'true', text: '·' }),
      el('span', { text: `${locked} still locked` }),
    )
  }
  state.subscribe(renderStatus)
  renderStatus()

  // Scroll spy. Purely an affordance — the anchors work without it.
  if ('IntersectionObserver' in window) {
    const visible = new Set<string>()
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) visible.add(entry.target.id)
          else visible.delete(entry.target.id)
        }
        const current = SECTIONS.find((s) => visible.has(s.id))
        for (const [id, a] of links) {
          const isCurrent = current?.id === id
          a.classList.toggle('is-current', isCurrent)
          if (isCurrent) a.setAttribute('aria-current', 'true')
          else a.removeAttribute('aria-current')
        }
        if (current) select.value = current.id
      },
      { rootMargin: '-120px 0px -55% 0px' },
    )
    for (const section of SECTIONS) {
      const node = document.getElementById(section.id)
      if (node) observer.observe(node)
    }
  }
}
