/**
 * Three ways to delay a secret, compared under an adversary you control.
 *
 * The chart answers one question: as the adversary's hardware gets faster,
 * when can they read it? Compute-bound delay slides down a 45° line — buy a
 * thousand times the silicon, wait a thousandth as long. Event-bound delay is
 * a flat line, because there is nothing to buy.
 *
 * Puzzle and VDF share that descending line exactly, and the chart says so
 * rather than nudging them apart for legibility: the VDF's contribution is not
 * a longer delay, it is that checking somebody else's answer stops costing you
 * the delay. That axis lives in the table, where it belongs.
 *
 * The 1× reference rate is measured in this browser — real BigInt squarings on
 * a real 2048-bit modulus — so the numbers are this machine's numbers. The
 * multiplier is labelled as an assumption, because it is one.
 */

import { formatCount, formatDuration, evaluateAll, type Scenario } from '../core/models'
import {
  add,
  button,
  clear,
  el,
  expert,
  honesty,
  labelledSelect,
  panel,
  stat,
  svg,
} from './dom'
import { state } from './state'

const DELAYS = [
  { value: '3600', text: '1 hour' },
  { value: '86400', text: '1 day' },
  { value: '2592000', text: '30 days' },
  { value: '31557600', text: '1 year' },
]

const PARTIES = [
  { value: '1', text: '1 — a single recipient' },
  { value: '25', text: '25 — a bidding round' },
  { value: '1000', text: '1000 — a public release' },
]

const SERIES: Record<string, { label: string; dash: string; cls: string }> = {
  puzzle: { label: 'Time-lock puzzle', dash: '', cls: 'series-puzzle' },
  // Long dashes, not short ones: puzzle and VDF share a line exactly, so the
  // dash has to be readable as "the same path, two owners" rather than blur
  // into a single ambiguous colour.
  vdf: { label: 'VDF', dash: '16 16', cls: 'series-vdf' },
  beacon: { label: 'Beacon timelock', dash: '', cls: 'series-beacon' },
}

const W = 760
const H = 330
const M = { top: 18, right: 118, bottom: 46, left: 98 }

export function mountCompare(host: HTMLElement): void {
  const section = panel(
    'compare',
    'Three models under a faster adversary',
    'Turn the adversary’s hardware up and watch which of the three delays survives it.',
  )

  const delay = labelledSelect('cmp-delay', 'Delay the designer wants', DELAYS)
  delay.select.value = '86400'
  const parties = labelledSelect('cmp-parties', 'People who want the secret', PARTIES)

  const speed = el('input', {
    type: 'range',
    id: 'cmp-speed',
    min: '0',
    max: '6',
    step: '0.25',
    value: '0',
  })
  const speedOut = el('output', { class: 'ctl-readout', for: 'cmp-speed' })

  const figure = el('figure', { class: 'chart-figure' })
  const caption = el('figcaption', { class: 'chart-caption' })
  // `.chart` carries `min-width: 34rem`, so `.chart-host` is a horizontal
  // scroller on any viewport under ~544px — which is every phone. It holds no
  // focusable content (the chart is one `role="img"` <svg>), so without a
  // tabindex there is no keyboard route to the scrolled-off half of it at all:
  // WCAG 2.1.1, flagged by axe as `scrollable-region-focusable` and by the
  // gate's own scroller oracle, in every single state at 380px. A focus target
  // needs a name, and `role="group"` is what makes naming it legal.
  const chartHost = el('div', {
    class: 'chart-host',
    tabindex: '0',
    role: 'group',
    'aria-label': 'Open-time chart, scrollable sideways',
  })
  add(figure, chartHost, caption)

  const legend = el('ul', { class: 'legend', role: 'list' })
  const tableHost = el('div', { class: 'tablewrap', tabindex: '0', role: 'region', 'aria-label': 'Model comparison table' })
  const summary = el('p', {
    class: 'compare-summary',
    role: 'status',
    'aria-live': 'polite',
    'aria-label': 'Comparison summary',
  })
  const calStats = el('div', { class: 'statrow' })

  const resetSpeed = button('Back to 1×', () => {
    speed.value = '0'
    render()
  }, 'btn-quiet btn-small')

  add(
    section,
    el(
      'div',
      { class: 'controls' },
      delay.wrap,
      parties.wrap,
      el(
        'div',
        { class: 'ctl ctl-range ctl-wide' },
        el('label', { class: 'ctl-label', for: 'cmp-speed', text: 'Adversary hardware' }),
        speed,
        speedOut,
      ),
      resetSpeed,
    ),
    summary,
    legend,
    figure,
    el('h3', { text: 'The same three models, on the axes a chart cannot carry' }),
    tableHost,
    calStats,
    honesty(
      'The 1× rate is measured live in this tab and is deliberately unimpressive — BigInt is not a competitive squaring implementation. That is why the x axis is a multiplier rather than a claim: a tuned ASIC is somewhere in the 10⁴–10⁶ range against this baseline, and you are invited to disagree with that estimate by moving the slider. ',
      'What is not an estimate is the shape: two of these curves are proportional to 1 / hardware and one of them is constant.',
    ),
    expert(
      'What the VDF row is actually for',
      el('p', {
        text: 'A VDF does not delay an adversary any longer than a time-lock puzzle does — the two open-time curves here are the same curve. What it adds is a short proof, so the delay is paid once by the world instead of once per interested party, and so a claimed answer can be checked without redoing the work. That is why the "cost to check someone else’s answer" column, not the chart, is where the VDF earns its place.',
      }),
      el('p', {
        text: 'Both compute-bound models also assume sequentiality: adding cores does not help, only a faster clock does. That assumption is doing real work, and it is why the community moved from "repeated squaring in an RSA group" toward class groups, where no trapdoor exists to be leaked.',
      }),
    ),
  )
  host.appendChild(section)

  function scenario(): Scenario {
    return {
      targetDelaySeconds: Number(delay.select.value),
      adversarySpeedup: 10 ** Number(speed.value),
      parties: Number(parties.select.value),
      beaconAlive: !state.beacon.isHalted,
    }
  }

  function renderLegend(alive: boolean): void {
    clear(legend)
    for (const [id, meta] of Object.entries(SERIES)) {
      const swatch = svg('svg', { class: 'legend-swatch', viewBox: '0 0 24 12', 'aria-hidden': 'true' })
      swatch.appendChild(
        svg('line', {
          x1: '1',
          y1: '6',
          x2: '23',
          y2: '6',
          class: `line ${meta.cls}`,
          'stroke-dasharray': meta.dash || undefined,
        }),
      )
      const dead = id === 'beacon' && !alive
      legend.appendChild(
        el(
          'li',
          { class: 'legend-item', role: 'listitem' },
          swatch,
          el('span', { text: meta.label }),
          dead ? el('span', { class: 'legend-note', text: '— halted, never opens' }) : null,
          id === 'vdf' ? el('span', { class: 'legend-note', text: '— dashed, on the puzzle’s line' }) : null,
        ),
      )
    }
  }

  function render(): void {
    const s = scenario()
    const cal = state.calibrate()
    const outcomes = evaluateAll(s, cal)
    const multiplier = s.adversarySpeedup

    speedOut.textContent =
      multiplier < 1.05
        ? '1× — the same machine you are reading this on'
        : `${formatCount(multiplier)}× faster than this browser`

    renderLegend(s.beaconAlive)
    renderChart(s, cal.squaringsPerSecond)
    renderTable(outcomes, s)

    const puzzle = outcomes[0]!
    const beacon = outcomes[2]!
    clear(summary)
    add(
      summary,
      el('span', { class: 'summary-icon', 'aria-hidden': 'true', text: '→ ' }),
      el('strong', {
        text: `At ${formatCount(multiplier)}× hardware, the puzzle opens in ${formatDuration(puzzle.earliestOpenSeconds)}. `,
      }),
      el('span', {
        text: s.beaconAlive
          ? `The beacon lock opens in ${formatDuration(beacon.earliestOpenSeconds)} — the same answer it gives at 1×, and at a million×.`
          : 'The beacon lock never opens: you halted the beacon in the exhibit above, and its ciphertexts are stranded.',
      }),
    )

    clear(calStats)
    add(
      calStats,
      stat('Measured 1× rate', `${formatCount(cal.squaringsPerSecond)} squarings/s`),
      stat('Modulus', `${cal.modulusBits} bits`),
      stat('Sampled over', `${cal.sampleMillis} ms`),
      stat('T for this delay', `${formatCount(puzzle.sequentialSquarings)} squarings`),
    )
  }

  function renderChart(s: Scenario, _rate: number): void {
    clear(chartHost)
    const D = s.targetDelaySeconds
    const xMax = 6 // log10 hardware multiplier
    const yTop = Math.log10(D * 4)
    const yBottom = Math.log10(D / 10 ** xMax / 4)

    const px = (logX: number) => M.left + (logX / xMax) * (W - M.left - M.right)
    const py = (logY: number) =>
      M.top + ((yTop - logY) / (yTop - yBottom)) * (H - M.top - M.bottom)

    const root = svg('svg', {
      class: 'chart',
      viewBox: `0 0 ${W} ${H}`,
      role: 'img',
      'aria-label': `Time until the secret can be read, against adversary hardware from 1× to one million×. The time-lock puzzle and the verifiable delay function fall in exact proportion to hardware, from ${formatDuration(D)} down to ${formatDuration(D / 10 ** xMax)}. The beacon timelock stays at ${s.beaconAlive ? formatDuration(D) : 'never'} across the whole range.`,
    })

    // ---- grid + axes ----
    for (let d = Math.ceil(yBottom); d <= Math.floor(yTop); d++) {
      const y = py(d)
      root.appendChild(svg('line', { class: 'grid', x1: M.left, y1: y, x2: W - M.right, y2: y }))
      root.appendChild(
        svg('text', {
          class: 'axis-label',
          x: M.left - 8,
          y: y + 4,
          'text-anchor': 'end',
          text: formatDuration(10 ** d),
        }),
      )
    }
    for (let d = 0; d <= xMax; d++) {
      const x = px(d)
      root.appendChild(
        svg('line', { class: 'grid grid-faint', x1: x, y1: M.top, x2: x, y2: H - M.bottom }),
      )
      root.appendChild(
        svg('text', {
          class: 'axis-label',
          x,
          y: H - M.bottom + 18,
          'text-anchor': 'middle',
          text: d === 0 ? '1×' : `10${superscript(d)}×`,
        }),
      )
    }
    root.appendChild(
      svg('text', {
        class: 'axis-title',
        x: M.left + (W - M.left - M.right) / 2,
        y: H - 6,
        'text-anchor': 'middle',
        text: 'Adversary hardware, relative to this browser',
      }),
    )
    root.appendChild(
      svg('text', {
        class: 'axis-title',
        x: 14,
        y: M.top + (H - M.top - M.bottom) / 2,
        'text-anchor': 'middle',
        transform: `rotate(-90 14 ${M.top + (H - M.top - M.bottom) / 2})`,
        text: 'Time until it can be read',
      }),
    )

    // ---- the compute-bound line: y = D / k, i.e. log y = log D - log k ----
    const computePath = `M ${px(0)} ${py(Math.log10(D))} L ${px(xMax)} ${py(Math.log10(D) - xMax)}`
    root.appendChild(
      svg('path', { class: 'line line-thick series-puzzle', d: computePath, fill: 'none' }),
    )
    root.appendChild(
      svg('path', {
        class: 'line line-thick series-vdf',
        d: computePath,
        fill: 'none',
        'stroke-dasharray': SERIES.vdf!.dash,
      }),
    )

    // ---- the event-bound line: flat, or absent ----
    if (s.beaconAlive) {
      root.appendChild(
        svg('path', {
          class: 'line series-beacon',
          fill: 'none',
          d: `M ${px(0)} ${py(Math.log10(D))} L ${px(xMax)} ${py(Math.log10(D))}`,
        }),
      )
    } else {
      root.appendChild(
        svg('path', {
          class: 'line series-beacon line-dead',
          fill: 'none',
          'stroke-dasharray': '3 6',
          d: `M ${px(0)} ${M.top + 8} L ${px(xMax)} ${M.top + 8}`,
        }),
      )
    }

    // ---- the slider's position, as a readable marker ----
    const k = Math.log10(s.adversarySpeedup)
    root.appendChild(
      svg('line', { class: 'marker', x1: px(k), y1: M.top, x2: px(k), y2: H - M.bottom }),
    )
    const computeY = py(Math.log10(D) - k)
    root.appendChild(svg('circle', { class: 'dot series-puzzle-fill', cx: px(k), cy: computeY, r: 5 }))
    if (s.beaconAlive) {
      root.appendChild(
        svg('circle', {
          class: 'dot series-beacon-fill',
          cx: px(k),
          cy: py(Math.log10(D)),
          r: 5,
        }),
      )
    }

    // ---- direct labels, so identity is never colour-alone ----
    root.appendChild(
      svg('text', {
        class: 'series-label series-puzzle-text',
        x: W - M.right + 10,
        y: py(Math.log10(D) - xMax) + 4,
        text: 'puzzle / VDF',
      }),
    )
    root.appendChild(
      svg('text', {
        class: 'series-label series-beacon-text',
        x: W - M.right + 10,
        y: (s.beaconAlive ? py(Math.log10(D)) : M.top + 8) + 4,
        text: s.beaconAlive ? 'beacon' : 'beacon: never',
      }),
    )

    chartHost.appendChild(root)
    caption.textContent = s.beaconAlive
      ? `Log–log. The puzzle and VDF lines are the same line: both are ${formatDuration(D)} divided by hardware. The beacon line is flat because there is no work for hardware to accelerate.`
      : `Log–log. With the beacon halted there is no beacon curve to draw — its ciphertexts do not open late, they do not open.`
  }

  function renderTable(outcomes: ReturnType<typeof evaluateAll>, s: Scenario): void {
    clear(tableHost)
    const table = el('table', { class: 'datatable' })
    const head = el('tr', {}, el('th', { scope: 'col', text: '' }))
    for (const o of outcomes) {
      head.appendChild(
        el(
          'th',
          { scope: 'col', class: `col-${o.model.id}` },
          el('span', { class: `colmark colmark-${o.model.id}`, 'aria-hidden': 'true' }),
          o.model.name,
        ),
      )
    }
    table.appendChild(el('thead', {}, head))

    const rows: Array<[string, (o: (typeof outcomes)[number]) => string]> = [
      ['Opens after', (o) => formatDuration(o.earliestOpenSeconds)],
      ['Sequential work on the critical path', (o) => `${formatCount(o.sequentialSquarings)} squarings`],
      [`Work burned across ${s.parties} interested part${s.parties === 1 ? 'y' : 'ies'}`, (o) => `${formatCount(o.totalSquarings)} squarings`],
      ['Cost to check someone else’s answer', (o) => `${formatCount(o.verifySquarings)} squarings`],
      ['Needs a third party', (o) => (o.model.needsThirdParty ? '✗ yes' : '✓ no')],
      ['Still opens if that party vanishes', (o) => (o.model.survivesOutage ? '✓ yes' : '✗ no')],
      ['How the delay is enforced', (o) => o.model.mechanism],
    ]

    const body = el('tbody')
    for (const [label, cell] of rows) {
      const tr = el('tr', {}, el('th', { scope: 'row', text: label }))
      for (const o of outcomes) tr.appendChild(el('td', { text: cell(o) }))
      body.appendChild(tr)
    }
    table.appendChild(body)
    tableHost.appendChild(table)
  }

  delay.select.addEventListener('change', render)
  parties.select.addEventListener('change', render)
  speed.addEventListener('input', render)
  state.subscribe(render)
  render()
}

function superscript(n: number): string {
  const map = ['⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹']
  return String(n)
    .split('')
    .map((d) => map[Number(d)] ?? d)
    .join('')
}
