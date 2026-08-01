import './styles.css'
import { mountNav } from './ui/nav'
import { mountIntro } from './ui/intro'
import { mountLock } from './ui/lock'
import { mountClock } from './ui/clock'
import { mountMechanism } from './ui/mechanism'
import { mountCompare } from './ui/compare'
import { mountOutage } from './ui/outage'
import { mountAttack } from './ui/attack'
import { mountScope } from './ui/scope'
import { state } from './ui/state'

/**
 * Order follows the story, not the mathematics: the idea, then the thing you
 * came to do, then the clock that makes it work, then the algebra underneath,
 * then how it compares, then how it fails, then how it resists you, then the
 * honest boundary.
 */
const exhibits = document.getElementById('exhibits')
const navHost = document.getElementById('labnav')

if (exhibits) {
  mountIntro(exhibits)
  mountLock(exhibits)
  mountClock(exhibits)
  mountMechanism(exhibits)
  mountCompare(exhibits)
  mountOutage(exhibits)
  mountAttack(exhibits)
  mountScope(exhibits)
}

// Mounted last: the scroll spy needs every exhibit to exist in the DOM.
if (navHost) mountNav(navHost)

// The beacon starts at round 1 and runs, so the page is live on arrival. The
// clock exhibit owns pausing it.
state.beacon.advanceTo(1)
state.start()
