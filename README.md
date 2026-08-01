# Beacon Lock

**Timelock encryption · drand beacon · IBE-based release**

Beacon-based timelock encryption where a ciphertext is locked to a future round of a public
randomness beacon — when the beacon publishes that round's signature, it becomes the decryption
key. Nobody grinds, everybody waits.

**[Open the live demo →](https://systemslibrarian.github.io/crypto-lab-beacon-lock/)**

---

## What It Is

There are three ways to make a secret unreadable until later. You can make one person grind
through a pile of sequential computation (a **time-lock puzzle**, Rivest–Shamir–Wagner 1996). You
can make that grind checkable so the world only pays for it once (a **verifiable delay function**,
Boneh–Bonneau–Bünz–Fisch 2018). Or you can make nobody grind at all, and have everyone wait for a
public event that is going to happen anyway.

This demo builds the third one, and the surprise is that it is **identity-based encryption in
disguise**. In Boneh–Franklin IBE you encrypt to an arbitrary identity string, and an authority
holding a master secret extracts that identity's private key. Point the identity at a *future
beacon round* instead of at a person and the authority becomes a clock:

| IBE | Beacon timelock |
|---|---|
| master public key `P_pub` | the beacon's group public key |
| identity `ID` | `SHA-256(uint64_be(round))` |
| key extraction `d_ID` | the beacon's BLS signature on that round |
| private key generator | the League of Entropy, on a three-second timer |

The "IBE private key" for round *n* is literally the 48 bytes drand publishes for round *n* —
the same bytes anyone can download for any other reason. Correctness is one line of bilinearity:

```
sender    computes   e(Q_ID, P_pub)^r  =  e(Q_ID, G₂)^(s·r)
receiver  computes   e(σ_ID, U)        =  e(s·Q_ID, r·G₂)  =  e(Q_ID, G₂)^(s·r)
```

Two parties, no shared secret, no interaction after the ciphertext — and the receiver's half is
unavailable until the beacon ticks.

**Primitives.** Boneh–Franklin **FullIdent** IBE (CRYPTO 2001 §4.2) — BasicIdent plus the
Fujisaki–Okamoto transform, so a wrong key is *detected* rather than silently producing garbage.
BLS12-381 pairings via `@noble/curves`. RFC 9380 hash-to-curve for H₁. AES-256-GCM (WebCrypto)
for the hybrid envelope. Beacon layout follows drand **quicknet**
(`bls-unchained-g1-rfc9380`): signatures in G1, public keys in G2.

**Byte-compatible with drand `tlock`.** The IBE is kyber's `EncryptCCAonG2` reimplemented
exactly — same `IBE-H2`/`IBE-H3`/`IBE-H4` tags, same SHA-256 truncation, same little-endian
counter in the H₃ rejection loop, and the same Fp12 serialization (kyber orders the twelve
48-byte limbs in reverse relative to noble). That is **proven, not claimed**: the test suite
opens a real ciphertext from drand's own `tlock` test corpus and recovers the exact key the Go
implementation locked. See [Build & Verify](#build--verify).

**Security model.** Confidentiality reduces to computational Diffie–Hellman in G1 on BLS12-381
(~126 bits conjectured, after the 2016 exTNFS improvements). On top of that sit two assumptions
that are *not* mathematical: the beacon stays **live** until the target round, and a threshold of
its operators do not **sign early in private**. Both are stated on the page, and one of them has
its own exhibit.

**Not production cryptography.** A teaching demo. Nothing here is audited, none of it is
constant-time, and no key material on the page should protect anything you care about.

---

## Exhibits

1. **Send a message to the future** — the plain-language on-ramp, with the three delay strategies
   side by side and a glossary for every term the page later assumes.
2. **Lock a secret to a future round** — the core interaction. Type a message, choose how far
   ahead to lock it, watch the beacon walk toward the round. Two buttons per ciphertext: the
   honest one, which reports that no key exists yet, and *Force it with the latest signature*,
   which feeds a genuine but wrong-round beacon signature to the real decryptor and gets a real
   rejection back.
3. **The beacon** — the clock, running. Verify any published round and see **both halves** of
   `e(σ, G₂) = e(H₁(m), P_pub)` computed from disjoint inputs and printed as two 576-byte GT
   elements. Switch the chain from unchained to chained and watch the "identity for round *n*+20"
   readout stop existing — the reason drand had to ship an unchained network before timelock
   encryption was possible at all.
4. **The mechanism, one step at a time** — eight steps from "name a future round" to "the
   plaintext is on screen", with a who-can-open-it-early ledger in the middle. Step 7 prints the
   sender's `e(Q, P_pub)^r` and the receiver's `e(σ, U)` and compares all 1152 hex digits. That
   comparison is what the demo exists for. The panel closes with **"Does this match the real
   thing?"** — a live decryption, in your browser, of a ciphertext produced by drand's reference
   Go implementation.
5. **Three models under a faster adversary** — a slider for the adversary's hardware, from 1× to
   10⁶×, against a squaring rate **measured live in your browser**. The puzzle and VDF curves
   fall in exact proportion; the beacon line is flat. A table carries the axes a chart cannot:
   work burned across *N* interested parties, and the cost of checking someone else's answer.
6. **What if the beacon dies?** — halt the beacon and the ciphertexts you locked upstairs become
   permanently unopenable, listed by name. Not "computationally infeasible" — absent.
7. **Break it yourself** — nine attacks against the same `decrypt()` the rest of the page uses:
   a genuine wrong-round signature, a forged G1 point, the identity element, single bit flips in
   V and W, a substituted U, a relabelled round, an edited AEAD payload, and the beacon operator
   signing early. Eight are refused, and the ninth is coloured as an **alarm** even though it
   returns a plaintext.
8. **Scope, and what this does not prove** — the exact real/simulated boundary, row by row.

---

## When to Use It

**Reach for beacon timelock when:**

- The unlock moment is a **wall-clock time**, not a puzzle budget — sealed-bid auctions,
  embargoed disclosures, coordinated vulnerability release, a will that opens on a date.
- **Many parties must open simultaneously.** One 48-byte publication unlocks every ciphertext
  addressed to that round, for everyone, at the same instant.
- You cannot tolerate a **custodian**. There is no escrow to subpoena, breach or bribe, because
  nobody holds the key before it is published to the world.
- You need the delay to be **immune to money.** An adversary with a warehouse of ASICs opens at
  exactly the same second as everyone else.

**Do NOT use it when:**

- **You cannot accept a liveness dependency.** If the beacon stops, your plaintext is gone. Use a
  time-lock puzzle or a VDF, where enough electricity always eventually wins.
- **Your horizon is decades.** This is a bet on both BLS12-381 and an organisation, for the whole
  period. It is also not post-quantum: a large quantum computer recovers the beacon's secret from
  its published key and opens every ciphertext ever locked to that chain, retroactively.
- **You need a release condition that is not time.** "When somebody proves X" is witness
  encryption, a different and much less practical primitive. This releases on a publication event
  and on nothing else.
- **You want a drop-in `.tle` tool.** The IBE layer here interoperates, but this repo does not
  implement the age container around it. Use drand's `tlock` for real files.
- **You need the beacon operator to be unable to cheat.** They can always extract early. drand's
  answer is a threshold key across ~20 organisations; if that is not enough for your threat
  model, no parameter choice fixes it.

---

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-beacon-lock/>**

Lock a message eight rounds out and try to open it immediately — you will be told there is
nothing to decrypt with, because there is not. Then force it with the latest genuine signature
and watch the real decryptor reject it. Let the clock reach the round and open it properly. Then
go to the comparison exhibit, drag the adversary's hardware to a million times your browser, and
notice which of the three lines has not moved. Then halt the beacon and see what it costs.

Everything runs in the browser. No backend, no network requests, no key material persisted.

---

## What Can Go Wrong

| Failure | What happens here |
|---|---|
| **Beacon stops** | Every ciphertext past the last published round is permanently unopenable. Exhibit 6 does this to your own ciphertexts and lists them. |
| **Operator signs early** | The ciphertext opens whenever they like, and nobody can tell. This is the one attack in exhibit 7 that succeeds; it renders as an alarm because the system did not hold. |
| **Wrong round's signature** | The FO check recomputes `r` from what it recovered, rebuilds `r·G₂`, and finds it is not `U`. Rejected, not guessed at. |
| **Any bit flipped in V or W** | `r = H₃(σ, M)` covers both, so a flipped bit invalidates the ciphertext instead of malleating the plaintext. |
| **Ciphertext relabelled with a nearer round** | The identity is derived from the round, so relabelling asks for a different key; separately, the round is the AEAD's associated data, so the GCM tag stops verifying. |
| **Chained beacon** | There is no identity to encrypt to. `roundMessage()` throws rather than inventing a placeholder. |
| **Malformed point offered as a signature** | `assertValidity()` on deserialization rejects off-curve and off-subgroup encodings; the identity element gets no special case and fails the same consistency check. |
| **Missing FO check** *(what a BasicIdent implementation would do)* | Any curve point yields a full-length, plausible, wrong plaintext. There is a test that demonstrates exactly this, so the value of the check is shown rather than asserted. |

---

## Real-World Usage

- **drand `tlock`** — the reference implementation, by Gailly, Melissaris and Romailler. Same
  construction as this page, with an age-compatible file format.
- **drand quicknet** — the League of Entropy chain that made it deployable: unchained, three
  seconds a round, signatures in G1, running since August 2023. The chain hash, group public key
  and four real round signatures in this repo come from it.
- **Sealed-bid auctions and MEV mitigation** — encrypt bids or transactions to a round shortly
  after the ordering is fixed, so nobody can front-run what they cannot read.
- **Coordinated disclosure and embargoes** — publish the ciphertext ahead of the date; the
  embargo is enforced by arithmetic rather than by everyone's good behaviour.
- **Dead-man switches** — no service holding a copy, and no service that can be leaned on.

---

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-beacon-lock.git
cd crypto-lab-beacon-lock
npm install
npm run dev            # http://localhost:5173
```

```bash
npm test               # 119 unit tests, incl. the spec, network and interop KATs
npm run build          # typecheck + production build
npm run test:a11y      # axe WCAG 2.1 A/AA gate, both themes (needs a build first)
```

---

## Related Demos

- [crypto-lab-ibe-gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/) — the same
  Boneh–Franklin scheme with a human identity and a private key generator. This lab is that lab
  with the authority replaced by a timer.
- [crypto-lab-time-lock-puzzle](https://systemslibrarian.github.io/crypto-lab-time-lock-puzzle/) —
  the 1996 answer: make the opener pay.
- [crypto-lab-vdf](https://systemslibrarian.github.io/crypto-lab-vdf/) — the same grind, made
  checkable, so the world pays once.
- [crypto-lab-threshold-decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/) —
  what the League of Entropy is actually doing with that master secret.

---

## Build & Verify

**119 unit tests** (Vitest, colocated as `src/**/*.test.ts`), of which the known-answer tests are:

| KAT | Count | Source | File |
|---|---|---|---|
| `BLS12381G1_XMD:SHA-256_SSWU_RO_` | 5 vectors | RFC 9380 Appendix J.9.1 | `src/core/bls.test.ts` |
| BLS12-381 curve parameters | 7 constants | draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1 | `src/core/bls.test.ts` |
| Real drand quicknet rounds | 4 signatures, 12 assertions | `api.drand.sh`, captured 2026-08-01 | `src/core/beacon.test.ts`, `src/core/tlock.test.ts` |
| **Reference `tlock` ciphertext** | **1 end-to-end decryption** | `drand/tlock` `testdata/`, plus the quicknet-t chain | `src/core/tlock.test.ts` |

All fixtures live in `src/fixtures/kat.json` and are copied verbatim from those sources —
**nothing in that file is computed by this repo.**

**The two load-bearing ones.**

*The beacon.* Four signatures the League of Entropy actually published are verified against
quicknet's real group public key, rejected against neighbouring rounds, and then used to open
timelock ciphertexts addressed to those same real rounds. Passing means the round encoding, the
hash-to-curve DST, the G1/G2 layout and the pairing equation all match the live network.

*The interop.* `INTEROP: decrypts a real ciphertext produced by the drand tlock CLI` takes the
`-> tlock` stanza out of drand's own
`testdata/lorem-tle-testnet-quicknet-t-2024-01-17-15-28.tle`, opens it with the signature the
quicknet-t testnet published for round 5,423,142, and asserts the recovered 16-byte age file key
equals `2088b21b7778175ecb9349dd98737373`. The Fujisaki–Okamoto check is what makes this
decisive: it recomputes `r = H₃(σ, M)` and rebuilds `r·G₂`, so a foreign ciphertext can only pass
if H₂, H₃, H₄ *and* the Fp12 serialization all match kyber byte for byte. A single wrong byte
anywhere makes it a 1-in-2²⁵⁵ accident. The same check runs live in the browser at the end of
exhibit 4.

These are static fixtures: the lab makes **no network requests at runtime**.

**What is still not interoperable:** the age container. This repo implements the identity-based
encryption that `tlock` uses, not age's armor, HKDF or ChaCha20-Poly1305 STREAM, so it cannot
read or write `.tle` files end to end.

**Accessibility gate.** `npm run test:a11y` runs `@axe-core/playwright` against the production
build served by `vite preview`, and asserts **zero WCAG 2.1 A/AA violations in both themes**. Each
theme is scanned twice — once with the healthy states on screen and once with the failure states
(stranded ciphertexts, a halted beacon, a chained chain refusing to address the future, an
early-signed ciphertext), because those use a different palette and different live regions. The
deploy workflow runs unit tests, the typechecked build and this gate before it will publish.

**Chart palette.** The three categorical series were validated per theme against the OKLCH
lightness band, the chroma floor, protan/deutan separation and contrast against that theme's chart
surface. Adjust them with the validator, not by eye.

---

## Performance

Measured on an Apple Silicon laptop, Node 24 (browser figures are comparable):

| Operation | Cost |
|---|---|
| BLS12-381 pairing | ~14 ms |
| Hash-to-G1 (RFC 9380) | ~1.3 ms |
| G2 scalar multiplication | ~0.5 ms |
| Timelock encrypt (1 pairing + 1 GT exponentiation + 1 G2 mul) | ~19 ms |
| Timelock decrypt (1 pairing + 1 G2 mul, plus the FO check) | ~9 ms |
| Ciphertext overhead | 128 bytes (96 B for `U` in G2, 32 B for `V`) + 28 B of AEAD |

Pairings are the expensive part, which is why the timelock covers only a 32-byte AES key and the
payload rides under AES-256-GCM. That cost is fixed no matter how large the message is.

The comparison exhibit's 1× reference rate is measured live in the visitor's browser — real BigInt
squarings on a real 2048-bit modulus, typically around 1.2M/s — so the numbers on screen are that
machine's numbers rather than a quoted figure.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
