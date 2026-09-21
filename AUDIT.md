# AUDIT — Secure Password Generator (pre-refactor, scope kept)

Tier 3 "keep scope": length, four character sets, two exclusions,
require-all-types, strength indicator and copy. Previous build:
`index.html` (148 lines), `script.js` (470 lines), `style.css`,
Font Awesome 6.0.0 from a CDN, two stock images. The generator was
better than most: it used `crypto.getRandomValues` with rejection
sampling. The findings are at the edges.

---

## A. Randomness

### A1 — Signed shift in the integer sampler
`script.js:108`: `randomValue = (randomValue << 8) + randomBytes[i]`.
JavaScript's `<<` works on signed 32-bit integers, so any four-byte
sample at or above 2³¹ went negative and the rejection test
`randomValue >= maxValidValue` passed it through. Ranges in this tool
never needed four bytes, so the bug was latent. **Fix:** `v = v * 256
+ b` in floating point; a test samples `2³² − 1` through four `0xFF`
bytes.

### A2 — `Math.random` still present
`script.js:91–93`: `getRandomElement` used `Math.random`; unused in
generation, but a trap for the next edit. **Fix:** removed; every
random draw goes through `uniformInt` over the injected byte source.

### A3 — Guaranteed characters trimmed rather than shuffled in
Lines 341–352 pushed one character per set first, filled to length,
then `slice(0, length)`; a later shuffle covered it, but the trim could
drop a guaranteed character when the length was short. **Fix:**
validation rejects a length shorter than the number of selected sets,
and the shuffle runs over the full array; `conforms()` checks every
generated password in tests across 16 option combinations × 20 draws.

## B. Honesty of the strength indicator

### B1 — A score out of 100 with invented bonuses
`estimatePasswordStrength` mixed `entropy / 100 × 70` with bonuses for
character classes and length, then mapped the result to "Weak" through
"Very Strong". Nothing explained what 100 meant. **Fix:** the page
shows entropy in bits with the formula and the pool size that produced
it; bands are this tool's own thresholds, printed beside the meter and
called that; guess-time estimates are given at three stated rates with
the assumption spelled out.

## C. Dependencies and structure

### C1 — Font Awesome from a CDN for two icons; Unsplash image in
structured data
**Fix:** removed; no external scripts or icon fonts; CSP
`default-src 'none'; script-src 'self'`.

### C2 — Fallback copy via `document.execCommand`
Lines 404–430 fell back to a deprecated API with a hidden textarea.
**Fix:** `navigator.clipboard.writeText`, with a visible instruction to
select and copy when the clipboard is unavailable; the password element
is `user-select: all`.

## D. Engineering

### D1 — No tests, no CI
**Fix:** 7 Vitest tests at 96.42 % statement coverage, including the
rejection boundary, the four-byte case, a chi-squared flatness test
over 26,000 draws, exclusions, conformance across option combinations,
determinism under an injected byte source, and the entropy and
duration arithmetic; ESLint, html-validate, security scan, Pages
deployment.
