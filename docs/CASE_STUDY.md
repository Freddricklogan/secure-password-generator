# Case Study — Secure Password Generator

**Repository:** [secure-password-generator](https://github.com/Freddricklogan/secure-password-generator) · **Live demo:** [freddricklogan.github.io/secure-password-generator](https://freddricklogan.github.io/secure-password-generator/) · **Author:** Freddrick Logan

---

## 1. Who has this problem

Anyone who publishes a security tool under their own name: the security instructor whose students copy the pattern, the reviewer who reads a "secure" generator and checks whether the sampler is biased, and the person who needs a password now and wants a page that does not send it anywhere. Small security tools are held to a higher standard than small visualizations, because a subtle flaw is invisible to the user.

## 2. The problem, as a scenario

A reviewer opens the generator and reads the source. She finds `crypto.getRandomValues` and rejection sampling — good — and then a signed left shift accumulating bytes, which would pass biased values through the rejection test for any four-byte range. She finds a `Math.random` helper sitting unused beside it. She finds a strength score out of 100 built from entropy times 0.7 plus bonuses for character classes, with no statement of what 100 means. Nothing on the page tells the user how many bits they are getting or at what rate an attacker would need to guess. That was the earlier version of this repository.

## 3. What it costs to leave it alone

A latent bias bug in a generator is the kind of finding that discredits a security portfolio in one sentence, whether or not it was reachable through the interface. A strength label with invented arithmetic teaches users to trust a word rather than a number. And a deprecated copy fallback and an icon font from a CDN add surface to a page whose only job is to keep a secret local.

## 4. The approach, and the alternative I rejected

I rejected expanding into passphrases, breach checks or a password manager. This is a Tier 3 item: keep the options, make the core correct and the claims checkable. `src/generator.js` takes a byte source as an argument — the platform CSPRNG in the page, a fixed sequence in tests — and draws every index through `uniformInt`, which reads whole bytes, accumulates with multiplication rather than a signed shift, and rejects values at or above the largest multiple of the range. Pools are built with exclusions applied, options are validated before generation, guaranteed characters are shuffled into the whole array rather than trimmed, and a conformance check confirms a password uses only the chosen sets and contains each required one. Strength is entropy in bits with the formula and pool size printed; bands are described on the page as this tool's thresholds; guess times are expected values at three named rates with the assumption stated. The icon font and the stock image went; the policy is `default-src 'none'; script-src 'self'`.

## 5. What the code does today

Set a length from 8 to 128; choose lowercase, uppercase, digits and symbols; optionally exclude the ambiguous characters I, l, 1, O and 0 and the punctuation that is easy to misread; require at least one character from each selected set. The page reports problems — no set left after exclusions, a length shorter than the number of required sets — and disables generation until they are fixed. Each generation shows the password, a self-check line, the pool size and set count, entropy in bits, the band with its thresholds printed beside the meter, and expected time to guess at one hundred, ten thousand and one hundred billion guesses per second. Copy uses the clipboard API and says so when it is unavailable.

## 6. Evidence

Seven Vitest tests cover the rejection boundary for a range of ten (bytes 250 to 255 rejected), the two-byte case, the four-byte value 2³² − 1, argument validation, a chi-squared flatness test over 26,000 draws into 26 buckets, pool construction under both exclusions, option validation messages, conformance across sixteen option combinations with twenty draws each, determinism under a fixed byte source, the shuffle, and the entropy, band and duration arithmetic. Statement coverage is 96.42 %. In headless Chrome the defaults produced 16 characters from a 91-character pool at 104.1 bits, lowercase only gave a 26-character pool at 75.2 bits, deselecting every set showed the error and disabled the button, excluding ambiguous characters left an 86-character pool with none of them present, and length 64 reported 411.3 bits, with zero console errors and no horizontal scroll at 1280 or 400 pixels. `AUDIT.md` records seven findings.

## 7. What it would take to run this in production

It already runs where a password generator should: entirely in the user's browser with no network. For an organisation, the additions would be a policy preset that fixes length and sets to the local standard, and a passphrase mode with a published word list — both of which would sit on the same sampler.

## 8. Limits and next steps

Guess rates are illustrative; the true rate depends on the hash and hardware of whoever is attacking. The bands are a convenience, not a standard. There is no passphrase mode and no check against breached-password lists, both of which would be reasonable next steps if the scope were widened.

## 9. Who should look at this

**Hiring manager:** evidence that I read my own security code critically, fix latent bugs and replace unexplained scores with checkable numbers.
**Consulting client:** a small, auditable generator whose every claim is printed with its inputs.
**Engineer:** read `uniformInt` in `src/generator.js` with its boundary tests and the chi-squared test.
