<h1 align="center">Secure Password Generator</h1>

<p align="center">
  <em>Cryptographically secure password generation with real entropy measurement — not Math.random().</em>
</p>

<p align="center">
  <a href="https://freddricklogan.github.io/secure-password-generator/"><img src="https://img.shields.io/badge/Live_Demo-Open_App-4361ee?style=for-the-badge&logo=github" alt="Live Demo"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Entropy-CSPRNG-4361ee" alt="CSPRNG">
  <img src="https://img.shields.io/badge/Crypto-Web_Crypto_API-3a0ca3" alt="Web Crypto">
  <img src="https://img.shields.io/badge/JavaScript-Vanilla_ES6-f7df1e?logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License">
</p>

---

## Overview

**Secure Password Generator** creates strong, unpredictable passwords using a **cryptographically
secure random number generator** (`crypto.getRandomValues`) rather than the biased, predictable
`Math.random()` most generators quietly rely on. Every generated password comes with a real
**entropy** estimate so you can reason about strength in bits, not vague “weak/strong” labels.

The distinction matters: password security is fundamentally about randomness quality, and this project
is built to get that detail right — the kind of thing that separates a security-aware engineer from a
tutorial follower.

> **▶ [Launch the live demo](https://freddricklogan.github.io/secure-password-generator/)**

---

## Why this project

| Skill demonstrated | Where it shows up |
|:--|:--|
| **Security fundamentals** | CSPRNG via `crypto.getRandomValues` instead of `Math.random()` |
| **Information theory** | Live entropy (bits) computed from character set and length |
| **Threat awareness** | Strength framed against brute-force / guessing resistance |
| **UX for security** | Clear, immediate feedback and sensible defaults |
| **Front-end engineering** | Dependency-free, responsive interface |

---

## Features

- **CSPRNG-based** generation for genuine unpredictability
- Configurable length and character sets (upper, lower, digits, symbols)
- Live **entropy / strength** meter in bits
- One-click copy
- Fully client-side — passwords never leave the browser

---

## Tech stack

- **Language:** Vanilla JavaScript (ES6+)
- **Randomness:** Web Crypto API (`crypto.getRandomValues`)
- **Runtime:** 100% client-side — no backend, no install

---

## Run locally

```bash
git clone https://github.com/Freddricklogan/secure-password-generator.git
cd secure-password-generator
python3 -m http.server 8000
# then visit http://localhost:8000
```

---

## Author

**Freddrick Logan** — Educational Technologist & Technology Leader
[GitHub](https://github.com/Freddricklogan) · [LinkedIn](https://www.linkedin.com/in/freddricklogan/)

## License

Released under the [MIT License](LICENSE).
