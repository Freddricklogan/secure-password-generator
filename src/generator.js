/** Password generation over an injected byte source (crypto.getRandomValues in the page, deterministic bytes in tests). */

export const SETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numeric: '0123456789',
  special: '!@#$%^&*()_+~`|}{[]:;?><,./-='
};
export const AMBIGUOUS = 'Il1O0'; // characters readers confuse in print
export const SIMILAR = '{}[]()|\\/\'"`~,;:.<>'; // punctuation that is easy to misread or mistype

/** Default byte source: the platform CSPRNG. */
export function cryptoBytes(n) {
  const a = new Uint8Array(n);
  globalThis.crypto.getRandomValues(a);
  return a;
}

/**
 * Uniform integer in [0, n) by rejection sampling over whole bytes, so no value is favoured.
 * Uses 1–4 bytes and unsigned arithmetic (the original used a signed shift, which breaks above 2^31).
 */
export function uniformInt(n, bytes = cryptoBytes) {
  if (!(Number.isInteger(n) && n > 0 && n <= 2 ** 32)) throw new RangeError('n must be an integer in 1..2^32');
  if (n === 1) return 0;
  const byteLength = Math.ceil(Math.log2(n) / 8);
  const space = 2 ** (8 * byteLength);
  const limit = space - (space % n);
  for (;;) {
    const b = bytes(byteLength);
    let v = 0;
    for (let i = 0; i < byteLength; i += 1) v = v * 256 + b[i];
    if (v < limit) return v % n;
  }
}

/** Builds the character pools for the chosen options; returns { pools: { name: chars }, all } with exclusions applied. */
export function buildPools(opts) {
  const pools = {};
  for (const name of ['lowercase', 'uppercase', 'numeric', 'special']) {
    if (!opts[name]) continue;
    let chars = SETS[name];
    if (opts.excludeAmbiguous) chars = [...chars].filter((c) => !AMBIGUOUS.includes(c)).join('');
    if (opts.excludeSimilar) chars = [...chars].filter((c) => !SIMILAR.includes(c)).join('');
    if (chars.length) pools[name] = chars;
  }
  return { pools, all: Object.values(pools).join('') };
}

export function validateOptions(opts) {
  const p = [];
  if (!(Number.isInteger(opts.length) && opts.length >= 8 && opts.length <= 128)) p.push('Length must be a whole number from 8 to 128');
  const { pools } = buildPools(opts);
  if (Object.keys(pools).length === 0) p.push('Choose at least one character set (after exclusions, none remains)');
  if (opts.requireAllTypes && Number.isInteger(opts.length) && opts.length < Object.keys(pools).length) p.push('Length is too short to include every selected set');
  return p;
}

/** Fisher–Yates with the same uniform source. */
export function shuffle(arr, bytes = cryptoBytes) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = uniformInt(i + 1, bytes);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * Generates a password. With requireAllTypes, one character from each pool is placed first and the whole
 * array is shuffled afterwards, so the guaranteed characters do not sit at predictable positions.
 */
export function generate(opts, bytes = cryptoBytes) {
  const problems = validateOptions(opts);
  if (problems.length) throw new Error(problems.join('; '));
  const { pools, all } = buildPools(opts);
  const chars = [];
  if (opts.requireAllTypes) for (const pool of Object.values(pools)) chars.push(pool[uniformInt(pool.length, bytes)]);
  while (chars.length < opts.length) chars.push(all[uniformInt(all.length, bytes)]);
  return (opts.requireAllTypes ? shuffle(chars, bytes) : chars).join('');
}

/** Entropy in bits for a password drawn uniformly from a pool of `poolSize` characters: length × log2(poolSize). */
export function entropyBits(length, poolSize) {
  return poolSize > 1 ? length * Math.log2(poolSize) : 0;
}

/** Bands used by this tool (not a standard): the boundaries are stated on the page. */
export const BANDS = [[128, 'Very strong'], [80, 'Strong'], [60, 'Reasonable'], [36, 'Weak'], [0, 'Very weak']];
export function band(bits) {
  for (const [min, label] of BANDS) if (bits >= min) return label;
  return 'Very weak';
}

/**
 * Expected time to guess at a stated rate (guesses per second), assuming the attacker knows the pool and length
 * and finds the password halfway through the space on average.
 */
export function expectedSeconds(bits, guessesPerSecond) {
  return 2 ** bits / 2 / guessesPerSecond;
}

export function humanDuration(seconds) {
  if (!Number.isFinite(seconds)) return 'beyond calculation';
  if (seconds < 1) return 'under a second';
  const units = [['year', 31557600], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
  for (const [name, span] of units) {
    if (seconds >= span) {
      const n = seconds / span;
      if (n >= 1e15) return `${n.toExponential(2)} ${name}s`;
      return `${n >= 100 ? Math.round(n).toLocaleString() : n.toFixed(n >= 10 ? 0 : 1)} ${name}${n >= 1.5 ? 's' : ''}`;
    }
  }
  return 'under a second';
}

/** Checks a generated password against the options that produced it (used by tests and by the page's self-check). */
export function conforms(password, opts) {
  const { pools, all } = buildPools(opts);
  if (password.length !== opts.length) return false;
  if (![...password].every((c) => all.includes(c))) return false;
  if (opts.requireAllTypes) for (const pool of Object.values(pools)) if (![...password].some((c) => pool.includes(c))) return false;
  return true;
}
