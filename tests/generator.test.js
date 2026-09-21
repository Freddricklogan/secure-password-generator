import { describe, expect, it } from 'vitest';
import { AMBIGUOUS, band, buildPools, conforms, cryptoBytes, entropyBits, expectedSeconds, generate, humanDuration, SETS, shuffle, SIMILAR, uniformInt, validateOptions } from '../src/generator.js';

const seq = (values) => { let i = 0; return (n) => Uint8Array.from({ length: n }, () => values[i++ % values.length]); };
const base = { length: 16, lowercase: true, uppercase: true, numeric: true, special: true, excludeAmbiguous: false, excludeSimilar: false, requireAllTypes: true };

describe('uniformInt', () => {
  it('rejects bytes at or above the unbiased limit and maps the rest with modulo', () => {
    // n = 10: limit = 256 - 6 = 250; bytes 250..255 are rejected
    expect(uniformInt(10, seq([250, 255, 7]))).toBe(7);
    expect(uniformInt(10, seq([249]))).toBe(9);
    expect(uniformInt(1, seq([0]))).toBe(0);
  });
  it('uses two bytes for n > 256 and unsigned arithmetic for n near 2^32', () => {
    expect(uniformInt(300, seq([1, 44]))).toBe(0);
    expect(uniformInt(300, seq([1, 45]))).toBe(1);
    expect(uniformInt(2 ** 32, seq([255, 255, 255, 255]))).toBe(2 ** 32 - 1);
    expect(() => uniformInt(0)).toThrow(RangeError);
    expect(() => uniformInt(2.5)).toThrow(RangeError);
  });
  it('is statistically flat over the CSPRNG (chi-squared on 26 buckets)', () => {
    const counts = new Array(26).fill(0);
    const N = 26000;
    for (let i = 0; i < N; i += 1) counts[uniformInt(26)] += 1;
    const expected = N / 26;
    const chi2 = counts.reduce((s, c) => s + ((c - expected) ** 2) / expected, 0);
    expect(chi2).toBeLessThan(52); // 25 degrees of freedom; 52 is above the 99.9th percentile (≈ 52.6 at 0.999)
    expect(cryptoBytes(3)).toHaveLength(3);
  });
});

describe('pools and options', () => {
  it('applies exclusions and reports empty pools', () => {
    const { pools, all } = buildPools({ ...base, excludeAmbiguous: true, excludeSimilar: true });
    for (const c of AMBIGUOUS) expect(all.includes(c)).toBe(false);
    for (const c of SIMILAR) expect(all.includes(c)).toBe(false);
    expect(pools.lowercase).toBe('abcdefghijkmnopqrstuvwxyz');
    expect(pools.numeric).toBe('23456789');
    expect(buildPools({ ...base, lowercase: false, uppercase: false, numeric: false }).all).toBe(SETS.special);
    expect(validateOptions({ ...base, lowercase: false, uppercase: false, numeric: false, special: false })).toEqual(['Choose at least one character set (after exclusions, none remains)']);
    expect(validateOptions({ ...base, length: 7 })).toEqual(['Length must be a whole number from 8 to 128']);
    expect(validateOptions({ ...base, length: 200 })).toHaveLength(1);
    expect(validateOptions(base)).toEqual([]);
  });
});

describe('generate', () => {
  it('produces conforming passwords for many option combinations, with every selected set present when required', () => {
    const combos = [];
    for (const l of [8, 16, 64, 128]) for (const ex of [false, true]) for (const req of [false, true]) combos.push({ ...base, length: l, excludeAmbiguous: ex, excludeSimilar: ex, requireAllTypes: req });
    for (const o of combos) for (let i = 0; i < 20; i += 1) expect(conforms(generate(o), o)).toBe(true);
    const only = { ...base, uppercase: false, numeric: false, special: false, requireAllTypes: true, length: 12 };
    expect(generate(only)).toMatch(/^[a-z]{12}$/);
  });
  it('is deterministic for a fixed byte source and shuffles guaranteed characters away from the front', () => {
    const a = generate(base, seq([3, 9, 27, 81, 5, 200, 1, 77]));
    const b = generate(base, seq([3, 9, 27, 81, 5, 200, 1, 77]));
    expect(a).toBe(b);
    expect(a).toHaveLength(16);
    // With requireAllTypes off, characters come straight from the pool in byte order.
    const c = generate({ ...base, requireAllTypes: false, length: 8 }, seq([0]));
    expect(c).toBe('a'.repeat(8));
    expect(shuffle([1, 2, 3], seq([0]))).toEqual([2, 3, 1]);
    expect(() => generate({ ...base, length: 3 })).toThrow(/Length/);
  });
});

describe('entropy and time', () => {
  it('computes bits, bands and expected durations', () => {
    expect(entropyBits(16, 94)).toBeCloseTo(16 * Math.log2(94), 9);
    expect(entropyBits(10, 1)).toBe(0);
    expect(band(200)).toBe('Very strong');
    expect(band(128)).toBe('Very strong');
    expect(band(100)).toBe('Strong');
    expect(band(70)).toBe('Reasonable');
    expect(band(40)).toBe('Weak');
    expect(band(10)).toBe('Very weak');
    expect(expectedSeconds(10, 1)).toBe(512);
    expect(humanDuration(0.5)).toBe('under a second');
    expect(humanDuration(90)).toBe('1.5 minutes');
    expect(humanDuration(3600 * 5)).toBe('5.0 hours');
    expect(humanDuration(86400 * 400)).toBe('1.1 year');
    expect(humanDuration(86400 * 600)).toBe('1.6 years');
    expect(humanDuration(31557600 * 12345)).toBe('12,345 years');
    expect(humanDuration(31557600 * 1e20)).toMatch(/e\+20 years$/);
    expect(humanDuration(Infinity)).toBe('beyond calculation');
  });
});
