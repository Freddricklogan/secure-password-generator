/** Binds the generator to the page. Scope kept from the original: length, four sets, exclusions, require-all-types, strength, copy. */
import { mountExecShell } from './exec-shell.js';
import { band, BANDS, buildPools, conforms, entropyBits, expectedSeconds, generate, humanDuration, validateOptions } from './generator.js';
import { $, el, setText } from './ui.js';

const RATES = [['online, throttled', 100], ['online, unthrottled', 1e4], ['offline, fast hash (GPU rig)', 1e11]];
let last = '';

function options() {
  return { length: Number($('password-length').value), lowercase: $('include-lowercase').checked, uppercase: $('include-uppercase').checked, numeric: $('include-numeric').checked, special: $('include-special').checked, excludeAmbiguous: $('exclude-ambiguous').checked, excludeSimilar: $('exclude-similar').checked, requireAllTypes: $('require-all-types').checked };
}

function renderStrength(opts) {
  const { all, pools } = buildPools(opts);
  const bits = entropyBits(opts.length, all.length);
  setText('pool', `${all.length} characters across ${Object.keys(pools).length} set${Object.keys(pools).length === 1 ? '' : 's'}`);
  setText('bits', `${bits.toFixed(1)} bits`);
  const label = band(bits);
  setText('strength-text', label);
  const meter = $('strength-meter');
  meter.value = Math.min(128, bits);
  meter.className = `meter band-${label.toLowerCase().replace(' ', '-')}`;
  const list = $('times');
  list.replaceChildren(...RATES.map(([name, rate]) => el('li', { text: `${name} (${rate.toExponential(0).replace('e+', '×10^')} guesses/s): ${humanDuration(expectedSeconds(bits, rate))}` })));
}

function run() {
  const opts = options();
  const problems = validateOptions(opts);
  setText('error-message', problems.join(' · '));
  $('error-message').hidden = problems.length === 0;
  $('generate').disabled = problems.length > 0;
  if (problems.length) { setText('password', '—'); return; }
  renderStrength(opts);
  last = generate(opts);
  setText('password', last);
  setText('self-check', conforms(last, opts) ? 'Self-check: the password uses only the chosen sets and, when required, at least one character from each.' : 'Self-check failed — please report this.');
}

async function copy() {
  if (!last) return;
  try { await navigator.clipboard.writeText(last); setText('copy-status', 'Copied to clipboard.'); } catch { setText('copy-status', 'Clipboard unavailable — select the password and copy it.'); }
  setTimeout(() => setText('copy-status', ''), 2500);
}

function boot() {
  $('generate').addEventListener('click', run);
  $('copy').addEventListener('click', copy);
  $('password-length').addEventListener('input', () => { setText('length-value', $('password-length').value); const o = options(); const p = validateOptions(o); if (!p.length) renderStrength(o); });
  for (const id of ['include-lowercase', 'include-uppercase', 'include-numeric', 'include-special', 'exclude-ambiguous', 'exclude-similar', 'require-all-types']) $(id).addEventListener('change', run);
  setText('bands', BANDS.slice().reverse().map(([min, label]) => `${label} ≥ ${min}`).join(' · '));
  run();
  const shell = mountExecShell({
    title: 'Secure Password Generator',
    tagline: 'Passwords from the platform CSPRNG with rejection sampling so no character is favoured, entropy stated in bits with the pool that produced it, and guess-time estimates at three stated rates. Nothing leaves the page.',
    repo: 'https://github.com/Freddricklogan/secure-password-generator',
    pagesUrl: 'https://freddricklogan.github.io/secure-password-generator/',
    badges: [{ label: 'crypto.getRandomValues', tone: 'accent' }, { label: 'No dependencies', dot: true }, { label: 'Scope kept', dot: true }],
    kpis: [
      { label: 'Length', compute: () => $('password-length').value, tone: 'accent' },
      { label: 'Pool', compute: () => $('pool').textContent.split(' ')[0] },
      { label: 'Entropy', compute: () => $('bits').textContent, tone: 'ok' },
      { label: 'Band', compute: () => $('strength-text').textContent, tone: 'warn' }
    ],
    tour: [
      { selector: '#password', title: 'Uniform, not modulo-biased', body: 'Each character index comes from whole random bytes with values above the unbiased limit rejected. A chi-squared test over 26,000 draws is in the test suite.' },
      { selector: '#strength', title: 'Entropy you can check', body: 'Bits = length × log2(pool size), with the pool size shown. The bands are this tool\'s own thresholds, printed beside the meter, not a standard.', action: () => { $('password-length').value = '12'; $('password-length').dispatchEvent(new Event('input')); run(); } },
      { selector: '#times', title: 'Time at a stated rate', body: 'Expected time to guess at three rates the page names, assuming the attacker knows the pool and length and finds the password halfway through the space on average.', action: () => { $('password-length').value = '20'; $('password-length').dispatchEvent(new Event('input')); run(); } }
    ]
  });
  shell.refreshKpis();
  $('generate').addEventListener('click', () => shell.refreshKpis());
  $('password-length').addEventListener('input', () => shell.refreshKpis());
}

boot();
