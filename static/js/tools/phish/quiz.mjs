/* Phishing Quiz — pure logic (no DOM), unit-tested in tests/unit/phish.test.mjs. */

/** Fisher–Yates with an injectable random source (tests pass a seeded one). */
export function shuffle(list, rand = Math.random) {
  const a = list.slice();
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

/**
 * Draws a round of `n` scenarios: between 30% and 40% legitimate, so "it's all
 * phishing" never wins, with at least three different scenario types.
 */
export function pickRound(pool, n = 10, rand = Math.random) {
  const legitCount = Math.round(n * (0.3 + rand() * 0.1));
  for (let attempt = 0; attempt < 50; attempt++) {
    const legit = shuffle(pool.filter((s) => !s.phish), rand).slice(0, legitCount);
    const phish = shuffle(pool.filter((s) => s.phish), rand).slice(0, n - legit.length);
    const round = shuffle([...legit, ...phish], rand);
    if (new Set(round.map((s) => s.type)).size >= 3) return round;
  }
  return shuffle(pool, rand).slice(0, n);
}

/** Rank key from a score out of 10. */
export function rankFor(score, total = 10) {
  const r = score / total;
  return r >= 0.9 ? 'rank4' : r >= 0.7 ? 'rank3' : r >= 0.4 ? 'rank2' : 'rank1';
}

/** Topics of the missed scenarios, most frequent first (ties keep pool order). */
export function topicsToReview(round, answers) {
  const count = new Map();
  round.forEach((s, i) => {
    if (answers[i] !== s.phish) for (const t of s.topics) count.set(t, (count.get(t) || 0) + 1);
  });
  return [...count.entries()].sort((a, b) => b[1] - a[1]).map(([t]) => t);
}

/** Every host name that appears in a scenario (for the reserved-domain test). */
export function hostsOf(s) {
  const urls = [s.m.href, s.m.url, s.m.qr].filter(Boolean);
  const hosts = urls.map((u) => new URL(u).hostname);
  if (s.m.fromAddr) hosts.push(s.m.fromAddr.split('@')[1]);
  return hosts;
}

/** Share text and URL: the score and the result page, nothing else. */
export function shareData(score, total, lang, template, origin = 'https://federicosella.com') {
  const url = `${origin}/${lang}/tools/phishing-quiz/score/${score}/`;
  return { text: template.replace('{score}', score).replace('{total}', total), url };
}
