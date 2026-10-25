---
title: "Aim Trainer & Reaction Time Test Online"
description: "Train your mouse aim in 60-second sessions: click glowing targets, then get hits, accuracy, average reaction time and a rank. Free browser aim trainer."
intro: "**ReflexGrid** is a 60-second aim trainer: targets pop up anywhere on the grid, you click or tap them as fast as you can, and at the end you get your hits, accuracy, average time-to-target and a rank from *Potato* to *Pro*."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["aim trainer", "reaction time test", "aim trainer online", "mouse accuracy test", "click speed test", "fps aim practice", "aim training browser", "reflex test"]
tags: ["games", "gaming", "reflexes", "tool"]
app_category: "GameApplication"
tool_file: "/tools/reflex-grid/"
tool_title: "ReflexGrid aim trainer"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Press **Start Training**. The 60-second timer starts and the first target appears."
  - "Click (or tap on touch screens) each glowing circle as fast and as accurately as you can. A new one appears as soon as you hit it."
  - "Watch the top bar: time left, hits so far and live accuracy. Missed clicks count against your accuracy."
  - "When time runs out, read the results: **Targets Hit**, **Accuracy**, **Avg Reaction** and **Total Clicks**, plus your rank."
  - "Press **Play Again** to beat your score. Warm up with a few rounds before comparing results."
faq:
  - q: "What is a good reaction time in this test?"
    a: "The average here is the time from a target appearing to your hit, so it includes moving the mouse, not just reacting. Under 300 ms (the *Gamer* rank) is good; under 200 ms (*Pro*) is excellent. Pure visual reaction time in simple tests is typically around 200–250 ms for adults, so ReflexGrid's numbers are naturally a bit higher."
  - q: "How are the ranks calculated?"
    a: "From your average time-to-target: under 200 ms is *Pro*, under 300 ms *Gamer*, under 400 ms *Casual*, under 500 ms *Novice*, and anything slower *Potato*. Accuracy is shown separately; for real progress, keep it above about 80% while bringing the time down."
  - q: "Does mouse sensitivity or DPI matter?"
    a: "Yes, a lot. Aim training is only useful with the same sensitivity you play with, so keep your in-game DPI and OS pointer settings. Disabling \"enhance pointer precision\" (mouse acceleration) on Windows makes movements more consistent and easier to train."
  - q: "Why do some targets look red?"
    a: "About 40% of targets are red instead of cyan, purely as a visual variation to keep you from anticipating. Both count the same."
  - q: "Can I play on a phone?"
    a: "Yes. The canvas listens for touch as well as mouse events, so taps count as clicks. Times on touch screens are not comparable with mouse times, so compare yourself with yourself on the same device."
  - q: "Are my scores saved or uploaded?"
    a: "No. Each session lives only in the page; nothing is stored or sent. Write down your best result if you want to track progress."
---

## How it works

The game is drawn on an HTML `<canvas>` scaled for your screen's pixel ratio, with an animated background grid and a HUD bar at the top.

**Targets.** Each target gets a random radius between 20 and 35 pixels and a random position, padded away from the edges and the HUD. It pulses by ±12% so it never sits perfectly still. The time it appears is stored with `performance.now()`, the browser's high-resolution clock.

**Hits and misses.** On every `mousedown` or `touchstart`, the distance from your pointer to the target's centre is computed with Pythagoras. Anything within 1.3× the radius counts as a hit, a small allowance for the glow and the pulse. A hit records the reaction time (now − spawn time), plays a short rising square-wave tone generated with the Web Audio API, emits a burst of particles and spawns the next target immediately. A miss plays a falling sawtooth tone and only increases your click count.

**Scoring.** At the end of the 60 seconds:

- **Targets Hit** is the number of successful clicks;
- **Accuracy** is hits ÷ total clicks;
- **Avg Reaction** is the mean of all recorded reaction times, in milliseconds;
- **Rank** depends on that average.

| Avg time-to-target | Rank |
|---|---|
| under 200 ms | Pro |
| 200–299 ms | Gamer |
| 300–399 ms | Casual |
| 400–499 ms | Novice |
| 500 ms and above | Potato |

Because each target spawns the instant the previous one is hit, the test measures *flick* speed: seeing a new target, moving to it and clicking. That is closer to what FPS games demand than a "wait for the screen to turn green" reaction test.

## Use cases

- **Warming up before FPS games** such as Valorant, CS2, Apex Legends or Overwatch: two or three rounds get your hand and eyes in sync.
- **Testing a new mouse or sensitivity.** Play a few rounds with each setting and compare accuracy and time-to-target.
- **Tracking improvement.** Note your average and accuracy each day; consistent practice shows up as lower times at the same accuracy.
- **A quick break.** One minute of focused clicking is a decent reset between long work sessions.
- **Ergonomics checks.** A sudden drop in accuracy can be a sign of fatigue; take a break.
