---
title: "Focus Timer & Ambient Noise Mixer"
description: "Mix white, pink and brown noise, rain, fire, keyboard and café sounds, and run a Pomodoro-style focus timer. Sounds generated live in your browser."
intro: "**ZenFocus** combines a focus timer with an eight-channel ambient sound mixer. Pick a preset or blend your own mix of noise, rain, fireplace, keyboard clicks and coffee-shop murmur, then start a 25-minute session. Every sound is generated live in your browser, with no audio files to download and no account."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["focus timer", "pomodoro timer online", "ambient noise mixer", "brown noise generator", "white noise online", "pink noise", "rain sounds for studying", "background noise for focus"]
tags: ["productivity", "focus", "audio", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/zen-focus/"
tool_title: "ZenFocus timer and noise mixer"
tool_height: 800
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
tool_allow: "clipboard-write; web-share"
howto:
  - "Choose a preset: **Deep Work** (brown noise and rain), **Coffee Break** (café murmur and fireplace) or **Silence** to mute every channel."
  - "Or build your own mix by dragging the slider on each card. The 🔊 button on a card mutes that channel without losing its level."
  - "Set the overall level with the **Master** slider. Start low: masking noise works best just loud enough to cover distractions."
  - "Adjust the session length with **−5**, **−1**, **+1** and **+5** (1 to 90 minutes, default 25), then press **Start**."
  - "Work until the chime. Press **Pause** to stop the clock and **Reset** to restore the full duration. For a break, set 5 minutes and start again."
faq:
  - q: "What is the difference between white, pink and brown noise?"
    a: "They differ in how energy is spread across frequencies. White noise has equal power at every frequency and sounds hissy. Pink noise loses about 3 dB per octave, so it sounds softer and more like steady rain. Brown (Brownian) noise loses about 6 dB per octave and sounds like a deep rumble or distant waterfall. Many people find brown or pink noise less fatiguing than white for long sessions."
  - q: "Does background noise actually improve focus?"
    a: "The evidence is mixed. Steady noise reliably masks unpredictable sounds such as speech and notifications, which are what usually break concentration. Some studies report benefits for attention, especially in people with ADHD, while others find no effect or a cost for complex reading. Treat it as a personal experiment: try a mix for a week and keep it if it helps."
  - q: "What is the Pomodoro Technique?"
    a: "A time-management method created by Francesco Cirillo: work on one task for 25 minutes, take a 5-minute break, and after four rounds take a longer 15–30 minute break. ZenFocus defaults to 25 minutes; set the timer to 5 for breaks. It does not switch automatically, which keeps you in control of when the next round starts."
  - q: "Does the timer keep running in a background tab?"
    a: "Yes. The countdown is calculated from a fixed end time, not by counting ticks, so it stays accurate even when the browser throttles timers in hidden tabs. The chime plays when time is up, as long as the tab is still open."
  - q: "Why is there no sound until I click something?"
    a: "Browsers block audio until you interact with a page. ZenFocus starts its audio engine on your first click on a slider, preset or Start, then fades channels in."
  - q: "Are the sounds recordings?"
    a: "No. Every channel is synthesised with the Web Audio API: noise buffers shaped by filters (for example, rain is high-passed white noise and thunder is low-passed brown noise), and the keyboard is a stream of short randomised clicks. Nothing is downloaded or streamed, so it also works offline once the page has loaded."
  - q: "Is it safe to listen for hours?"
    a: "Keep the volume moderate. A common guideline is to stay at levels where you can still hear someone speaking next to you, and to take regular breaks. Long exposure to loud sound through headphones can damage hearing."
---

## How it works

ZenFocus is a single page built on the **Web Audio API**. When you first interact with it, it creates an `AudioContext` and generates a few seconds of raw noise into memory:

- **White noise** with uniformly random samples between −1 and 1, which gives a flat spectrum.
- **Pink noise** using Paul Kellet's well-known filter, a bank of first-order filters that approximates a −3 dB/octave slope.
- **Brown noise** from a "leaky integrator" that accumulates random steps, giving a −6 dB/octave slope.
- **Keyboard clicks**: about five short, exponentially decaying bursts per second at random volumes.

The pink and brown buffers are adjusted so their last sample meets the first, so the loop point doesn't click. Each of the eight channels is a looping source, optionally passed through a biquad filter, then a gain node (the card's slider), then the master gain:

| Channel | Source | Filter |
|---|---|---|
| White Noise | white | none |
| Pink Noise | pink | none |
| Brown Noise | brown | none |
| Rain | white | high-pass 1.2 kHz |
| Thunder | brown | low-pass 100 Hz |
| Fireplace | white | band-pass 700 Hz |
| Keyboard | clicks | band-pass 2.2 kHz |
| Coffee Shop | pink | wide band-pass 1 kHz |

All channels run continuously from the start; moving a slider only changes its gain, with a 50 ms ramp so changes never pop. Muting ramps the gain to zero but remembers the slider value.

**The timer** stores the moment the session should end and recomputes the remaining time four times a second. Browsers can slow `setInterval` in background tabs, but because the display is derived from the clock rather than from counted ticks, a 25-minute session ends after 25 minutes. When it reaches zero, three sine tones (an A-major arpeggio: 880, 1109 and 1319 Hz) play as a soft chime.

The Share button uses your device's native share sheet where available, and otherwise copies the page link. Nothing else leaves the page: no settings or usage are stored.

## Use cases

- **Deep-work blocks.** Start Deep Work, set 50 minutes and close everything else. The steady rumble masks office chatter and street noise.
- **Studying with the Pomodoro method.** Alternate 25-minute sessions and 5-minute breaks, and take a longer break after four rounds.
- **Open-plan offices and shared homes.** Pink or brown noise under headphones at low volume covers intelligible speech, the most distracting sound for most people.
- **Writing and reading.** A light Coffee Shop + Fireplace mix gives a "café" atmosphere without music lyrics competing for attention.
- **Winding down.** Rain and brown noise make a calm background for reading before sleep. Use the timer to stop yourself scrolling.
- **Timeboxing chores and meetings.** Set 10 or 15 minutes for a task you keep postponing; the chime tells you when to stop.
