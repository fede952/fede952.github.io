---
title: "FLAC Lyric Video Generator"
date: 2026-01-11
draft: false
description: "A specialized automation tool for audiophiles to enjoy lossless FLAC audio with synchronized lyrics on in-car systems."
tags: ["FFmpeg", "PowerShell", "Automation", "Car Audio"]
categories: ["Projects", "Coding"]
externalLink: "https://github.com/fede952/Lyric-video-generator"
---

_Nota: Para preservar la precisión técnica, este contenido se muestra en su idioma original (Inglés)._

---

### Automating Lossless In-Car Entertainment

**Project Overview**
High-end automotive infotainment systems (such as the Audi MIB3) typically support FLAC audio but lack the ability to render synchronized external lyrics (`.lrc` files). This project bridges that gap for audiophiles who refuse to compromise on quality.

I developed a zero-dependency automation tool that merges lossless audio with synchronized lyrics into a video container. The core philosophy is **Bit-Perfect integrity**: the audio stream is copied directly without re-compression, while lyrics are programmatically "burned" into the video stream to ensure compatibility with any player, regardless of subtitle support.

**Key Features**

* **Lossless Audio Preservation:** Utilizes FFmpeg's `copy` codec to maintain the original FLAC quality 1:1.
* **Dynamic Lyric Rendering:** Parses standard `.lrc` files to create a dual-line karaoke display (highlighting current vs. upcoming lines).
* **Intelligent Automation:** Recursively scans directories to process full discographies in batch.
* **Visual Customization:** Supports custom backdrops (e.g., carbon fiber textures) with automated dimming for text readability.

**Technologies Used**

* **Core Logic:** PowerShell & Batch Scripting
* **Media Processing:** FFmpeg (CLI)
* **Data Formatting:** LRC to ASS (Advanced Substation Alpha) conversion logic

[View on GitHub](https://github.com/fede952/Lyric-video-generator)
