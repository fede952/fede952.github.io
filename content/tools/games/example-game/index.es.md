---
title: "Example Browser Game"
description: "A demonstration of how to create browser-based games"
tags: ["example", "demo", "html5"]
layout: "game"
draft: false
date: 2026-02-03
---

_Nota: Para preservar la precisión técnica, este contenido se muestra en su idioma original (Inglés)._

---

This is an example game page to demonstrate the game layout.

## How It Works

Browser games can be embedded using either:

1. **Front matter parameter** - Set `game_file: "/path/to/game.html"` in the front matter
2. **Shortcode** - Use `{{</* game-embed src="/path/to/game.html" width="800" height="600" */>}}` in the content

## Creating Your Own Game

To create a new browser game:

1. Create a directory: `content/games/your-game-name/`
2. Add `index.md` with description (this file)
3. Create your game HTML in `static/games/your-game-name/game.html`
4. Add game logic in `static/js/games/your-game-name.js`
5. Set `game_file`, `game_width`, `game_height` parameters or use the shortcode

## Technologies Supported

- **HTML5 Canvas** - For 2D graphics
- **WebGL** - For 3D graphics
- **Vanilla JavaScript** - No frameworks needed
- **Any game engine** - Phaser, Three.js, PixiJS, etc.

## Example Game Structure

```
content/games/snake/
  └── index.md (this description)

static/games/snake/
  └── game.html (the game container)

static/js/games/
  └── snake.js (the game engine)
```

## Security

Games run in sandboxed iframes with:
- Script execution allowed
- Pointer lock allowed (for FPS games)
- No form submission
- No top navigation
