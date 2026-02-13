---
title: "Code Breaker: Sfida di Digitazione Cyberpunk"
description: "Metti alla prova la tua velocita di programmazione. Digita veri snippet Python, Bash e JS contro il tempo per violare il sistema."
date: 2026-02-13
categories: ["Giochi", "Fun"]
tags: ["game", "typing", "html5", "cyberpunk", "coding-challenge"]
layout: "game"
draft: false
---

Il sistema bersaglio e protetto da un firewall criptato. L'unico modo per entrare? **Digita la sequenza di codice esatta prima che scada il tempo.** Un solo errore e verrai bloccato. Quanto sono veloci le tue dita?

<div id="game-container" style="border: 1px solid #333; padding: 20px; background: rgba(0,0,0,0.5); border-radius: 8px; text-align: center;">
    <h2 class="neon-text">SYSTEM LOCKED</h2>
    <p>Type the code below to bypass the firewall.</p>

    <div id="timer" style="font-size: 2rem; color: #00ff41; margin: 10px 0;">30</div>

    <div id="code-display" style="background: #111; padding: 15px; border: 1px solid #444; color: #ccc; font-family: monospace; text-align: left; margin-bottom: 15px; user-select: none;">
        Press Start to initialize...
    </div>

    <textarea id="code-input" placeholder="Type here..." disabled style="width: 100%; height: 100px; background: #0d0d0d; color: #00ff41; border: 1px solid #333; padding: 10px; font-family: monospace;"></textarea>

    <button id="start-btn" style="margin-top: 15px; padding: 10px 30px; background: #00ff41; color: #000; border: none; font-weight: bold; cursor: pointer;">INITIALIZE HACK</button>
    <div id="result" style="margin-top: 10px; font-weight: bold;"></div>
</div>

<script>
const snippets = [
    "sudo systemctl restart nginx",
    "docker run -d -p 80:80 nginx",
    "const active = users.filter(u => u.isActive);",
    "git commit -m 'fix: critical bug'",
    "import os; os.system('rm -rf /tmp/*')"
];

let timeLeft = 30;
let timerInterval;
let currentSnippet = "";
const display = document.getElementById('code-display');
const input = document.getElementById('code-input');
const startBtn = document.getElementById('start-btn');
const timerEl = document.getElementById('timer');
const resultEl = document.getElementById('result');

startBtn.addEventListener('click', startGame);

function startGame() {
    input.value = "";
    input.disabled = false;
    input.focus();
    startBtn.style.display = 'none';
    resultEl.textContent = "";
    timeLeft = 30;
    timerEl.textContent = timeLeft;

    currentSnippet = snippets[Math.floor(Math.random() * snippets.length)];
    display.textContent = currentSnippet;

    timerInterval = setInterval(() => {
        timeLeft--;
        timerEl.textContent = timeLeft;
        if (timeLeft <= 0) endGame(false);
    }, 1000);
}

input.addEventListener('input', () => {
    if (input.value.trim() === currentSnippet) {
        endGame(true);
    }
});

function endGame(win) {
    clearInterval(timerInterval);
    input.disabled = true;
    startBtn.style.display = 'inline-block';
    startBtn.textContent = "RETRY HACK";

    if (win) {
        resultEl.innerHTML = "<span style='color:#00ff41'>ACCESS GRANTED. SYSTEM BREACHED.</span>";
    } else {
        resultEl.innerHTML = "<span style='color:red'>ACCESS DENIED. CONNECTION TERMINATED.</span>";
    }
}
</script>

## Come Giocare

- **Clicca "INITIALIZE HACK"** per avviare il timer e rivelare uno snippet di codice.
- **Digita lo snippet esattamente** come mostrato — ogni carattere, spazio e simbolo conta.
- **Batti il conto alla rovescia di 30 secondi** per violare il sistema.
- Se il tempo scade, la connessione viene terminata. Premi **RETRY HACK** per riprovare.
