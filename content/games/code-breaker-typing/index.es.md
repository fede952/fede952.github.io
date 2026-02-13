---
title: "Code Breaker: Desafio de Escritura Cyberpunk"
description: "Pon a prueba tu velocidad de programacion. Escribe fragmentos reales de Python, Bash y JS contra reloj para vulnerar el sistema."
date: 2026-02-13
categories: ["Juegos", "Fun"]
tags: ["game", "typing", "html5", "cyberpunk", "coding-challenge"]
layout: "game"
draft: false
---

El sistema objetivo esta bloqueado detras de un firewall cifrado. Tu unica forma de entrar? **Escribe la secuencia de codigo exacta antes de que se acabe el tiempo.** Un error y quedas fuera. Que tan rapidos son tus dedos?

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

## Como Jugar

- **Haz clic en "INITIALIZE HACK"** para iniciar el temporizador y revelar un fragmento de codigo.
- **Escribe el fragmento exactamente** como se muestra — cada caracter, espacio y simbolo importa.
- **Vence el reloj de 30 segundos** para vulnerar el sistema.
- Si se acaba el tiempo, la conexion se termina. Pulsa **RETRY HACK** para intentarlo de nuevo.
