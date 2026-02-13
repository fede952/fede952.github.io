---
title: "Code Breaker: Киберпанк Испытание на Скорость Печати"
description: "Проверь свою скорость программирования. Набирай настоящие фрагменты Python, Bash и JS на время, чтобы взломать систему."
date: 2026-02-13
categories: ["Игры", "Fun"]
tags: ["game", "typing", "html5", "cyberpunk", "coding-challenge"]
layout: "game"
draft: false
---

Целевая система заблокирована за зашифрованным файрволом. Единственный путь внутрь? **Набери точную последовательность кода до истечения времени.** Одна ошибка — и тебя отключат. Насколько быстры твои пальцы?

<div id="game-container" style="border: 1px solid #333; padding: 20px; background: rgba(0,0,0,0.5); border-radius: 8px; text-align: center;">
    <h2 class="neon-text">СИСТЕМА ЗАБЛОКИРОВАНА</h2>
    <p>Набери код ниже, чтобы обойти файрвол.</p>

    <div id="timer" style="font-size: 2rem; color: #00ff41; margin: 10px 0;">30</div>

    <div id="code-display" style="background: #111; padding: 15px; border: 1px solid #444; color: #ccc; font-family: monospace; text-align: left; margin-bottom: 15px; user-select: none;">
        Нажмите «Старт» для инициализации...
    </div>

    <textarea id="code-input" placeholder="Печатайте здесь..." disabled style="width: 100%; height: 100px; background: #0d0d0d; color: #00ff41; border: 1px solid #333; padding: 10px; font-family: monospace;"></textarea>

    <button id="start-btn" style="margin-top: 15px; padding: 10px 30px; background: #00ff41; color: #000; border: none; font-weight: bold; cursor: pointer;">НАЧАТЬ ВЗЛОМ</button>
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
    startBtn.textContent = "ПОВТОРИТЬ ВЗЛОМ";

    if (win) {
        resultEl.innerHTML = "<span style='color:#00ff41'>ДОСТУП РАЗРЕШЁН. СИСТЕМА ВЗЛОМАНА.</span>";
    } else {
        resultEl.innerHTML = "<span style='color:red'>ДОСТУП ЗАПРЕЩЁН. СОЕДИНЕНИЕ ПРЕРВАНО.</span>";
    }
}
</script>

## Как Играть

- **Нажмите «НАЧАТЬ ВЗЛОМ»**, чтобы запустить таймер и увидеть фрагмент кода.
- **Наберите фрагмент точно так**, как он показан — каждый символ, пробел и знак имеет значение.
- **Уложитесь в 30 секунд**, чтобы взломать систему.
- Если время истечёт, соединение будет разорвано. Нажмите **ПОВТОРИТЬ ВЗЛОМ**, чтобы попробовать снова.
