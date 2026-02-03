---
title: "Cifrario di Cesare"
description: "Cifra e decifra testo utilizzando il classico cifrario di Cesare con chiave di spostamento personalizzabile"
date: 2024-01-01
tags: ["crittografia", "cifrario", "sicurezza", "tool"]
layout: "tool-split"
draft: false

code_language: "python"
algorithm_code: |
  def caesar_cipher(text, shift, decrypt=False):
      """
      Implementazione del cifrario di Cesare
      Sposta ogni lettera di 'shift' posizioni
      """
      if decrypt:
          shift = -shift

      result = []

      for char in text:
          if char.isalpha():
              # Ottieni offset ASCII (A=65, a=97)
              ascii_offset = 65 if char.isupper() else 97

              # Sposta carattere
              shifted = (ord(char) - ascii_offset + shift) % 26

              # Riconverti in carattere
              result.append(chr(shifted + ascii_offset))
          else:
              # Mantieni caratteri non alfabetici invariati
              result.append(char)

      return ''.join(result)

  # Esempio
  testo_chiaro = "Ciao Mondo"
  chiave = 3

  cifrato = caesar_cipher(testo_chiaro, chiave)
  # Output: "Fldn Prqgr"

  decifrato = caesar_cipher(cifrato, chiave, decrypt=True)
  # Output: "Ciao Mondo"

explanation: |
  Il **cifrario di Cesare** è una delle tecniche di cifratura più antiche e semplici, prende il nome da Giulio Cesare che lo utilizzava nella sua corrispondenza privata.

  **Come funziona:**
  - Ogni lettera nel testo in chiaro viene spostata di un numero fisso di posizioni nell'alfabeto
  - Ad esempio, con uno spostamento di 3: A→D, B→E, C→F, ecc.
  - I caratteri non alfabetici (numeri, spazi, punteggiatura) rimangono invariati
  - Il cifrario si "riavvolge": X→A, Y→B, Z→C (con spostamento 3)

  **Nota di Sicurezza:**
  Il cifrario di Cesare **NON è sicuro** per uso moderno. Con solo 25 chiavi possibili, può essere violato in secondi usando la forza bruta. È mostrato qui per scopi educativi per dimostrare concetti crittografici di base.

tool_js: "/js/tools/caesar.js"
tool_html: |
  <div class="tool-input-group">
    <label for="caesar-input">Testo di Input</label>
    <textarea id="caesar-input" rows="4" placeholder="Inserisci il tuo testo qui...">Ciao Mondo!</textarea>
  </div>

  <div class="tool-input-group">
    <label for="caesar-shift">
      Chiave di Spostamento
      <span class="range-value" id="shift-value">3</span>
    </label>
    <input type="range" id="caesar-shift" min="1" max="25" value="3">
  </div>

  <div class="tool-buttons">
    <button class="tool-btn" onclick="encryptCaesar()">Cifra</button>
    <button class="tool-btn secondary" onclick="decryptCaesar()">Decifra</button>
    <button class="tool-btn secondary" onclick="clearCaesar()">Cancella</button>
  </div>

  <div class="tool-output">
    <label>Output</label>
    <textarea id="caesar-output" rows="4" readonly placeholder="Il risultato apparirà qui..."></textarea>
    <button class="copy-btn" onclick="copyCaesarOutput()">Copia</button>
  </div>

  <div id="caesar-message"></div>
---

Utilizza lo strumento interattivo a destra per cifrare e decifrare testo usando il cifrario di Cesare. Regola la chiave di spostamento usando lo slider e osserva i risultati in tempo reale.
