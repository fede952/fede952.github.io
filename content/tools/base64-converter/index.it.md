---
title: "Convertitore Base64"
description: "Codifica e decodifica testo in/da formato Base64 con supporto UTF-8"
date: 2026-01-17
tags: ["codifica", "base64", "sicurezza", "tool"]
layout: "tool-split"
draft: false

code_language: "python"
algorithm_code: |
  import base64

  def base64_encode(text):
      """
      Codifica testo in Base64
      1. Converti testo in bytes (UTF-8)
      2. Applica codifica Base64
      3. Converti risultato in stringa
      """
      # Step 1: Testo → Bytes
      text_bytes = text.encode('utf-8')

      # Step 2: Bytes → Bytes Base64
      base64_bytes = base64.b64encode(text_bytes)

      # Step 3: Bytes Base64 → Stringa
      base64_string = base64_bytes.decode('ascii')

      return base64_string

  def base64_decode(base64_string):
      """
      Decodifica Base64 in testo
      Processo inverso con gestione errori
      """
      try:
          # Step 1: Stringa Base64 → Bytes
          base64_bytes = base64_string.encode('ascii')

          # Step 2: Bytes Base64 → Bytes Originali
          text_bytes = base64.b64decode(base64_bytes)

          # Step 3: Bytes → Testo
          text = text_bytes.decode('utf-8')

          return text

      except Exception as e:
          return f"Errore: Stringa Base64 non valida"

  # Esempio di Utilizzo
  originale = "Ciao, 世界!"  # Testo UTF-8
  codificato = base64_encode(originale)
  # Output: "Q2lhbywg5LiW55WMIQ=="

  decodificato = base64_decode(codificato)
  # Output: "Ciao, 世界!"

explanation: |
  **Base64** è uno schema di codifica binario-testo che rappresenta dati binari in formato stringa ASCII. È comunemente utilizzato per:

  - **Allegati email** (codifica MIME)
  - **Data URLs** in HTML/CSS (`data:image/png;base64,...`)
  - **JSON Web Tokens (JWT)** encoding
  - **Autenticazione API** (header Basic Auth)

  **Come funziona:**
  1. Il testo di input viene convertito in bytes (codifica UTF-8)
  2. Ogni 3 bytes (24 bit) vengono divisi in 4 gruppi da 6 bit
  3. Ogni gruppo da 6 bit viene mappato a un carattere Base64 (A-Z, a-z, 0-9, +, /)
  4. Viene aggiunto padding (`=`) se necessario per rendere la lunghezza dell'output un multiplo di 4

  **Note Importanti:**
  - Base64 **NON è crittografia** - è solo codifica
  - L'output è circa il 33% più grande dell'input
  - Questo tool supporta caratteri UTF-8 completi (inclusi emoji e testo internazionale)

tool_js: "/js/tools/base64.js"
tool_html: |
  <div class="tool-input-group">
    <label for="base64-input">Testo di Input</label>
    <textarea id="base64-input" rows="5" placeholder="Inserisci testo da codificare o stringa Base64 da decodificare...">Ciao, Mondo!</textarea>
  </div>

  <div class="tool-buttons">
    <button class="tool-btn" onclick="encodeBase64()">Codifica in Base64</button>
    <button class="tool-btn secondary" onclick="decodeBase64()">Decodifica da Base64</button>
    <button class="tool-btn secondary" onclick="clearBase64()">Cancella</button>
  </div>

  <div class="tool-output">
    <label>Output</label>
    <textarea id="base64-output" rows="5" readonly placeholder="Il risultato apparirà qui..."></textarea>
    <button class="copy-btn" onclick="copyBase64Output()">Copia</button>
  </div>

  <div id="base64-message"></div>
---

Utilizza questo strumento per codificare testo in Base64 o decodificare stringhe Base64 in testo semplice. Supporta completamente caratteri UTF-8 inclusi emoji e alfabeti internazionali.
