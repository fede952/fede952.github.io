---
title: "Generatore di Hash"
description: "Genera hash crittografici (MD5, SHA-1, SHA-256, SHA-512) utilizzando Web Crypto API"
date: 2025-01-17
tags: ["crittografia", "hash", "sicurezza", "tool"]
layout: "tool-split"
draft: false

code_language: "python"
algorithm_code: |
  import hashlib

  def generate_hash(text, algorithm='sha256'):
      """
      Genera hash crittografico del testo
      Supporta: MD5, SHA-1, SHA-256, SHA-512
      """
      # Converti testo in bytes
      text_bytes = text.encode('utf-8')

      # Seleziona algoritmo hash
      if algorithm == 'md5':
          hash_obj = hashlib.md5()
      elif algorithm == 'sha1':
          hash_obj = hashlib.sha1()
      elif algorithm == 'sha256':
          hash_obj = hashlib.sha256()
      elif algorithm == 'sha512':
          hash_obj = hashlib.sha512()
      else:
          raise ValueError("Algoritmo non supportato")

      # Aggiorna hash con i dati
      hash_obj.update(text_bytes)

      # Ottieni rappresentazione esadecimale
      hash_hex = hash_obj.hexdigest()

      return hash_hex

  # Esempio di Utilizzo
  text = "Ciao, Mondo!"

  md5_hash = generate_hash(text, 'md5')
  # Output: "65a8e27d8879283831b664bd8b7f0ad4"

  sha256_hash = generate_hash(text, 'sha256')
  # Output: "dffd6021bb2bd5b0af676290809ec3a5..."

  sha512_hash = generate_hash(text, 'sha512')
  # Output: "374d794a95cdcfd8b35993185fef9ba3..."

explanation: |
  Una **funzione hash crittografica** è un algoritmo matematico che mappa dati di dimensione arbitraria in un valore di dimensione fissa (l'hash o digest).

  **Proprietà Chiave:**
  - **Deterministica**: Lo stesso input produce sempre lo stesso hash
  - **Unidirezionale**: Non è possibile invertire l'hash per ottenere i dati originali
  - **Resistente alle collisioni**: Input diversi raramente producono lo stesso hash
  - **Effetto valanga**: Piccola modifica dell'input = hash completamente diverso

  **Funzioni Hash Comuni:**

  - **MD5** (128-bit): Veloce ma **insicuro** - vulnerabile a collisioni. Utilizzare solo per scopi non di sicurezza (checksum)
  - **SHA-1** (160-bit): **Deprecato** per la sicurezza. Esistono attacchi di collisione
  - **SHA-256** (256-bit): **Raccomandato** - Parte della famiglia SHA-2, ampiamente utilizzato in Bitcoin, SSL/TLS
  - **SHA-512** (512-bit): **Più sicuro** - Variante più forte di SHA-2, utilizzato per applicazioni ad alta sicurezza

  **Utilizzi Comuni:**
  - Hashing password (con salt + key stretching)
  - Verifica integrità file
  - Firme digitali
  - Mining blockchain
  - Deduplica dati

  **Nota di Sicurezza:**
  Non utilizzare mai MD5 o SHA-256 da soli per le password! Usa funzioni di hashing password appropriate come Argon2, bcrypt o PBKDF2 con salt e alto numero di iterazioni.

tool_js: "/js/tools/hash.js"
tool_html: |
  <div class="tool-input-group">
    <label for="hash-input">Testo di Input</label>
    <textarea id="hash-input" rows="4" placeholder="Inserisci testo da hashare..." oninput="generateAllHashes()">Ciao, Mondo!</textarea>
  </div>

  <div class="tool-message info">
    Tutti gli hash vengono generati in tempo reale mentre digiti utilizzando Web Crypto API
  </div>

  <div class="tool-output">
    <label>MD5 (128-bit)</label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-md5" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('md5')" style="padding: 0.5rem 1rem;">Copia</button>
    </div>
  </div>

  <div class="tool-output">
    <label>SHA-1 (160-bit)</label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-sha1" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('sha1')" style="padding: 0.5rem 1rem;">Copia</button>
    </div>
  </div>

  <div class="tool-output">
    <label>SHA-256 (256-bit) <span style="color: #10b981;">Raccomandato</span></label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-sha256" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('sha256')" style="padding: 0.5rem 1rem;">Copia</button>
    </div>
  </div>

  <div class="tool-output">
    <label>SHA-512 (512-bit)</label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-sha512" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('sha512')" style="padding: 0.5rem 1rem;">Copia</button>
    </div>
  </div>

  <div class="tool-buttons">
    <button class="tool-btn secondary" onclick="clearHash()">Cancella Tutto</button>
  </div>

  <div id="hash-message"></div>
---

Genera hash crittografici in tempo reale utilizzando la Web Crypto API nativa del browser. Tutti i calcoli avvengono lato client - i tuoi dati non lasciano mai il tuo dispositivo.
