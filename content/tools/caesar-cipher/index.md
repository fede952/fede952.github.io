---
title: "Caesar Cipher"
description: "Encrypt and decrypt text using the classic Caesar cipher with customizable shift key"
date: 2024-01-01
tags: ["cryptography", "cipher", "security", "tool"]
layout: "tool-split"
draft: false

code_language: "python"
algorithm_code: |
  def caesar_cipher(text, shift, decrypt=False):
      """
      Caesar cipher implementation
      Shifts each letter by 'shift' positions
      """
      if decrypt:
          shift = -shift

      result = []

      for char in text:
          if char.isalpha():
              # Get ASCII offset (A=65, a=97)
              ascii_offset = 65 if char.isupper() else 97

              # Shift character
              shifted = (ord(char) - ascii_offset + shift) % 26

              # Convert back to character
              result.append(chr(shifted + ascii_offset))
          else:
              # Keep non-alphabetic characters unchanged
              result.append(char)

      return ''.join(result)

  # Example
  plaintext = "Hello World"
  shift_key = 3

  encrypted = caesar_cipher(plaintext, shift_key)
  # Output: "Khoor Zruog"

  decrypted = caesar_cipher(encrypted, shift_key, decrypt=True)
  # Output: "Hello World"

explanation: |
  The **Caesar cipher** is one of the oldest and simplest encryption techniques, named after Julius Caesar who used it in his private correspondence.

  **How it works:**
  - Each letter in the plaintext is shifted by a fixed number of positions down the alphabet
  - For example, with a shift of 3: A→D, B→E, C→F, etc.
  - Non-alphabetic characters (numbers, spaces, punctuation) remain unchanged
  - The cipher wraps around: X→A, Y→B, Z→C (with shift 3)

  **Security Note:**
  The Caesar cipher is **NOT secure** for modern use. With only 25 possible keys, it can be broken in seconds using brute force. It's shown here for educational purposes to demonstrate basic cryptographic concepts.

tool_js: "/js/tools/caesar.js"
tool_html: |
  <div class="tool-input-group">
    <label for="caesar-input">Input Text</label>
    <textarea id="caesar-input" rows="4" placeholder="Enter your text here...">Hello World!</textarea>
  </div>

  <div class="tool-input-group">
    <label for="caesar-shift">
      Shift Key
      <span class="range-value" id="shift-value">3</span>
    </label>
    <input type="range" id="caesar-shift" min="1" max="25" value="3">
  </div>

  <div class="tool-buttons">
    <button class="tool-btn" onclick="encryptCaesar()">Encrypt</button>
    <button class="tool-btn secondary" onclick="decryptCaesar()">Decrypt</button>
    <button class="tool-btn secondary" onclick="clearCaesar()">Clear</button>
  </div>

  <div class="tool-output">
    <label>Output</label>
    <textarea id="caesar-output" rows="4" readonly placeholder="Result will appear here..."></textarea>
    <button class="copy-btn" onclick="copyCaesarOutput()">Copy</button>
  </div>

  <div id="caesar-message"></div>
---

Use the interactive tool on the right to encrypt and decrypt text using the Caesar cipher. Adjust the shift key using the slider and see the results in real-time.
