---
title: "Hash Generator"
description: "Generate cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512) using Web Crypto API"
date: 2026-02-03
tags: ["cryptography", "hash", "security", "tool"]
layout: "tool-split"
draft: false

code_language: "python"
algorithm_code: |
  import hashlib

  def generate_hash(text, algorithm='sha256'):
      """
      Generate cryptographic hash of text
      Supports: MD5, SHA-1, SHA-256, SHA-512
      """
      # Convert text to bytes
      text_bytes = text.encode('utf-8')

      # Select hash algorithm
      if algorithm == 'md5':
          hash_obj = hashlib.md5()
      elif algorithm == 'sha1':
          hash_obj = hashlib.sha1()
      elif algorithm == 'sha256':
          hash_obj = hashlib.sha256()
      elif algorithm == 'sha512':
          hash_obj = hashlib.sha512()
      else:
          raise ValueError("Unsupported algorithm")

      # Update hash with data
      hash_obj.update(text_bytes)

      # Get hexadecimal representation
      hash_hex = hash_obj.hexdigest()

      return hash_hex

  # Example Usage
  text = "Hello, World!"

  md5_hash = generate_hash(text, 'md5')
  # Output: "65a8e27d8879283831b664bd8b7f0ad4"

  sha256_hash = generate_hash(text, 'sha256')
  # Output: "dffd6021bb2bd5b0af676290809ec3a5..."

  sha512_hash = generate_hash(text, 'sha512')
  # Output: "374d794a95cdcfd8b35993185fef9ba3..."

explanation: |
  A **cryptographic hash function** is a mathematical algorithm that maps data of arbitrary size to a fixed-size value (the hash or digest).

  **Key Properties:**
  - **Deterministic**: Same input always produces same hash
  - **One-way**: Cannot reverse hash back to original data
  - **Collision-resistant**: Different inputs rarely produce same hash
  - **Avalanche effect**: Small input change = completely different hash

  **Common Hash Functions:**

  - **MD5** (128-bit): Fast but **insecure** - vulnerable to collisions. Only use for non-security purposes (checksums)
  - **SHA-1** (160-bit): **Deprecated** for security. Collision attacks exist
  - **SHA-256** (256-bit): **Recommended** - Part of SHA-2 family, widely used in Bitcoin, SSL/TLS
  - **SHA-512** (512-bit): **Most secure** - Stronger variant of SHA-2, used for high-security applications

  **Common Uses:**
  - Password hashing (with salt + key stretching)
  - File integrity verification
  - Digital signatures
  - Blockchain mining
  - Data deduplication

  **Security Note:**
  Never hash passwords with just MD5 or SHA-256 alone! Use proper password hashing functions like Argon2, bcrypt, or PBKDF2 with salt and high iteration counts.

tool_js: "/js/tools/hash.js"
tool_html: |
  <div class="tool-input-group">
    <label for="hash-input">Input Text</label>
    <textarea id="hash-input" rows="4" placeholder="Enter text to hash..." oninput="generateAllHashes()">Hello, World!</textarea>
  </div>

  <div class="tool-message info">
    All hashes are generated in real-time as you type using Web Crypto API
  </div>

  <div class="tool-output">
    <label>MD5 (128-bit)</label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-md5" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('md5')" style="padding: 0.5rem 1rem;">Copy</button>
    </div>
  </div>

  <div class="tool-output">
    <label>SHA-1 (160-bit)</label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-sha1" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('sha1')" style="padding: 0.5rem 1rem;">Copy</button>
    </div>
  </div>

  <div class="tool-output">
    <label>SHA-256 (256-bit) <span style="color: #10b981;">Recommended</span></label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-sha256" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('sha256')" style="padding: 0.5rem 1rem;">Copy</button>
    </div>
  </div>

  <div class="tool-output">
    <label>SHA-512 (512-bit)</label>
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      <input type="text" id="hash-sha512" readonly style="flex: 1; font-family: monospace; font-size: 0.85rem;">
      <button class="tool-btn secondary" onclick="copyHash('sha512')" style="padding: 0.5rem 1rem;">Copy</button>
    </div>
  </div>

  <div class="tool-buttons">
    <button class="tool-btn secondary" onclick="clearHash()">Clear All</button>
  </div>

  <div id="hash-message"></div>
---

_참고: 기술적 정확성을 유지하기 위해 이 콘텐츠는 원래 언어(영어)로 표시됩니다._

---

Generate cryptographic hashes in real-time using the browser's native Web Crypto API. All computations happen client-side - your data never leaves your device.
