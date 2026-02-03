---
title: "Base64 Encoder/Decoder"
description: "Encode and decode text to/from Base64 format with UTF-8 support"
date: 2024-01-01
tags: ["encoding", "base64", "security", "tool"]
layout: "tool-split"
draft: false

code_language: "python"
algorithm_code: |
  import base64

  def base64_encode(text):
      """
      Encode text to Base64
      1. Convert text to bytes (UTF-8)
      2. Apply Base64 encoding
      3. Convert result to string
      """
      # Step 1: Text → Bytes
      text_bytes = text.encode('utf-8')

      # Step 2: Bytes → Base64 Bytes
      base64_bytes = base64.b64encode(text_bytes)

      # Step 3: Base64 Bytes → String
      base64_string = base64_bytes.decode('ascii')

      return base64_string

  def base64_decode(base64_string):
      """
      Decode Base64 back to text
      Reverse process with error handling
      """
      try:
          # Step 1: Base64 String → Bytes
          base64_bytes = base64_string.encode('ascii')

          # Step 2: Base64 Bytes → Original Bytes
          text_bytes = base64.b64decode(base64_bytes)

          # Step 3: Bytes → Text
          text = text_bytes.decode('utf-8')

          return text

      except Exception as e:
          return f"Error: Invalid Base64 string"

  # Example Usage
  original = "Hello, 世界!"  # UTF-8 text
  encoded = base64_encode(original)
  # Output: "SGVsbG8sIOS4lueVjCE="

  decoded = base64_decode(encoded)
  # Output: "Hello, 世界!"

explanation: |
  **Base64** is a binary-to-text encoding scheme that represents binary data in an ASCII string format. It's commonly used for:

  - **Email attachments** (MIME encoding)
  - **Data URLs** in HTML/CSS (`data:image/png;base64,...`)
  - **JSON Web Tokens (JWT)** encoding
  - **API authentication** (Basic Auth headers)

  **How it works:**
  1. Input text is converted to bytes (UTF-8 encoding)
  2. Every 3 bytes (24 bits) are divided into 4 groups of 6 bits
  3. Each 6-bit group is mapped to a Base64 character (A-Z, a-z, 0-9, +, /)
  4. Padding (`=`) is added if needed to make the output length a multiple of 4

  **Important Notes:**
  - Base64 is **NOT encryption** - it's just encoding
  - The output is ~33% larger than the input
  - This tool supports full UTF-8 characters (including emojis and international text)

tool_js: "/js/tools/base64.js"
tool_html: |
  <div class="tool-input-group">
    <label for="base64-input">Input Text</label>
    <textarea id="base64-input" rows="5" placeholder="Enter text to encode or Base64 string to decode...">Hello, World!</textarea>
  </div>

  <div class="tool-buttons">
    <button class="tool-btn" onclick="encodeBase64()">Encode to Base64</button>
    <button class="tool-btn secondary" onclick="decodeBase64()">Decode from Base64</button>
    <button class="tool-btn secondary" onclick="clearBase64()">Clear</button>
  </div>

  <div class="tool-output">
    <label>Output</label>
    <textarea id="base64-output" rows="5" readonly placeholder="Result will appear here..."></textarea>
    <button class="copy-btn" onclick="copyBase64Output()">Copy</button>
  </div>

  <div id="base64-message"></div>
---

_Примечание: Для сохранения технической точности этот контент отображается на языке оригинала (английском)._

---

Use this tool to encode text to Base64 or decode Base64 strings back to plain text. Fully supports UTF-8 characters including emojis and international alphabets.
