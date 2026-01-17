/**
 * Caesar Cipher Tool - JavaScript Implementation
 * Federico Sella Tech Portal
 */

// Update shift value display
document.getElementById('caesar-shift').addEventListener('input', function() {
    document.getElementById('shift-value').textContent = this.value;
});

/**
 * Encrypt text using Caesar cipher
 */
function encryptCaesar() {
    const input = document.getElementById('caesar-input').value;
    const shift = parseInt(document.getElementById('caesar-shift').value);

    if (!input.trim()) {
        showMessage('Please enter some text to encrypt', 'error');
        return;
    }

    const result = caesarCipher(input, shift, false);
    document.getElementById('caesar-output').value = result;
    showMessage('Text encrypted successfully!', 'success');
}

/**
 * Decrypt text using Caesar cipher
 */
function decryptCaesar() {
    const input = document.getElementById('caesar-input').value;
    const shift = parseInt(document.getElementById('caesar-shift').value);

    if (!input.trim()) {
        showMessage('Please enter some text to decrypt', 'error');
        return;
    }

    const result = caesarCipher(input, shift, true);
    document.getElementById('caesar-output').value = result;
    showMessage('Text decrypted successfully!', 'success');
}

/**
 * Core Caesar cipher algorithm
 * @param {string} text - Input text
 * @param {number} shift - Shift key (1-25)
 * @param {boolean} decrypt - Whether to decrypt (reverse shift)
 * @returns {string} - Encrypted/decrypted text
 */
function caesarCipher(text, shift, decrypt = false) {
    if (decrypt) {
        shift = -shift;
    }

    let result = '';

    for (let i = 0; i < text.length; i++) {
        let char = text[i];

        if (char.match(/[a-z]/i)) {
            // Determine if uppercase or lowercase
            const code = text.charCodeAt(i);
            const isUpperCase = (code >= 65 && code <= 90);
            const base = isUpperCase ? 65 : 97;

            // Shift character
            const shifted = ((code - base + shift) % 26 + 26) % 26;
            result += String.fromCharCode(shifted + base);
        } else {
            // Keep non-alphabetic characters unchanged
            result += char;
        }
    }

    return result;
}

/**
 * Clear all fields
 */
function clearCaesar() {
    document.getElementById('caesar-input').value = '';
    document.getElementById('caesar-output').value = '';
    document.getElementById('caesar-shift').value = 3;
    document.getElementById('shift-value').textContent = '3';
    clearMessage();
}

/**
 * Copy output to clipboard
 */
function copyCaesarOutput() {
    const output = document.getElementById('caesar-output');

    if (!output.value) {
        showMessage('Nothing to copy!', 'error');
        return;
    }

    output.select();
    document.execCommand('copy');

    // Visual feedback
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');

    setTimeout(() => {
        btn.textContent = originalText;
        btn.classList.remove('copied');
    }, 2000);

    showMessage('Copied to clipboard!', 'success');
}

/**
 * Show message to user
 * @param {string} text - Message text
 * @param {string} type - Message type (success, error, info)
 */
function showMessage(text, type = 'info') {
    const messageDiv = document.getElementById('caesar-message');
    messageDiv.textContent = text;
    messageDiv.className = `tool-message ${type}`;
    messageDiv.style.display = 'block';

    // Auto-hide after 3 seconds
    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 3000);
}

/**
 * Clear message
 */
function clearMessage() {
    const messageDiv = document.getElementById('caesar-message');
    messageDiv.style.display = 'none';
}
