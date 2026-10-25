/**
 * Caesar Cipher Tool - JavaScript Implementation
 * Federico Sella Tech Portal
 * Shifts the 26 basic Latin letters (A-Z, a-z); everything else is kept.
 * UI strings come from window.TOOL_STRINGS (set by the Hugo partial).
 */

function T(key, fallback) {
    var s = window.TOOL_STRINGS && window.TOOL_STRINGS[key];
    return s || fallback;
}

// Update shift value display
document.getElementById('caesar-shift').addEventListener('input', function() {
    document.getElementById('shift-value').textContent = this.value;
});

/**
 * Encrypt text using Caesar cipher
 */
function encryptCaesar() {
    runCaesar(false);
}

/**
 * Decrypt text using Caesar cipher
 */
function decryptCaesar() {
    runCaesar(true);
}

function runCaesar(decrypt) {
    const input = document.getElementById('caesar-input').value;
    const shift = parseInt(document.getElementById('caesar-shift').value, 10);

    if (!input.trim()) {
        showMessage(T('needText', 'Enter some text first.'), 'error');
        return;
    }

    document.getElementById('caesar-output').value = caesarCipher(input, shift, decrypt);
    showMessage(decrypt ? T('decrypted', 'Text decrypted.') : T('encrypted', 'Text encrypted.'), 'success');
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
        const code = text.charCodeAt(i);
        const isUpper = code >= 65 && code <= 90;
        const isLower = code >= 97 && code <= 122;

        if (isUpper || isLower) {
            const base = isUpper ? 65 : 97;
            // ((x + k) mod 26 + 26) mod 26 keeps the result positive for negative shifts
            const shifted = ((code - base + shift) % 26 + 26) % 26;
            result += String.fromCharCode(shifted + base);
        } else {
            // Keep digits, punctuation, spaces and accented letters unchanged
            result += text[i];
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
function copyCaesarOutput(evt) {
    const output = document.getElementById('caesar-output');
    const btn = evt && evt.currentTarget;

    if (!output.value) {
        showMessage(T('nothing', 'Nothing to copy yet.'), 'error');
        return;
    }

    const done = () => {
        if (btn) {
            const originalText = btn.textContent;
            btn.textContent = T('copiedShort', 'Copied!');
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = originalText;
                btn.classList.remove('copied');
            }, 2000);
        }
        showMessage(T('copied', 'Copied to the clipboard.'), 'success');
    };
    const legacy = () => {
        output.select();
        try { document.execCommand('copy'); done(); }
        catch (error) { showMessage(T('copyFailed', 'Could not copy to the clipboard.'), 'error'); }
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(output.value).then(done).catch(legacy);
    } else {
        legacy();
    }
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
    clearTimeout(showMessage.timer);
    showMessage.timer = setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 3000);
}

/**
 * Clear message
 */
function clearMessage() {
    document.getElementById('caesar-message').style.display = 'none';
}
