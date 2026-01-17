/**
 * Base64 Encoder/Decoder Tool - JavaScript Implementation
 * Federico Sella Tech Portal
 * Full UTF-8 support for international characters
 */

/**
 * Encode text to Base64
 * Handles UTF-8 properly using TextEncoder
 */
function encodeBase64() {
    const input = document.getElementById('base64-input').value;

    if (!input) {
        showBase64Message('Please enter some text to encode', 'error');
        return;
    }

    try {
        // UTF-8 safe encoding
        // First convert to UTF-8 bytes, then to Base64
        const utf8Bytes = new TextEncoder().encode(input);
        const binaryString = Array.from(utf8Bytes, byte => String.fromCharCode(byte)).join('');
        const base64 = btoa(binaryString);

        document.getElementById('base64-output').value = base64;
        showBase64Message('Text encoded to Base64 successfully!', 'success');

    } catch (error) {
        showBase64Message('Encoding error: ' + error.message, 'error');
    }
}

/**
 * Decode Base64 to text
 * Handles UTF-8 properly using TextDecoder
 */
function decodeBase64() {
    const input = document.getElementById('base64-input').value.trim();

    if (!input) {
        showBase64Message('Please enter a Base64 string to decode', 'error');
        return;
    }

    try {
        // UTF-8 safe decoding
        // First decode Base64, then interpret as UTF-8
        const binaryString = atob(input);
        const utf8Bytes = Uint8Array.from(binaryString, char => char.charCodeAt(0));
        const decoded = new TextDecoder().decode(utf8Bytes);

        document.getElementById('base64-output').value = decoded;
        showBase64Message('Base64 decoded successfully!', 'success');

    } catch (error) {
        showBase64Message('Decoding error: Invalid Base64 string. Please check your input.', 'error');
    }
}

/**
 * Clear all fields
 */
function clearBase64() {
    document.getElementById('base64-input').value = '';
    document.getElementById('base64-output').value = '';
    clearBase64Message();
}

/**
 * Copy output to clipboard
 */
function copyBase64Output() {
    const output = document.getElementById('base64-output');

    if (!output.value) {
        showBase64Message('Nothing to copy!', 'error');
        return;
    }

    output.select();

    try {
        // Try modern Clipboard API first
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(output.value).then(() => {
                updateCopyButton();
                showBase64Message('Copied to clipboard!', 'success');
            }).catch(() => {
                // Fallback to execCommand
                document.execCommand('copy');
                updateCopyButton();
                showBase64Message('Copied to clipboard!', 'success');
            });
        } else {
            // Fallback for older browsers
            document.execCommand('copy');
            updateCopyButton();
            showBase64Message('Copied to clipboard!', 'success');
        }
    } catch (error) {
        showBase64Message('Failed to copy to clipboard', 'error');
    }
}

/**
 * Update copy button visual feedback
 */
function updateCopyButton() {
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');

    setTimeout(() => {
        btn.textContent = originalText;
        btn.classList.remove('copied');
    }, 2000);
}

/**
 * Show message to user
 * @param {string} text - Message text
 * @param {string} type - Message type (success, error, info)
 */
function showBase64Message(text, type = 'info') {
    const messageDiv = document.getElementById('base64-message');
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
function clearBase64Message() {
    const messageDiv = document.getElementById('base64-message');
    messageDiv.style.display = 'none';
}
