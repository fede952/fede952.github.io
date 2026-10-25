/**
 * Base64 Encoder/Decoder Tool - JavaScript Implementation
 * Federico Sella Tech Portal
 * Full UTF-8 support; decoding also accepts Base64URL (JWT-style) input.
 * UI strings come from window.TOOL_STRINGS (set by the Hugo partial).
 */

function T(key, fallback) {
    var s = window.TOOL_STRINGS && window.TOOL_STRINGS[key];
    return s || fallback;
}

/**
 * Encode text to Base64
 * Handles UTF-8 properly using TextEncoder
 */
function encodeBase64() {
    const input = document.getElementById('base64-input').value;

    if (!input) {
        showBase64Message(T('needText', 'Enter some text to encode.'), 'error');
        return;
    }

    // UTF-8 safe encoding: text -> UTF-8 bytes -> binary string -> Base64
    const utf8Bytes = new TextEncoder().encode(input);
    const binaryString = Array.from(utf8Bytes, byte => String.fromCharCode(byte)).join('');
    document.getElementById('base64-output').value = btoa(binaryString);
    showBase64Message(T('encoded', 'Encoded to Base64 (UTF-8).'), 'success');
}

/**
 * Decode Base64 (or Base64URL) to text
 * Handles UTF-8 properly using TextDecoder
 */
function decodeBase64() {
    let input = document.getElementById('base64-input').value.replace(/\s+/g, '');

    if (!input) {
        showBase64Message(T('needB64', 'Enter a Base64 string to decode.'), 'error');
        return;
    }

    // Base64URL (RFC 4648 §5, used by JWTs and many APIs): map the URL-safe
    // alphabet back to standard Base64 and restore the stripped "=" padding.
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    if (input.length % 4 === 1) {
        showBase64Message(T('invalid', 'This is not valid Base64 or Base64URL.'), 'error');
        return;
    }
    while (input.length % 4) input += '=';

    let utf8Bytes;
    try {
        const binaryString = atob(input);
        utf8Bytes = Uint8Array.from(binaryString, char => char.charCodeAt(0));
    } catch (error) {
        showBase64Message(T('invalid', 'This is not valid Base64 or Base64URL.'), 'error');
        return;
    }

    try {
        // fatal: true -> invalid UTF-8 (binary data) is reported, not mangled
        document.getElementById('base64-output').value = new TextDecoder('utf-8', { fatal: true }).decode(utf8Bytes);
        showBase64Message(T('decoded', 'Decoded from Base64.'), 'success');
    } catch (error) {
        document.getElementById('base64-output').value = new TextDecoder('utf-8').decode(utf8Bytes);
        showBase64Message(T('notText', 'Decoded, but the bytes are not valid UTF-8 text.'), 'info');
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
function copyBase64Output(evt) {
    const output = document.getElementById('base64-output');
    const btn = evt && evt.currentTarget;

    if (!output.value) {
        showBase64Message(T('nothing', 'Nothing to copy yet.'), 'error');
        return;
    }

    const done = () => {
        updateCopyButton(btn);
        showBase64Message(T('copied', 'Copied to the clipboard.'), 'success');
    };
    const legacy = () => {
        output.select();
        try { document.execCommand('copy'); done(); }
        catch (error) { showBase64Message(T('copyFailed', 'Could not copy to the clipboard.'), 'error'); }
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(output.value).then(done).catch(legacy);
    } else {
        legacy();
    }
}

/**
 * Copy button visual feedback
 */
function updateCopyButton(btn) {
    if (!btn) return;
    const originalText = btn.textContent;
    btn.textContent = T('copiedShort', 'Copied!');
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
    clearTimeout(showBase64Message.timer);
    showBase64Message.timer = setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 3000);
}

/**
 * Clear message
 */
function clearBase64Message() {
    document.getElementById('base64-message').style.display = 'none';
}
