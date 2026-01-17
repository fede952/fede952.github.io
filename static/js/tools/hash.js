/**
 * Hash Generator Tool - JavaScript Implementation
 * Federico Sella Tech Portal
 * Uses Web Crypto API for SHA algorithms and pure JS for MD5
 */

/**
 * Generate all hashes in real-time
 */
async function generateAllHashes() {
    const input = document.getElementById('hash-input').value;

    if (!input) {
        clearAllHashes();
        return;
    }

    try {
        // Generate all hashes in parallel
        const [md5, sha1, sha256, sha512] = await Promise.all([
            generateMD5(input),
            generateSHA(input, 'SHA-1'),
            generateSHA(input, 'SHA-256'),
            generateSHA(input, 'SHA-512')
        ]);

        document.getElementById('hash-md5').value = md5;
        document.getElementById('hash-sha1').value = sha1;
        document.getElementById('hash-sha256').value = sha256;
        document.getElementById('hash-sha512').value = sha512;

    } catch (error) {
        showHashMessage('Error generating hashes: ' + error.message, 'error');
    }
}

/**
 * Generate SHA hash using Web Crypto API
 * @param {string} text - Input text
 * @param {string} algorithm - SHA-1, SHA-256, or SHA-512
 * @returns {Promise<string>} - Hex hash
 */
async function generateSHA(text, algorithm) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    return bufferToHex(hashBuffer);
}

/**
 * Generate MD5 hash (pure JavaScript implementation)
 * Note: Web Crypto API doesn't support MD5, so we use a pure JS implementation
 * @param {string} text - Input text
 * @returns {string} - MD5 hex hash
 */
function generateMD5(text) {
    // MD5 implementation (simplified for educational purposes)
    // For production, consider using a library like CryptoJS

    function md5cycle(x, k) {
        let a = x[0], b = x[1], c = x[2], d = x[3];
        a = ff(a, b, c, d, k[0], 7, -680876936);
        d = ff(d, a, b, c, k[1], 12, -389564586);
        c = ff(c, d, a, b, k[2], 17, 606105819);
        b = ff(b, c, d, a, k[3], 22, -1044525330);
        a = ff(a, b, c, d, k[4], 7, -176418897);
        d = ff(d, a, b, c, k[5], 12, 1200080426);
        c = ff(c, d, a, b, k[6], 17, -1473231341);
        b = ff(b, c, d, a, k[7], 22, -45705983);
        a = ff(a, b, c, d, k[8], 7, 1770035416);
        d = ff(d, a, b, c, k[9], 12, -1958414417);
        c = ff(c, d, a, b, k[10], 17, -42063);
        b = ff(b, c, d, a, k[11], 22, -1990404162);
        a = ff(a, b, c, d, k[12], 7, 1804603682);
        d = ff(d, a, b, c, k[13], 12, -40341101);
        c = ff(c, d, a, b, k[14], 17, -1502002290);
        b = ff(b, c, d, a, k[15], 22, 1236535329);
        a = gg(a, b, c, d, k[1], 5, -165796510);
        d = gg(d, a, b, c, k[6], 9, -1069501632);
        c = gg(c, d, a, b, k[11], 14, 643717713);
        b = gg(b, c, d, a, k[0], 20, -373897302);
        a = gg(a, b, c, d, k[5], 5, -701558691);
        d = gg(d, a, b, c, k[10], 9, 38016083);
        c = gg(c, d, a, b, k[15], 14, -660478335);
        b = gg(b, c, d, a, k[4], 20, -405537848);
        a = gg(a, b, c, d, k[9], 5, 568446438);
        d = gg(d, a, b, c, k[14], 9, -1019803690);
        c = gg(c, d, a, b, k[3], 14, -187363961);
        b = gg(b, c, d, a, k[8], 20, 1163531501);
        a = gg(a, b, c, d, k[13], 5, -1444681467);
        d = gg(d, a, b, c, k[2], 9, -51403784);
        c = gg(c, d, a, b, k[7], 14, 1735328473);
        b = gg(b, c, d, a, k[12], 20, -1926607734);
        a = hh(a, b, c, d, k[5], 4, -378558);
        d = hh(d, a, b, c, k[8], 11, -2022574463);
        c = hh(c, d, a, b, k[11], 16, 1839030562);
        b = hh(b, c, d, a, k[14], 23, -35309556);
        a = hh(a, b, c, d, k[1], 4, -1530992060);
        d = hh(d, a, b, c, k[4], 11, 1272893353);
        c = hh(c, d, a, b, k[7], 16, -155497632);
        b = hh(b, c, d, a, k[10], 23, -1094730640);
        a = hh(a, b, c, d, k[13], 4, 681279174);
        d = hh(d, a, b, c, k[0], 11, -358537222);
        c = hh(c, d, a, b, k[3], 16, -722521979);
        b = hh(b, c, d, a, k[6], 23, 76029189);
        a = hh(a, b, c, d, k[9], 4, -640364487);
        d = hh(d, a, b, c, k[12], 11, -421815835);
        c = hh(c, d, a, b, k[15], 16, 530742520);
        b = hh(b, c, d, a, k[2], 23, -995338651);
        a = ii(a, b, c, d, k[0], 6, -198630844);
        d = ii(d, a, b, c, k[7], 10, 1126891415);
        c = ii(c, d, a, b, k[14], 15, -1416354905);
        b = ii(b, c, d, a, k[5], 21, -57434055);
        a = ii(a, b, c, d, k[12], 6, 1700485571);
        d = ii(d, a, b, c, k[3], 10, -1894986606);
        c = ii(c, d, a, b, k[10], 15, -1051523);
        b = ii(b, c, d, a, k[1], 21, -2054922799);
        a = ii(a, b, c, d, k[8], 6, 1873313359);
        d = ii(d, a, b, c, k[15], 10, -30611744);
        c = ii(c, d, a, b, k[6], 15, -1560198380);
        b = ii(b, c, d, a, k[13], 21, 1309151649);
        a = ii(a, b, c, d, k[4], 6, -145523070);
        d = ii(d, a, b, c, k[11], 10, -1120210379);
        c = ii(c, d, a, b, k[2], 15, 718787259);
        b = ii(b, c, d, a, k[9], 21, -343485551);
        x[0] = add32(a, x[0]);
        x[1] = add32(b, x[1]);
        x[2] = add32(c, x[2]);
        x[3] = add32(d, x[3]);
    }

    function cmn(q, a, b, x, s, t) {
        a = add32(add32(a, q), add32(x, t));
        return add32((a << s) | (a >>> (32 - s)), b);
    }

    function ff(a, b, c, d, x, s, t) {
        return cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }

    function gg(a, b, c, d, x, s, t) {
        return cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }

    function hh(a, b, c, d, x, s, t) {
        return cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function ii(a, b, c, d, x, s, t) {
        return cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    function add32(a, b) {
        return (a + b) & 0xFFFFFFFF;
    }

    function md51(s) {
        const n = s.length;
        const state = [1732584193, -271733879, -1732584194, 271733878];
        let i;
        for (i = 64; i <= s.length; i += 64) {
            md5cycle(state, md5blk(s.substring(i - 64, i)));
        }
        s = s.substring(i - 64);
        const tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < s.length; i++)
            tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3);
        if (i > 55) {
            md5cycle(state, tail);
            for (i = 0; i < 16; i++) tail[i] = 0;
        }
        tail[14] = n * 8;
        md5cycle(state, tail);
        return state;
    }

    function md5blk(s) {
        const md5blks = [];
        for (let i = 0; i < 64; i += 4) {
            md5blks[i >> 2] = s.charCodeAt(i) +
                (s.charCodeAt(i + 1) << 8) +
                (s.charCodeAt(i + 2) << 16) +
                (s.charCodeAt(i + 3) << 24);
        }
        return md5blks;
    }

    const hex_chr = '0123456789abcdef'.split('');

    function rhex(n) {
        let s = '', j = 0;
        for (; j < 4; j++)
            s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] +
                hex_chr[(n >> (j * 8)) & 0x0F];
        return s;
    }

    function hex(x) {
        for (let i = 0; i < x.length; i++)
            x[i] = rhex(x[i]);
        return x.join('');
    }

    // Convert string to UTF-8 bytes for proper MD5 hashing
    function stringToUTF8Bytes(str) {
        const utf8 = unescape(encodeURIComponent(str));
        return utf8;
    }

    return hex(md51(stringToUTF8Bytes(text)));
}

/**
 * Convert ArrayBuffer to hex string
 * @param {ArrayBuffer} buffer
 * @returns {string} - Hex string
 */
function bufferToHex(buffer) {
    const byteArray = new Uint8Array(buffer);
    const hexCodes = [...byteArray].map(value => {
        const hexCode = value.toString(16);
        return hexCode.padStart(2, '0');
    });
    return hexCodes.join('');
}

/**
 * Copy specific hash to clipboard
 * @param {string} algorithm - md5, sha1, sha256, or sha512
 */
function copyHash(algorithm) {
    const input = document.getElementById(`hash-${algorithm}`);

    if (!input.value) {
        showHashMessage('No hash to copy!', 'error');
        return;
    }

    input.select();

    try {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(input.value).then(() => {
                showHashMessage(`${algorithm.toUpperCase()} hash copied to clipboard!`, 'success');
            }).catch(() => {
                document.execCommand('copy');
                showHashMessage(`${algorithm.toUpperCase()} hash copied to clipboard!`, 'success');
            });
        } else {
            document.execCommand('copy');
            showHashMessage(`${algorithm.toUpperCase()} hash copied to clipboard!`, 'success');
        }
    } catch (error) {
        showHashMessage('Failed to copy to clipboard', 'error');
    }
}

/**
 * Clear all hash fields
 */
function clearHash() {
    document.getElementById('hash-input').value = '';
    clearAllHashes();
    clearHashMessage();
}

/**
 * Clear all hash output fields
 */
function clearAllHashes() {
    document.getElementById('hash-md5').value = '';
    document.getElementById('hash-sha1').value = '';
    document.getElementById('hash-sha256').value = '';
    document.getElementById('hash-sha512').value = '';
}

/**
 * Show message to user
 * @param {string} text - Message text
 * @param {string} type - Message type (success, error, info)
 */
function showHashMessage(text, type = 'info') {
    const messageDiv = document.getElementById('hash-message');
    messageDiv.textContent = text;
    messageDiv.className = `tool-message ${type}`;
    messageDiv.style.display = 'block';

    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 3000);
}

/**
 * Clear message
 */
function clearHashMessage() {
    const messageDiv = document.getElementById('hash-message');
    messageDiv.style.display = 'none';
}

// Generate hashes on page load
window.addEventListener('DOMContentLoaded', () => {
    generateAllHashes();
});
