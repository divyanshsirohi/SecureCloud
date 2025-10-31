/**
 * Token generation and validation utilities
 * Handles session tokens and cryptographic operations
 */
const crypto = require('crypto');
const config = require('../config');

/**
 * Generate secure random token
 * @param {number} length - Token length in bytes (default: 32)
 * @returns {string} Hex-encoded random token
 */
function generateToken(length = config.security.tokenLength) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash token for storage
 * Uses SHA-256 for fast, secure hashing
 * @param {string} token - Token to hash
 * @returns {string} Hex-encoded hash
 */
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Generate secure random bytes
 * @param {number} length - Number of bytes
 * @returns {Buffer} Random bytes
 */
function generateRandomBytes(length) {
    return crypto.randomBytes(length);
}

/**
 * Generate HMAC signature
 * @param {string|Buffer} data - Data to sign
 * @param {string} secret - Secret key
 * @returns {string} Hex-encoded HMAC
 */
function generateHMAC(data, secret) {
    return crypto
        .createHmac('sha256', secret)
        .update(data)
        .digest('hex');
}

/**
 * Verify HMAC signature
 * @param {string|Buffer} data - Data to verify
 * @param {string} signature - Expected signature
 * @param {string} secret - Secret key
 * @returns {boolean} True if signature is valid
 */
function verifyHMAC(data, signature, secret) {
    const expectedSignature = generateHMAC(data, secret);

    // Use timing-safe comparison
    return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
    );
}

/**
 * Generate session token with metadata
 * @param {string} userId - User ID
 * @param {Object} metadata - Additional metadata
 * @returns {Object} Token object with token and expiry
 */
function generateSessionToken(userId, metadata = {}) {
    const token = generateToken();
    const tokenHash = hashToken(token);

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + config.security.sessionExpiryHours);

    return {
        token,
        tokenHash,
        expiresAt,
        userId,
        metadata
    };
}

/**
 * Generate API key (longer, more secure token)
 * @returns {string} API key
 */
function generateApiKey() {
    const prefix = 'sk'; // Secret key prefix
    const randomPart = generateToken(48); // 48 bytes = 96 hex chars
    return `${prefix}_${randomPart}`;
}

/**
 * Constant-time string comparison
 * Prevents timing attacks
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if strings are equal
 */
function timingSafeEqual(a, b) {
    try {
        return crypto.timingSafeEqual(
            Buffer.from(a),
            Buffer.from(b)
        );
    } catch (error) {
        // Lengths don't match
        return false;
    }
}

/**
 * Generate unique file identifier
 * @returns {string} UUID v4
 */
function generateFileId() {
    return crypto.randomUUID();
}

/**
 * Generate nonce for encryption
 * @param {number} length - Nonce length in bytes (default: 12 for GCM)
 * @returns {Buffer} Random nonce
 */
function generateNonce(length = 12) {
    return crypto.randomBytes(length);
}

/**
 * Derive key from password using PBKDF2
 * @param {string} password - Password
 * @param {Buffer|string} salt - Salt
 * @param {number} iterations - Number of iterations
 * @param {number} keyLength - Derived key length
 * @returns {Promise<Buffer>} Derived key
 */
function deriveKey(password, salt, iterations = 100000, keyLength = 32) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, iterations, keyLength, 'sha256', (err, key) => {
            if (err) reject(err);
            else resolve(key);
        });
    });
}

module.exports = {
    generateToken,
    hashToken,
    generateRandomBytes,
    generateHMAC,
    verifyHMAC,
    generateSessionToken,
    generateApiKey,
    timingSafeEqual,
    generateFileId,
    generateNonce,
    deriveKey,
};
