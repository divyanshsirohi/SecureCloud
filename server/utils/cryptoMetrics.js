/**
 * Cryptographic metrics and analysis utilities
 * Measures encryption quality and performance
 */
const crypto = require('crypto');

/**
 * Calculate avalanche effect
 * Measures how changing one bit in input affects output
 * Good encryption should change ~50% of bits
 *
 * @param {Buffer|string} original - Original data
 * @param {Buffer|string} modified - Modified data (1 bit difference)
 * @returns {number} Percentage of bits changed (ideal: ~50%)
 */
function calculateAvalancheEffect(original, modified) {
    try {
        // Hash both inputs
        const hash1 = crypto.createHash('sha256').update(original).digest();
        const hash2 = crypto.createHash('sha256').update(modified).digest();

        let differentBits = 0;
        const totalBits = hash1.length * 8;

        // Count differing bits using XOR
        for (let i = 0; i < hash1.length; i++) {
            const xor = hash1[i] ^ hash2[i];
            // Count set bits in XOR result
            differentBits += xor.toString(2).split('1').length - 1;
        }

        // Return percentage
        return (differentBits / totalBits) * 100;

    } catch (error) {
        console.error('Avalanche effect calculation error:', error);
        return 0;
    }
}

/**
 * Calculate collision resistance score using Chi-Square test for uniformity
 * Score range: 0 - 100 (higher = better)
 *
 * @param {Buffer|string} data - Data to hash
 * @returns {number} Collision resistance score
 */
function calculateCollisionResistance(data) {
    try {
        const hash = crypto.createHash('sha256').update(data).digest();

        const freq = new Array(256).fill(0);
        const n = hash.length;

        for (let i = 0; i < n; i++) {
            freq[hash[i]]++;
        }

        // Expected frequency for uniform distribution
        const expected = n / 256;

        // Chi-Square calculation
        let chiSquare = 0;
        for (let i = 0; i < 256; i++) {
            const diff = freq[i] - expected;
            chiSquare += (diff * diff) / expected;
        }

        // Normalize score: lower chi-square = more uniform = more random
        // Ideal Chi-square for uniform distribution with 255 df ~ 255
        const ideal = 255;
        let score = (ideal / chiSquare) * 100;

        // Trim to 0–100 range
        if (score > 100) score = 100;
        if (score < 0) score = 0;

        return parseFloat(score.toFixed(2));

    } catch (error) {
        console.error('Collision resistance calculation error:', error);
        return 0;
    }
}


/**
 * Analyze encryption quality of a buffer
 * @param {Buffer} buffer - Encrypted data buffer
 * @returns {Object} Encryption quality metrics
 */
function analyzeEncryptionQuality(buffer) {
    try {
        // Sample first 1KB for analysis (or entire buffer if smaller)
        const sampleSize = Math.min(1024, buffer.length);
        const sample = buffer.slice(0, sampleSize);

        // Calculate metrics
        const testData = sample.toString('hex');
        const modifiedData = testData.substring(0, testData.length - 1) +
            (testData[testData.length - 1] === '0' ? '1' : '0');

        const avalancheEffect = calculateAvalancheEffect(testData, modifiedData);
        const collisionResistance = calculateCollisionResistance(buffer);
        const entropy = calculateBufferEntropy(sample);

        return {
            avalancheEffect: parseFloat(avalancheEffect.toFixed(2)),
            collisionResistance: parseFloat(collisionResistance.toFixed(6)),
            entropy: parseFloat(entropy.toFixed(6)),
            quality: assessQuality(avalancheEffect, collisionResistance, entropy)
        };

    } catch (error) {
        console.error('Encryption quality analysis error:', error);
        return {
            avalancheEffect: 0,
            collisionResistance: 0,
            entropy: 0,
            quality: 'unknown'
        };
    }
}

/**
 * Calculate buffer entropy
 * @param {Buffer} buffer - Data buffer
 * @returns {number} Entropy value
 */
function calculateBufferEntropy(buffer) {
    const freq = new Array(256).fill(0);

    for (let i = 0; i < buffer.length; i++) {
        freq[buffer[i]]++;
    }

    let entropy = 0;
    for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            const p = freq[i] / buffer.length;
            entropy -= p * Math.log2(p);
        }
    }

    return entropy;
}

/**
 * Assess overall encryption quality
 * @param {number} avalanche - Avalanche effect percentage
 * @param {number} collision - Collision resistance score
 * @param {number} entropy - Entropy value
 * @returns {string} Quality assessment
 */
function assessQuality(avalanche, collision, entropy) {
    // Ideal avalanche effect is ~50%
    const avalancheScore = 100 - Math.abs(avalanche - 50) * 2;

    // Ideal collision resistance is close to 8.0
    const collisionScore = (collision / 8.0) * 100;

    // Ideal entropy is close to 8.0
    const entropyScore = (entropy / 8.0) * 100;

    const overallScore = (avalancheScore + collisionScore + entropyScore) / 3;

    if (overallScore >= 90) return 'excellent';
    if (overallScore >= 75) return 'good';
    if (overallScore >= 60) return 'acceptable';
    return 'poor';
}

/**
 * Generate cryptographic fingerprint of data
 * @param {Buffer} data - Data to fingerprint
 * @returns {string} SHA-256 hash hex string
 */
function generateFingerprint(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Verify data integrity using fingerprint
 * @param {Buffer} data - Data to verify
 * @param {string} expectedFingerprint - Expected fingerprint
 * @returns {boolean} True if data matches fingerprint
 */
function verifyFingerprint(data, expectedFingerprint) {
    const actualFingerprint = generateFingerprint(data);
    return actualFingerprint === expectedFingerprint;
}

/**
 * Time a cryptographic operation
 * @param {Function} operation - Async operation to time
 * @returns {Promise<{result: any, durationMs: number}>}
 */
async function timeCryptoOperation(operation) {
    const startTime = Date.now();
    const result = await operation();
    const durationMs = Date.now() - startTime;

    return { result, durationMs };
}

module.exports = {
    calculateAvalancheEffect,
    calculateCollisionResistance,
    analyzeEncryptionQuality,
    calculateBufferEntropy,
    generateFingerprint,
    verifyFingerprint,
    timeCryptoOperation,
};
