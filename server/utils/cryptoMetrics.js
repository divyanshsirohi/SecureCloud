// SecurityMetrics.js
// Minimal, robust security scoring module for encryption quality + practical crypto hygiene.
// Only builtin dependency: crypto

const crypto = require('crypto');

/* -------------------------
   Utilities
   ------------------------- */
const POPCNT = new Uint8Array(256);
for (let i = 0; i < 256; i++) POPCNT[i] = i.toString(2).split('1').length - 1;

function safeBuffer(input) {
    if (Buffer.isBuffer(input)) return input;
    if (typeof input === 'string') return Buffer.from(input, 'utf8');
    if (input instanceof ArrayBuffer) return Buffer.from(new Uint8Array(input));
    throw new TypeError('Input must be Buffer, string, or ArrayBuffer');
}

function clamp01(x) { return Math.max(0, Math.min(1, x)); }

/* -------------------------
   Entropy (Shannon) per byte (0..8)
   ------------------------- */
function calculateBufferEntropy(buf) {
    try {
        buf = safeBuffer(buf);
        if (buf.length === 0) return 0;
        const freq = new Array(256).fill(0);
        for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] === 0) continue;
            const p = freq[i] / buf.length;
            entropy -= p * Math.log2(p);
        }
        return entropy; // 0..8
    } catch (e) {
        return 0;
    }
}

/* -------------------------
   Avalanche effect (%)
   Use actual bytes: flip a single bit in the input and compare hashes
   ------------------------- */
function calculateAvalancheEffect(original, modified, hashAlg = 'sha256') {
    try {
        const h1 = crypto.createHash(hashAlg).update(safeBuffer(original)).digest();
        const h2 = crypto.createHash(hashAlg).update(safeBuffer(modified)).digest();
        if (h1.length !== h2.length) return 0;
        const totalBits = h1.length * 8;
        let diffBits = 0;
        for (let i = 0; i < h1.length; i++) {
            diffBits += POPCNT[h1[i] ^ h2[i]];
        }
        return (diffBits / totalBits) * 100;
    } catch (e) {
        return 0;
    }
}

/* -------------------------
   Collision resistance: Chi-square uniformity on hash bytes -> normalized 0..100
   ------------------------- */
function calculateCollisionResistanceScore(data, hashAlg = 'sha256') {
    try {
        const hash = crypto.createHash(hashAlg).update(safeBuffer(data)).digest();
        const n = hash.length;
        if (n === 0) return 0;
        const freq = new Array(256).fill(0);
        for (let i = 0; i < n; i++) freq[hash[i]]++;
        const expected = n / 256;
        let chiSq = 0;
        for (let i = 0; i < 256; i++) {
            const d = freq[i] - expected;
            chiSq += (d * d) / (expected || 1);
        }
        // Heuristic normalization:
        // For 256 buckets df ~= 255, ideal chiSq ~ 255. Use that to produce 0..100.
        const ideal = 255;
        // avoid division by 0
        let raw = ideal / (chiSq || ideal);
        // map to 0..1 with diminishing returns
        raw = clamp01(raw * 0.95 + 0.05);
        return parseFloat((raw * 100).toFixed(2));
    } catch (e) {
        return 0;
    }
}

/* -------------------------
   Cipher mode rating (simple, deterministic)
   Input: mode string (e.g., 'aes-256-gcm', 'aes-128-cbc', 'chacha20-poly1305')
   Returns: { rating: 'Excellent'|'Good'|'Weak'|'Unsafe', score: 0-100 }
   ------------------------- */
function rateCipherMode(modeStr = '') {
    try {
        const s = ('' + modeStr).toLowerCase();
        if (!s) return { rating: 'Unknown', score: 50 };
        if (s.includes('gcm') || s.includes('cha') || s.includes('poly1305')) return { rating: 'Excellent', score: 95 };
        if (s.includes('ctr') || s.includes('xccm')) return { rating: 'Good', score: 80 };
        if (s.includes('cbc')) return { rating: 'Weak', score: 55 };
        if (s.includes('ecb')) return { rating: 'Unsafe', score: 10 };
        return { rating: 'Unknown', score: 60 };
    } catch (e) {
        return { rating: 'Unknown', score: 50 };
    }
}

/* -------------------------
   Integrity / AEAD check
   Returns boolean if mode appears to be AEAD
   ------------------------- */
function hasIntegrity(modeStr = '') {
    const s = ('' + modeStr).toLowerCase();
    return s.includes('gcm') || s.includes('ccm') || s.includes('poly1305') || s.includes('aead');
}

/* -------------------------
   KDF strength scoring
   Input: { algo: 'pbkdf2'|'scrypt'|'argon2id'|'bcrypt', params: {...} }
   Returns 0..100
   ------------------------- */
function scoreKDF(kdf = {}) {
    try {
        if (!kdf || typeof kdf !== 'object') return 0;
        const algo = (kdf.algo || '').toLowerCase();
        const p = kdf.params || {};
        if (algo === 'argon2id') {
            // params: timeCost, memoryKB, parallelism
            const time = Math.max(1, p.timeCost || 1);
            const mem = Math.max(1, p.memoryKB || (64 * 1024)); // default 64MB
            const par = Math.max(1, p.parallelism || 1);
            // heuristic: prefer memory and time
            const score = clamp01((Math.log2(mem) / 16) * 0.6 + (time / 3) * 0.35 + (par / 4) * 0.05);
            return parseFloat((score * 100).toFixed(2));
        }
        if (algo === 'scrypt') {
            // params: N, r, p
            const N = p.N || 16384;
            const score = clamp01(Math.log2(N) / 20); // N=2^14 ~ 0.7
            return parseFloat((score * 100).toFixed(2));
        }
        if (algo === 'pbkdf2') {
            const iter = p.iterations || 10000;
            return parseFloat(clamp01(iter / 200000) * 100 .toFixed(2));
        }
        if (algo === 'bcrypt') {
            const cost = p.cost || 10;
            return parseFloat(clamp01(cost / 16) * 100 .toFixed(2));
        }
        // Unknown algorithm: conservative mid score
        return 50;
    } catch (e) {
        return 0;
    }
}

/* -------------------------
   Nonce/IV reuse detector
   Input: array of objects: [{ keyFingerprint: 'hex', iv: Buffer|string }, ...]
   Returns: { reuseCount, reusedPairs: [ { key, iv, occurrences } ], verdict }
   ------------------------- */
function detectNonceReuse(records = []) {
    try {
        if (!Array.isArray(records)) return { reuseCount: 0, reusedPairs: [], verdict: 'invalid input' };
        const map = new Map();
        for (const r of records) {
            if (!r) continue;
            const key = (r.keyFingerprint || '').toString();
            let iv;
            try { iv = safeBuffer(r.iv).toString('hex'); } catch { iv = String(r.iv || ''); }
            const id = `${key}:${iv}`;
            map.set(id, (map.get(id) || 0) + 1);
        }
        const reused = [];
        let reuseCount = 0;
        for (const [k, v] of map.entries()) {
            if (v > 1) {
                reuseCount += v - 1;
                const [key, iv] = k.split(':');
                reused.push({ key, iv, occurrences: v });
            }
        }
        return { reuseCount, reusedPairs: reused, verdict: reuseCount > 0 ? 'nonce reuse detected' : 'ok' };
    } catch (e) {
        return { reuseCount: 0, reusedPairs: [], verdict: 'error' };
    }
}

/* -------------------------
   Key rotation scoring
   Input: { lastRotationDays: number, rotationPolicyExists: boolean }
   Returns 0..100
   ------------------------- */
function scoreKeyRotation(meta = {}) {
    try {
        const days = Number.isFinite(meta.lastRotationDays) ? meta.lastRotationDays : 99999;
        const policy = !!meta.rotationPolicyExists;
        // ideal rotation <= 90 days
        const freshness = clamp01(1 - (days / 365)); // 0..1
        const score = (freshness * 0.7 + (policy ? 0.3 : 0)) * 100;
        return parseFloat(score.toFixed(2));
    } catch (e) {
        return 0;
    }
}

/* -------------------------
   Overall quality aggregator
   Inputs: prepared metric numbers (0..100 or entropy 0..8)
   ------------------------- */
function assessQuality(metrics) {
    try {
        // normalize entropy (0..8) to 0..100
        const entropyScore = clamp01((metrics.entropy || 0) / 8) * 100;
        const avalancheScore = clamp01((metrics.avalanche || 0) / 100) * 100;
        const collisionScore = clamp01((metrics.collision || 0) / 100) * 100;
        const cipherScore = clamp01((metrics.cipher || 50) / 100) * 100;
        const kdfScore = clamp01((metrics.kdf || 50) / 100) * 100;
        const rotationScore = clamp01((metrics.rotation || 0) / 100) * 100;
        // Weighted aggregate (tuneable)
        const overall = (entropyScore * 0.25) + (avalancheScore * 0.20) + (collisionScore * 0.20) + (cipherScore * 0.15) + (kdfScore * 0.10) + (rotationScore * 0.10);
        const overallRound = parseFloat(overall.toFixed(2));
        let grade = 'poor';
        if (overallRound >= 90) grade = 'excellent';
        else if (overallRound >= 75) grade = 'good';
        else if (overallRound >= 60) grade = 'acceptable';
        return { overallScore: overallRound, grade };
    } catch (e) {
        return { overallScore: 0, grade: 'poor' };
    }
}

/* -------------------------
   Fingerprint helpers
   ------------------------- */
function generateFingerprint(data, hashAlg = 'sha256') {
    try {
        return crypto.createHash(hashAlg).update(safeBuffer(data)).digest('hex');
    } catch (e) {
        return '';
    }
}

/* -------------------------
   Main convenient API:
   generateReport(options)
   options = {
     samplePlaintext: Buffer|string, // optional: used to compute avalanche by flipping 1 bit
     sampleEncrypted: Buffer|string, // encrypted buffer sample (for entropy, collision)
     cipherMode: 'aes-256-gcm'|'aes-128-cbc'|...,
     kdf: { algo: 'argon2id', params: {...} },
     ivRecords: [ { keyFingerprint: '...', iv: Buffer }, ... ],
     keyRotationMeta: { lastRotationDays: 120, rotationPolicyExists: true },
     hashAlg: 'sha256'
   }
   ------------------------- */
function generateReport(options = {}) {
    try {
        const hashAlg = options.hashAlg || 'sha256';
        // Entropy & collision operate on encrypted sample if present
        const enc = options.sampleEncrypted ? safeBuffer(options.sampleEncrypted) : Buffer.alloc(0);
        const plaintext = options.samplePlaintext !== undefined ? safeBuffer(options.samplePlaintext) : null;

        const entropy = enc.length ? calculateBufferEntropy(enc) : 0;
        const collision = enc.length ? calculateCollisionResistanceScore(enc, hashAlg) : 0;

        // Avalanche: if plaintext provided, create a single-bit flip variant (robust)
        let avalanche = 0;
        if (plaintext) {
            const modified = Buffer.from(plaintext);
            // flip lowest-order bit of last byte (safe and deterministic)
            if (modified.length > 0) modified[modified.length - 1] ^= 1;
            avalanche = calculateAvalancheEffect(plaintext, modified, hashAlg);
        }

        const cipher = rateCipherMode(options.cipherMode || '');
        const integrity = hasIntegrity(options.cipherMode || '');
        const kdfScore = scoreKDF(options.kdf || {});
        const nonceReport = detectNonceReuse(options.ivRecords || []);
        const rotationScore = scoreKeyRotation(options.keyRotationMeta || {});

        const metrics = {
            entropy: parseFloat(entropy.toFixed(6)),
            collision: parseFloat(collision.toFixed(2)),
            avalanche: parseFloat(avalanche.toFixed(2)),
            cipherMode: (options.cipherMode || '').toString(),
            cipherModeRating: cipher.rating,
            cipherModeScore: cipher.score,
            integrityProtected: !!integrity,
            kdfScore,
            nonceReuse: nonceReport,
            rotationScore
        };

        const quality = assessQuality({
            entropy: metrics.entropy,
            avalanche: metrics.avalanche,
            collision: metrics.collision,
            cipher: metrics.cipherModeScore,
            kdf: metrics.kdfScore,
            rotation: metrics.rotationScore
        });

        return {
            generatedAt: new Date().toISOString(),
            fingerprintOfSample: enc.length ? generateFingerprint(enc, hashAlg) : '',
            metrics,
            quality
        };
    } catch (e) {
        return { error: 'report generation failed' };
    }
}

/* -------------------------
   Exports
   ------------------------- */
module.exports = {
    calculateBufferEntropy,
    calculateAvalancheEffect,
    calculateCollisionResistanceScore,
    rateCipherMode,
    hasIntegrity,
    scoreKDF,
    detectNonceReuse,
    scoreKeyRotation,
    generateFingerprint,
    assessQuality,
    generateReport
};
