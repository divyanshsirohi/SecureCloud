/**
 * Audit logging middleware and utilities
 * Tracks all security-relevant operations with security metrics
 */

const { pool } = require('../db');
const SecurityMetrics = require('../utils/cryptoMetrics'); // make sure path matches your project

/**
 * Request logging middleware (low impact)
 */
function requestLogger(req, res, next) {
    const startTime = Date.now();

    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${req.ip}`);

    const originalSend = res.send;
    res.send = function(data) {
        res.send = originalSend;
        const duration = Date.now() - startTime;

        console.log(
            `[${new Date().toISOString()}] ${req.method} ${req.path} ` +
            `Status: ${res.statusCode} - ${duration}ms`
        );

        return res.send(data);
    };

    next();
}

/**
 * Log audit event to DB with security scorecard support
 */
async function logAudit(data = {}) {
    try {
        const metadata = data.metadata || {};

        // If encrypted sample exists in metadata => run security scorecard
        if (metadata.sampleEncrypted) {
            try {
                metadata.securityReport = SecurityMetrics.generateReport({
                    samplePlaintext: metadata.samplePlaintext,
                    sampleEncrypted: metadata.sampleEncrypted,
                    cipherMode: data.encryptionAlgorithm || 'aes-256-gcm',
                    kdf: metadata.kdf,
                    ivRecords: metadata.ivRecords,
                    keyRotationMeta: metadata.keyRotationMeta
                });
            } catch (err) {
                console.error('Security report generation failed:', err);
            }

            // Cleaning large buffers
            delete metadata.sampleEncrypted;
            delete metadata.samplePlaintext;
        }

        await pool.query(`
            INSERT INTO audit_logs (
                user_id, file_id, action, ip_address, user_agent,
                encryption_time_ms, decryption_time_ms, key_generation_time_ms,
                avalanche_effect_percentage, collision_resistance_score,
                signature_verification_time_ms, file_size_bytes,
                encryption_algorithm, key_size, metadata, success, error_message
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
        `, [
            data.userId || null,
            data.fileId || null,
            data.action,
            data.ipAddress || null,
            data.userAgent || null,
            data.encryptionTime || null,
            data.decryptionTime || null,
            data.keyGenerationTime || null,
            data.avalancheEffect || null,
            data.collisionResistance || null,
            data.signatureVerificationTime || null,
            data.fileSize || null,
            data.encryptionAlgorithm || 'AES-256-GCM',
            data.keySize || 256,
            metadata ? JSON.stringify(metadata) : null,
            data.success !== false,
            data.errorMessage || null
        ]);

        if (process.env.NODE_ENV === 'development') {
            console.log(`[AUDIT] ${data.action} | User: ${data.userId || 'Anon'} | Success: ${data.success !== false}`);
        }

    } catch (error) {
        console.error('Audit logging error:', error); // Never throw — audit must not break flow
    }
}

/**
 * Middleware to auto-audit an action
 */
function auditMiddleware(action) {
    return (req, res, next) => {
        const startTime = Date.now();
        const originalJson = res.json;

        res.json = function(responseBody) {
            res.json = originalJson;
            const duration = Date.now() - startTime;
            const success = res.statusCode >= 200 && res.statusCode < 400;

            logAudit({
                userId: req.user?.userId,
                fileId: req.params?.fileId,
                action,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                encryptionTime: duration,
                success,
                errorMessage: !success ? responseBody?.error : null,
                metadata: {
                    method: req.method,
                    path: req.path,
                    statusCode: res.statusCode,
                    // Attach security-related values when available
                    cipherMode: req.cipherMode,
                    kdf: req.kdfParams,
                    ivRecords: req.ivRecords,
                    keyRotationMeta: req.keyRotationMeta
                }
            }).catch(console.error);

            return originalJson.call(this, responseBody);
        };

        next();
    };
}

/**
 * Cleanup old logs
 */
async function cleanupOldLogs(retentionDays = 90) {
    try {
        const result = await pool.query(`
            DELETE FROM audit_logs
            WHERE timestamp < NOW() - INTERVAL '${retentionDays} days'
            RETURNING log_id
        `);

        console.log(`Cleaned ${result.rowCount} old logs`);
        return result.rowCount;

    } catch (error) {
        console.error('Audit cleanup error:', error);
        return 0;
    }
}

module.exports = {
    requestLogger,
    logAudit,
    auditMiddleware,
    cleanupOldLogs
};
