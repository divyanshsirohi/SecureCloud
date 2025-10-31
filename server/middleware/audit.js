/**
 * Audit logging middleware and utilities
 * Tracks all security-relevant operations
 */
const { pool } = require('../db');

/**
 * Request logging middleware
 * Logs all incoming requests
 */
function requestLogger(req, res, next) {
    const startTime = Date.now();

    // Log request
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${req.ip}`);

    // Capture response
    const originalSend = res.send;
    res.send = function(data) {
        res.send = originalSend;
        const duration = Date.now() - startTime;

        console.log(
            `[${new Date().toISOString()}] ${req.method} ${req.path} - ` +
            `Status: ${res.statusCode} - Duration: ${duration}ms`
        );

        return res.send(data);
    };

    next();
}

/**
 * Log audit event to database
 * @param {Object} data - Audit log data
 */
async function logAudit(data) {
    try {
        await pool.query(`
      INSERT INTO audit_logs (
        user_id, 
        file_id, 
        action, 
        ip_address, 
        user_agent,
        encryption_time_ms, 
        decryption_time_ms, 
        key_generation_time_ms,
        avalanche_effect_percentage, 
        collision_resistance_score,
        signature_verification_time_ms, 
        file_size_bytes,
        encryption_algorithm, 
        key_size, 
        metadata, 
        success, 
        error_message
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
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
            data.metadata ? JSON.stringify(data.metadata) : null,
            data.success !== false,
            data.errorMessage || null
        ]);

        // Log to console in development
        if (process.env.NODE_ENV === 'development') {
            console.log(`[AUDIT] ${data.action} - User: ${data.userId || 'Anonymous'} - Success: ${data.success !== false}`);
        }

    } catch (error) {
        // Don't throw - audit logging failure shouldn't break app flow
        console.error('Audit logging error:', error);
    }
}

/**
 * Create audit middleware for specific actions
 * @param {string} action - Action name
 */
function auditMiddleware(action) {
    return async (req, res, next) => {
        const startTime = Date.now();

        // Capture original json method
        const originalJson = res.json;

        res.json = function(data) {
            const duration = Date.now() - startTime;
            const success = res.statusCode >= 200 && res.statusCode < 400;

            // Log audit asynchronously
            logAudit({
                userId: req.user?.userId,
                fileId: req.params?.fileId,
                action,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                encryptionTime: duration,
                metadata: {
                    method: req.method,
                    path: req.path,
                    statusCode: res.statusCode
                },
                success,
                errorMessage: !success ? data.error : null
            }).catch(console.error);

            return originalJson.call(this, data);
        };

        next();
    };
}

/**
 * Cleanup old audit logs (called periodically)
 * @param {number} retentionDays - Days to keep logs
 */
async function cleanupOldLogs(retentionDays = 90) {
    try {
        const result = await pool.query(`
      DELETE FROM audit_logs
      WHERE timestamp < NOW() - INTERVAL '${retentionDays} days'
      RETURNING log_id
    `);

        console.log(`Cleaned up ${result.rowCount} old audit logs`);
        return result.rowCount;

    } catch (error) {
        console.error('Audit cleanup error:', error);
        throw error;
    }
}

module.exports = {
    requestLogger,
    logAudit,
    auditMiddleware,
    cleanupOldLogs,
};
