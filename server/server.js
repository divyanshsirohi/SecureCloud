/**
 * Main server entry point
 * Secure Cloud Storage Backend
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const path = require('path');

const config = require('./config');
const { initializeDatabase, closePool } = require('./db');
const { requestLogger } = require('./middleware/audit');
const { apiLimiter } = require('./middleware/rateLimit');
const { testConnection } = require('./utils/s3');

// Initialize Express
const app = express();

// Trust proxy for Render load balancer
app.set('trust proxy', 1);

// ============================================
// SECURITY, CORS, BODY PARSING, LOGGING
// ============================================

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", "data:", "https:"],
            },
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
        },
    })
);

app.use(
    cors({
        origin: config.FRONTEND_URL,
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
    })
);

app.use(express.json({ limit: config.upload.requestSizeLimit }));
app.use(express.urlencoded({ extended: true, limit: config.upload.requestSizeLimit }));
app.use(compression());
app.use(requestLogger);
app.use('/api/', apiLimiter);

// ============================================
// FRONTEND STATIC SERVING (Render Compatible)
// ============================================

// Serve static files from frontend directory
app.use(express.static(path.join(__dirname, '../frontend')));

// Catch-all for frontend routes (must come BEFORE API routes)
app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();

    const acceptsHTML = req.headers.accept && req.headers.accept.includes('text/html');
    if (!acceptsHTML) {
        return res.json({
            name: 'Secure Cloud Storage API',
            version: '1.0.0',
            status: 'operational',
            timestamp: new Date().toISOString(),
            endpoints: {
                auth: '/api/auth',
                files: '/api/files',
                shares: '/api/shares',
                audit: '/api/audit',
                stats: '/api/stats'
            },
            documentation: '/api/docs'
        });
    }

    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ============================================
// API ROUTES
// ============================================

const authRoutes = require('./routes/auth');
const filesRoutes = require('./routes/files');
const sharesRoutes = require('./routes/shares');
const { authenticate } = require('./middleware/auth');
const { pool } = require('./db');

app.use('/api/auth', authRoutes);
app.use('/api/files', filesRoutes);
app.use('/api/shares', sharesRoutes);

// ------- AUDIT LOG ROUTES -------
app.get('/api/audit', authenticate, async (req, res) => {
    try {
        const { page = 1, limit = 50, action, startDate, endDate } = req.query;
        const offset = (page - 1) * limit;

        let conditions = ['user_id = $1'];
        let params = [req.user.userId, limit, offset];
        let paramIndex = 4;

        if (action) {
            conditions.push(`action = $${paramIndex}`);
            params.push(action);
            paramIndex++;
        }
        if (startDate) {
            conditions.push(`timestamp >= $${paramIndex}`);
            params.push(startDate);
            paramIndex++;
        }
        if (endDate) {
            conditions.push(`timestamp <= $${paramIndex}`);
            params.push(endDate);
            paramIndex++;
        }

        const whereClause = conditions.join(' AND');

        const logsResult = await pool.query(`
            SELECT log_id, action, timestamp, ip_address, encryption_time_ms,
                   decryption_time_ms, key_generation_time_ms, avalanche_effect_percentage,
                   collision_resistance_score, file_size_bytes, success, error_message, metadata
            FROM audit_logs
            WHERE ${whereClause}
            ORDER BY timestamp DESC
            LIMIT $2 OFFSET $3
        `, params);

        const total = (
            await pool.query(`SELECT COUNT(*) AS total FROM audit_logs WHERE ${whereClause}`, params.slice(0, paramIndex - 1))
        ).rows[0].total;

        res.json({
            logs: logsResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: parseInt(total),
                totalPages: Math.ceil(total / limit),
            },
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to retrieve audit logs', code: 'GET_AUDIT_ERROR' });
    }
});

// ------- EXPORT AUDIT -------
app.get('/api/audit/export', authenticate, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        let conditions = ['user_id = $1'];
        let params = [req.user.userId];
        let paramIndex = 2;

        if (startDate) {
            conditions.push(`timestamp >= $${paramIndex}`);
            params.push(startDate);
            paramIndex++;
        }
        if (endDate) {
            conditions.push(`timestamp <= $${paramIndex}`);
            params.push(endDate);
            paramIndex++;
        }

        const logsResult = await pool.query(`
            SELECT timestamp, action, file_id, ip_address, encryption_time_ms,
                   avalanche_effect_percentage, collision_resistance_score,
                   file_size_bytes, success, error_message
            FROM audit_logs
            WHERE ${conditions.join(' AND')}
            ORDER BY timestamp DESC
            LIMIT ${config.audit.exportMaxRecords}
        `, params);

        const headers = [
            'Timestamp', 'Action', 'File ID', 'IP Address', 'Encryption Time (ms)',
            'Avalanche Effect (%)', 'Collision Resistance', 'File Size (bytes)', 'Success', 'Error'
        ];

        const csv = [
            headers.join(','),
            ...logsResult.rows.map(log => [
                log.timestamp,
                log.action,
                log.file_id || '',
                log.ip_address || '',
                log.encryption_time_ms || '',
                log.avalanche_effect_percentage || '',
                log.collision_resistance_score || '',
                log.file_size_bytes || '',
                log.success ? 'Yes' : 'No',
                log.error_message ? `"${log.error_message.replace(/"/g, '""')}"` : ''
            ].join(','))
        ].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=audit-logs-${Date.now()}.csv`);
        res.send(csv);
    } catch (error) {
        res.status(500).json({ error: 'Failed to export audit logs', code: 'EXPORT_AUDIT_ERROR' });
    }
});

// ------- STATS -------
app.get('/api/stats', authenticate, async (req, res) => {
    try {
        const fileStatsQuery = `
            SELECT COUNT(*) AS total_files, SUM(file_size) AS total_size, AVG(file_size) AS avg_file_size,
                   COUNT(DISTINCT mime_type) AS file_types
            FROM files
            WHERE owner_id = $1 AND is_deleted = FALSE
        `;
        const actionStatsQuery = `
            SELECT action, COUNT(*) AS count, AVG(encryption_time_ms) AS avg_time,
                   COUNT(CASE WHEN success = TRUE THEN 1 END) AS success_count,
                   COUNT(CASE WHEN success = FALSE THEN 1 END) AS error_count
            FROM audit_logs
            WHERE user_id = $1 AND timestamp > NOW() - INTERVAL '30 days'
            GROUP BY action ORDER BY count DESC LIMIT 10
        `;
        const metricsQuery = `
            SELECT AVG(avalanche_effect_percentage) AS avg_avalanche,
                   AVG(collision_resistance_score) AS avg_collision,
                   AVG(encryption_time_ms) AS avg_encryption_time,
                   AVG(file_size_bytes) AS avg_file_size
            FROM audit_logs
            WHERE user_id = $1 AND action IN ('FILE_UPLOAD', 'FILE_DOWNLOAD')
                  AND timestamp > NOW() - INTERVAL '30 days'
        `;
        const shareStatsQuery = `
            SELECT COUNT(CASE WHEN owner_id = $1 AND is_active = TRUE THEN 1 END) AS active_shares_sent,
                   COUNT(CASE WHEN recipient_id = $1 AND is_active = TRUE THEN 1 END) AS active_shares_received
            FROM file_shares
        `;

        const fileStats = (await pool.query(fileStatsQuery, [req.user.userId])).rows[0];
        const actionStats = (await pool.query(actionStatsQuery, [req.user.userId])).rows;
        const metrics = (await pool.query(metricsQuery, [req.user.userId])).rows[0];
        const shares = (await pool.query(shareStatsQuery, [req.user.userId])).rows[0];

        res.json({
            files: {
                total: parseInt(fileStats.total_files),
                totalSize: parseInt(fileStats.total_size || 0),
                averageSize: parseFloat(fileStats.avg_file_size || 0),
                fileTypes: parseInt(fileStats.file_types),
            },
            shares: {
                sent: parseInt(shares.active_shares_sent),
                received: parseInt(shares.active_shares_received),
            },
            encryption: {
                averageAvalancheEffect: parseFloat(metrics.avg_avalanche || 0).toFixed(2),
                averageCollisionResistance: parseFloat(metrics.avg_collision || 0).toFixed(6),
                averageEncryptionTime: parseFloat(metrics.avg_encryption_time || 0).toFixed(2),
                averageFileSize: parseInt(metrics.avg_file_size || 0),
            },
            actions: actionStats,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get statistics', code: 'GET_STATS_ERROR' });
    }
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found', code: 'NOT_FOUND', path: req.path, method: req.method });
});

app.use((error, req, res, next) => {
    if (error.code === 'LIMIT_FILE_SIZE')
        return res.status(413).json({ error: 'File too large', code: 'FILE_TOO_LARGE', maxSize: config.upload.maxFileSize });

    if (error.code === 'LIMIT_UNEXPECTED_FILE')
        return res.status(400).json({ error: 'Unexpected file field', code: 'UNEXPECTED_FILE' });

    res.status(error.status || 500).json({ error: error.message || 'Internal server error', code: error.code || 'INTERNAL_ERROR' });
});

// ============================================
// SERVER INITIALIZATION
// ============================================

async function startServer() {
    try {
        console.log('🚀 Starting Secure Cloud Storage Server...');
        console.log(`📍 Environment: ${config.NODE_ENV}`);
        console.log(`📍 Port: ${config.PORT}`);

        const server = app.listen(config.PORT, () => {
            console.log(`✓ Server running on port ${config.PORT}`);
            console.log(`✓ API at http://localhost:${config.PORT}/api`);
        });

        initializeDatabase()
            .then(() => console.log('✓ Database initialized'))
            .catch(err => console.error('⚠ DB init failed:', err.message));

        testConnection()
            .then(ok => console.log(ok ? '✓ S3 connected' : '⚠ S3 connection failed'))
            .catch(err => console.error('⚠ S3 error:', err.message));

        const gracefulShutdown = async (signal) => {
            console.log(`\n${signal} received. Shutting down gracefully...`);
            server.close(async () => {
                await closePool();
                console.log(`✓ Shutdown complete`);
                process.exit(0);
            });
            setTimeout(() => {
                console.error('⚠ Forced shutdown after timeout');
                process.exit(1);
            }, 30000);
        };

        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));

        process.on('uncaughtException', (error) => console.error('❌ Uncaught Exception:', error));
        process.on('unhandledRejection', (reason, promise) =>
            console.error('❌ Unhandled Rejection:', promise, 'reason:', reason)
        );

    } catch (error) {
        console.error('❌ Server initialization failed:', error);
        process.exit(1);
    }
}

if (require.main === module) startServer();

module.exports = app;
