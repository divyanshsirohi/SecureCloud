/**
 * Main server entry point
 * Secure Cloud Storage Backend
 */
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const config = require('./config');
const { initializeDatabase, closePool } = require('./db');
const { requestLogger, cleanupOldLogs } = require('./middleware/audit');
const { apiLimiter } = require('./middleware/rateLimit');

// Import routes
const authRoutes = require('./routes/auth');
const filesRoutes = require('./routes/files');
const sharesRoutes = require('./routes/shares');

// Import utilities
const { testConnection } = require('./utils/s3');

// Initialize Express app
const app = express();

// Trust proxy (for accurate IP addresses behind load balancer)
app.set('trust proxy', 1);

// ============================================
// MIDDLEWARE CONFIGURATION
// ============================================

// Security headers
app.use(helmet({
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
        preload: true
    }
}));

// CORS configuration
app.use(cors({
    origin: config.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing
app.use(express.json({ limit: config.upload.requestSizeLimit }));
app.use(express.urlencoded({ extended: true, limit: config.upload.requestSizeLimit }));

// Compression
app.use(compression());

// Request logging
app.use(requestLogger);

// Rate limiting
app.use('/api/', apiLimiter);

const path = require('path');

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));

// Serve index.html for all non-API routes
app.get('/*', (req, res) => {
    if (!req.path.startsWith('/api')) {
        res.sendFile(path.join(__dirname, '../frontend/index.html'));
    }
});


// ============================================
// HEALTH CHECK & INFO ENDPOINTS
// ============================================

/**
 * GET /
 * Root endpoint - API information
 */
app.get('/', (req, res) => {
    res.json({
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
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', async (req, res) => {
    try {
        // Check database connection
        const { pool } = require('./db');
        const dbResult = await pool.query('SELECT NOW()');

        // Check S3 connection
        const s3Status = await testConnection();

        const health = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            services: {
                database: {
                    status: dbResult.rows.length > 0 ? 'connected' : 'disconnected',
                    responseTime: dbResult.rows[0] ? 'OK' : 'N/A'
                },
                storage: {
                    status: s3Status ? 'connected' : 'disconnected',
                    provider: 'AWS S3'
                },
                api: {
                    status: 'operational'
                }
            },
            memory: {
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
                total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
            }
        };

        res.json(health);

    } catch (error) {
        console.error('Health check error:', error);
        res.status(503).json({
            status: 'unhealthy',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// ============================================
// API ROUTES
// ============================================

app.use('/api/auth', authRoutes);
app.use('/api/files', filesRoutes);
app.use('/api/shares', sharesRoutes);

/**
 * GET /api/audit
 * Get audit logs (with authentication)
 */
const { authenticate } = require('./middleware/auth');
const { pool } = require('./db');

app.get('/api/audit', authenticate, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            action,
            startDate,
            endDate
        } = req.query;

        const offset = (page - 1) * limit;

        // Build query conditions
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

        const whereClause = conditions.join(' AND ');

        // Get audit logs
        const logsResult = await pool.query(`
      SELECT 
        log_id,
        action,
        timestamp,
        ip_address,
        encryption_time_ms,
        decryption_time_ms,
        key_generation_time_ms,
        avalanche_effect_percentage,
        collision_resistance_score,
        file_size_bytes,
        success,
        error_message,
        metadata
      FROM audit_logs
      WHERE ${whereClause}
      ORDER BY timestamp DESC
      LIMIT $2 OFFSET $3
    `, params);

        // Get total count
        const countParams = params.slice(0, paramIndex - 1);
        const countResult = await pool.query(`
      SELECT COUNT(*) as total
      FROM audit_logs
      WHERE ${whereClause}
    `, countParams);

        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);

        res.json({
            logs: logsResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages
            }
        });

    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({
            error: 'Failed to retrieve audit logs',
            code: 'GET_AUDIT_ERROR'
        });
    }
});

/**
 * GET /api/audit/export
 * Export audit logs as CSV
 */
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

        const whereClause = conditions.join(' AND ');

        const logsResult = await pool.query(`
      SELECT 
        timestamp,
        action,
        file_id,
        ip_address,
        encryption_time_ms,
        avalanche_effect_percentage,
        collision_resistance_score,
        file_size_bytes,
        success,
        error_message
      FROM audit_logs
      WHERE ${whereClause}
      ORDER BY timestamp DESC
      LIMIT ${config.audit.exportMaxRecords}
    `, params);

        // Generate CSV
        const headers = [
            'Timestamp',
            'Action',
            'File ID',
            'IP Address',
            'Encryption Time (ms)',
            'Avalanche Effect (%)',
            'Collision Resistance',
            'File Size (bytes)',
            'Success',
            'Error'
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
        console.error('Export audit logs error:', error);
        res.status(500).json({
            error: 'Failed to export audit logs',
            code: 'EXPORT_AUDIT_ERROR'
        });
    }
});

/**
 * GET /api/stats
 * Get user statistics
 */
app.get('/api/stats', authenticate, async (req, res) => {
    try {
        // Get file statistics
        const fileStatsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_files,
        SUM(file_size) as total_size,
        AVG(file_size) as avg_file_size,
        COUNT(DISTINCT mime_type) as file_types
      FROM files
      WHERE owner_id = $1 AND is_deleted = FALSE
    `, [req.user.userId]);

        // Get action breakdown
        const actionStatsResult = await pool.query(`
      SELECT 
        action,
        COUNT(*) as count,
        AVG(encryption_time_ms) as avg_time,
        COUNT(CASE WHEN success = TRUE THEN 1 END) as success_count,
        COUNT(CASE WHEN success = FALSE THEN 1 END) as error_count
      FROM audit_logs
      WHERE user_id = $1 
      AND timestamp > NOW() - INTERVAL '30 days'
      GROUP BY action
      ORDER BY count DESC
      LIMIT 10
    `, [req.user.userId]);

        // Get encryption metrics
        const metricsResult = await pool.query(`
      SELECT 
        AVG(avalanche_effect_percentage) as avg_avalanche,
        AVG(collision_resistance_score) as avg_collision,
        AVG(encryption_time_ms) as avg_encryption_time,
        AVG(file_size_bytes) as avg_file_size
      FROM audit_logs
      WHERE user_id = $1 
      AND action IN ('FILE_UPLOAD', 'FILE_DOWNLOAD')
      AND timestamp > NOW() - INTERVAL '30 days'
    `, [req.user.userId]);

        // Get share statistics
        const shareStatsResult = await pool.query(`
      SELECT
        COUNT(CASE WHEN owner_id = $1 AND is_active = TRUE THEN 1 END) as active_shares_sent,
        COUNT(CASE WHEN recipient_id = $1 AND is_active = TRUE THEN 1 END) as active_shares_received
      FROM file_shares
    `, [req.user.userId]);

        const fileStats = fileStatsResult.rows[0];
        const metrics = metricsResult.rows[0];
        const shareStats = shareStatsResult.rows[0];

        res.json({
            files: {
                total: parseInt(fileStats.total_files),
                totalSize: parseInt(fileStats.total_size || 0),
                averageSize: parseFloat(fileStats.avg_file_size || 0),
                fileTypes: parseInt(fileStats.file_types)
            },
            shares: {
                sent: parseInt(shareStats.active_shares_sent),
                received: parseInt(shareStats.active_shares_received)
            },
            encryption: {
                averageAvalancheEffect: parseFloat(metrics.avg_avalanche || 0).toFixed(2),
                averageCollisionResistance: parseFloat(metrics.avg_collision || 0).toFixed(6),
                averageEncryptionTime: parseFloat(metrics.avg_encryption_time || 0).toFixed(2),
                averageFileSize: parseInt(metrics.avg_file_size || 0)
            },
            actions: actionStatsResult.rows
        });

    } catch (error) {
        console.error('Get statistics error:', error);
        res.status(500).json({
            error: 'Failed to get statistics',
            code: 'GET_STATS_ERROR'
        });
    }
});

// ============================================
// ERROR HANDLING
// ============================================

/**
 * 404 handler
 */
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        code: 'NOT_FOUND',
        path: req.path,
        method: req.method
    });
});

/**
 * Global error handler
 */
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);

    // Multer errors
    if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
            error: 'File too large',
            code: 'FILE_TOO_LARGE',
            maxSize: config.upload.maxFileSize
        });
    }

    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
        return res.status(400).json({
            error: 'Unexpected file field',
            code: 'UNEXPECTED_FILE'
        });
    }

    // Default error response
    res.status(error.status || 500).json({
        error: error.message || 'Internal server error',
        code: error.code || 'INTERNAL_ERROR',
        ...(config.NODE_ENV === 'development' && { stack: error.stack })
    });
});

// ============================================
// SERVER INITIALIZATION
// ============================================

/**
 * Initialize server
 */
async function startServer() {
    try {
        console.log('🚀 Starting Secure Cloud Storage Server...');
        console.log(`📍 Environment: ${config.NODE_ENV}`);

        // Initialize database
        await initializeDatabase();

        // Test S3 connection
        const s3Connected = await testConnection();
        if (s3Connected) {
            console.log('✓ S3 connection successful');
        } else {
            console.warn('⚠ S3 connection failed - file operations may not work');
        }

        // Start server
        const server = app.listen(config.PORT, () => {
            console.log(`✓ Server running on port ${config.PORT}`);
            console.log(`✓ API available at http://localhost:${config.PORT}`);
            console.log(`✓ Health check: http://localhost:${config.PORT}/health`);
        });

        // Graceful shutdown handler
        const gracefulShutdown = async (signal) => {
            console.log(`\n${signal} received. Starting graceful shutdown...`);

            server.close(async () => {
                console.log('✓ HTTP server closed');

                try {
                    await closePool();
                    console.log('✓ Database connections closed');
                    console.log('✓ Shutdown complete');
                    process.exit(0);
                } catch (error) {
                    console.error('Error during shutdown:', error);
                    process.exit(1);
                }
            });

            // Force shutdown after 30 seconds
            setTimeout(() => {
                console.error('⚠ Forced shutdown after timeout');
                process.exit(1);
            }, 30000);
        };

        // Handle shutdown signals
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));

        // Schedule audit log cleanup (daily at 2 AM)
        const scheduleCleanup = () => {
            const now = new Date();
            const nextRun = new Date(
                now.getFullYear(),
                now.getMonth(),
                now.getDate() + 1,
                2, 0, 0, 0
            );
            const timeout = nextRun.getTime() - now.getTime();

            setTimeout(async () => {
                try {
                    console.log('Running scheduled audit log cleanup...');
                    const deleted = await cleanupOldLogs(config.audit.retention_days);
                    console.log(`✓ Cleaned up ${deleted} old audit logs`);
                } catch (error) {
                    console.error('Audit cleanup error:', error);
                }
                scheduleCleanup(); // Schedule next cleanup
            }, timeout);
        };

        scheduleCleanup();
        console.log('✓ Scheduled daily audit log cleanup');

    } catch (error) {
        console.error('❌ Server initialization failed:', error);
        process.exit(1);
    }
}

// Start server if this is the main module
if (require.main === module) {
    startServer();
}

module.exports = app;
