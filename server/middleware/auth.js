/**
 * Authentication middleware
 * Validates JWT tokens and attaches user info to request
 */
const { pool } = require('../db');
const { hashToken } = require('../utils/token');
const { logAudit } = require('./audit');

/**
 * Authentication middleware
 * Verifies session token and attaches user to request
 */
async function authenticate(req, res, next) {
    try {
        // Extract token from Authorization header
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'No token provided',
                code: 'NO_TOKEN'
            });
        }

        const token = authHeader.substring(7);
        const tokenHash = hashToken(token);

        // Validate token against database
        const result = await pool.query(`
      SELECT 
        s.user_id, 
        s.expires_at, 
        s.created_at as session_created,
        u.username, 
        u.email, 
        u.is_active,
        u.public_key
      FROM sessions s
      JOIN users u ON s.user_id = u.user_id
      WHERE s.token_hash = $1 AND s.is_active = TRUE
    `, [tokenHash]);

        if (result.rows.length === 0) {
            await logAudit({
                action: 'AUTH_INVALID_TOKEN',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                success: false,
                errorMessage: 'Invalid token'
            });

            return res.status(401).json({
                error: 'Invalid token',
                code: 'INVALID_TOKEN'
            });
        }

        const session = result.rows[0];

        // Check token expiration
        if (new Date(session.expires_at) < new Date()) {
            // Deactivate expired session
            await pool.query(
                'UPDATE sessions SET is_active = FALSE WHERE token_hash = $1',
                [tokenHash]
            );

            await logAudit({
                userId: session.user_id,
                action: 'AUTH_TOKEN_EXPIRED',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                success: false
            });

            return res.status(401).json({
                error: 'Token expired',
                code: 'TOKEN_EXPIRED'
            });
        }

        // Check user account status
        if (!session.is_active) {
            await logAudit({
                userId: session.user_id,
                action: 'AUTH_INACTIVE_USER',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                success: false
            });

            return res.status(401).json({
                error: 'User account is inactive',
                code: 'INACTIVE_ACCOUNT'
            });
        }

        // Attach user info to request
        req.user = {
            userId: session.user_id,
            username: session.username,
            email: session.email,
            publicKey: session.public_key,
            sessionCreated: session.session_created
        };

        // Attach token for potential logout
        req.tokenHash = tokenHash;

        next();

    } catch (error) {
        console.error('Authentication error:', error);

        await logAudit({
            action: 'AUTH_ERROR',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({
            error: 'Authentication failed',
            code: 'AUTH_ERROR'
        });
    }
}

/**
 * Optional authentication middleware
 * Attaches user if authenticated but doesn't block unauthenticated requests
 */
async function optionalAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next();
        }

        await authenticate(req, res, next);
    } catch (error) {
        // Continue without authentication
        next();
    }
}

module.exports = {
    authenticate,
    optionalAuth,
};
