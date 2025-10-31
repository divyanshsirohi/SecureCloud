/**
 * Rate limiting middleware
 * Protects against brute force and DoS attacks
 */
const rateLimit = require('express-rate-limit');
const config = require('../config');

/**
 * General API rate limiter
 */
const apiLimiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    message: {
        error: config.rateLimit.message,
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip successful requests in count (optional)
    skip: (req, res) => res.statusCode < 400,
});

/**
 * Strict rate limiter for authentication endpoints
 * Prevents brute force attacks
 */
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: {
        error: 'Too many authentication attempts. Please try again later.',
        code: 'AUTH_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
});

/**
 * File upload rate limiter
 * Prevents storage abuse
 */
const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 50, // 50 uploads per hour
    message: {
        error: 'Upload limit exceeded. Please try again later.',
        code: 'UPLOAD_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

/**
 * Share operation limiter
 * Prevents spam sharing
 */
const shareLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // 100 shares per hour
    message: {
        error: 'Share limit exceeded. Please try again later.',
        code: 'SHARE_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

/**
 * Custom rate limiter with dynamic limits based on user type
 */
function createDynamicLimiter(options) {
    return rateLimit({
        ...options,
        keyGenerator: (req) => {
            // Use user ID if authenticated, otherwise IP
            return req.user ? `user:${req.user.userId}` : `ip:${req.ip}`;
        },
        skip: (req) => {
            // Skip rate limiting for admin users (if implemented)
            return req.user && req.user.isAdmin;
        },
    });
}

module.exports = {
    apiLimiter,
    authLimiter,
    uploadLimiter,
    shareLimiter,
    createDynamicLimiter,
};
