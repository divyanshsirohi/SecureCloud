/**
 * Authentication routes
 * Handles user registration, login, logout, and session management
 */
const express = require('express');
const argon2 = require('argon2');
const { pool } = require('../db');
const { generateSessionToken, hashToken } = require('../utils/token');
const { authenticate } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');
const { logAudit } = require('../middleware/audit');
const config = require('../config');

const router = express.Router();

/**
 * POST /auth/register
 * Register new user account with end-to-end encryption keys
 */
router.post('/register', authLimiter, async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      username,
      email,
      passwordHash,
      publicKey,
      encryptedPrivateKey,
      salt
    } = req.body;

    // Validate required fields
    if (!username || !email || !passwordHash || !publicKey || !encryptedPrivateKey || !salt) {
      await logAudit({
        action: 'REGISTER_FAILED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        errorMessage: 'Missing required fields'
      });

      return res.status(400).json({
        error: 'Missing required fields',
        code: 'MISSING_FIELDS'
      });
    }

    // Validate username format
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: 'Username must be 3-20 characters (letters, numbers, underscore)',
        code: 'INVALID_USERNAME'
      });
    }

    // Validate email format
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        error: 'Invalid email format',
        code: 'INVALID_EMAIL'
      });
    }

    await client.query('BEGIN');

    // Check if username or email already exists
    const existingUser = await client.query(
        'SELECT user_id FROM users WHERE username = $1 OR email = $2',
        [username, email]
    );

    if (existingUser.rows.length > 0) {
      await client.query('ROLLBACK');

      await logAudit({
        action: 'REGISTER_FAILED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        errorMessage: 'Username or email already exists'
      });

      return res.status(409).json({
        error: 'Username or email already exists',
        code: 'USER_EXISTS'
      });
    }

    // Hash the client-provided password hash with Argon2
    // This adds server-side security layer
    const serverPasswordHash = await argon2.hash(passwordHash, config.security.argon2);

    // Insert new user
    const userResult = await client.query(`
      INSERT INTO users (
        username, 
        email, 
        password_hash, 
        public_key, 
        encrypted_private_key, 
        salt
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING user_id, username, email, created_at
    `, [username, email, serverPasswordHash, publicKey, encryptedPrivateKey, salt]);

    const newUser = userResult.rows[0];

    // Generate session token
    const sessionToken = generateSessionToken(newUser.user_id);

    // Store session
    await client.query(`
      INSERT INTO sessions (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)
    `, [newUser.user_id, sessionToken.tokenHash, sessionToken.expiresAt]);

    await client.query('COMMIT');

    // Log successful registration
    await logAudit({
      userId: newUser.user_id,
      action: 'REGISTER_SUCCESS',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true,
      metadata: { username: newUser.username, email: newUser.email }
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        userId: newUser.user_id,
        username: newUser.username,
        email: newUser.email,
        createdAt: newUser.created_at
      },
      token: sessionToken.token,
      expiresAt: sessionToken.expiresAt
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Registration error:', error);

    await logAudit({
      action: 'REGISTER_ERROR',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({
      error: 'Registration failed',
      code: 'REGISTRATION_ERROR'
    });
  } finally {
    client.release();
  }
});

/**
 * POST /auth/login
 * Authenticate user and create session
 */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, passwordHash } = req.body;

    if (!username || !passwordHash) {
      await logAudit({
        action: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        errorMessage: 'Missing credentials'
      });

      return res.status(400).json({
        error: 'Missing credentials',
        code: 'MISSING_CREDENTIALS'
      });
    }

    // Fetch user
    const userResult = await pool.query(`
      SELECT 
        user_id, 
        username, 
        email, 
        password_hash, 
        public_key,
        encrypted_private_key, 
        salt, 
        is_active
      FROM users
      WHERE username = $1
    `, [username]);

    if (userResult.rows.length === 0) {
      await logAudit({
        action: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        errorMessage: 'Invalid credentials',
        metadata: { username }
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const user = userResult.rows[0];

    // Check if account is active
    if (!user.is_active) {
      await logAudit({
        userId: user.user_id,
        action: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        errorMessage: 'Account inactive'
      });

      return res.status(401).json({
        error: 'Account is inactive',
        code: 'INACTIVE_ACCOUNT'
      });
    }

    // Verify password
    const isValidPassword = await argon2.verify(user.password_hash, passwordHash);

    if (!isValidPassword) {
      await logAudit({
        userId: user.user_id,
        action: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        errorMessage: 'Invalid password'
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Generate session token
    const sessionToken = generateSessionToken(user.user_id);

    // Store session
    await pool.query(`
      INSERT INTO sessions (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)
    `, [user.user_id, sessionToken.tokenHash, sessionToken.expiresAt]);

    // Update last login
    await pool.query(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = $1',
        [user.user_id]
    );

    // Log successful login
    await logAudit({
      userId: user.user_id,
      action: 'LOGIN_SUCCESS',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      message: 'Login successful',
      user: {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        publicKey: user.public_key,
        encryptedPrivateKey: user.encrypted_private_key,
        salt: user.salt
      },
      token: sessionToken.token,
      expiresAt: sessionToken.expiresAt
    });

  } catch (error) {
    console.error('Login error:', error);

    await logAudit({
      action: 'LOGIN_ERROR',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({
      error: 'Login failed',
      code: 'LOGIN_ERROR'
    });
  }
});

/**
 * POST /auth/logout
 * Invalidate current session
 */
router.post('/logout', authenticate, async (req, res) => {
  try {
    // Invalidate session
    await pool.query(
        'UPDATE sessions SET is_active = FALSE WHERE token_hash = $1',
        [req.tokenHash]
    );

    await logAudit({
      userId: req.user.userId,
      action: 'LOGOUT_SUCCESS',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ message: 'Logged out successfully' });

  } catch (error) {
    console.error('Logout error:', error);

    await logAudit({
      userId: req.user?.userId,
      action: 'LOGOUT_ERROR',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({
      error: 'Logout failed',
      code: 'LOGOUT_ERROR'
    });
  }
});

/**
 * GET /auth/me
 * Get current user information
 */
router.get('/me', authenticate, async (req, res) => {
  try {
    const userResult = await pool.query(`
      SELECT 
        user_id, 
        username, 
        email, 
        public_key,
        encrypted_private_key,
        salt,
        created_at,
        last_login
      FROM users
      WHERE user_id = $1
    `, [req.user.userId]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    res.json({ user: userResult.rows[0] });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      error: 'Failed to get user information',
      code: 'GET_USER_ERROR'
    });
  }
});

/**
 * POST /auth/refresh
 * Refresh session token
 */
router.post('/refresh', authenticate, async (req, res) => {
  try {
    // Invalidate old session
    await pool.query(
        'UPDATE sessions SET is_active = FALSE WHERE token_hash = $1',
        [req.tokenHash]
    );

    // Generate new session token
    const sessionToken = generateSessionToken(req.user.userId);

    // Store new session
    await pool.query(`
      INSERT INTO sessions (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)
    `, [req.user.userId, sessionToken.tokenHash, sessionToken.expiresAt]);

    await logAudit({
      userId: req.user.userId,
      action: 'TOKEN_REFRESH',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      message: 'Token refreshed successfully',
      token: sessionToken.token,
      expiresAt: sessionToken.expiresAt
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Failed to refresh token',
      code: 'REFRESH_ERROR'
    });
  }
});

/**
 * GET /auth/sessions
 * Get all active sessions for current user
 */
router.get('/sessions', authenticate, async (req, res) => {
  try {
    const sessionsResult = await pool.query(`
      SELECT 
        session_id,
        created_at,
        expires_at,
        is_active
      FROM sessions
      WHERE user_id = $1 AND is_active = TRUE
      ORDER BY created_at DESC
    `, [req.user.userId]);

    res.json({ sessions: sessionsResult.rows });

  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      error: 'Failed to get sessions',
      code: 'GET_SESSIONS_ERROR'
    });
  }
});

/**
 * DELETE /auth/sessions/:sessionId
 * Revoke a specific session
 */
router.delete('/sessions/:sessionId', authenticate, async (req, res) => {
  try {
    const { sessionId } = req.params;

    const result = await pool.query(`
      UPDATE sessions
      SET is_active = FALSE
      WHERE session_id = $1 AND user_id = $2
      RETURNING session_id
    `, [sessionId, req.user.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Session not found',
        code: 'SESSION_NOT_FOUND'
      });
    }

    await logAudit({
      userId: req.user.userId,
      action: 'SESSION_REVOKED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true,
      metadata: { sessionId }
    });

    res.json({ message: 'Session revoked successfully' });

  } catch (error) {
    console.error('Revoke session error:', error);
    res.status(500).json({
      error: 'Failed to revoke session',
      code: 'REVOKE_SESSION_ERROR'
    });
  }
});

/**
 * DELETE /auth/sessions
 * Revoke all sessions except current
 */
router.delete('/sessions', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      UPDATE sessions
      SET is_active = FALSE
      WHERE user_id = $1 AND token_hash != $2
      RETURNING session_id
    `, [req.user.userId, req.tokenHash]);

    await logAudit({
      userId: req.user.userId,
      action: 'ALL_SESSIONS_REVOKED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true,
      metadata: { revokedCount: result.rowCount }
    });

    res.json({
      message: 'All other sessions revoked successfully',
      revokedCount: result.rowCount
    });

  } catch (error) {
    console.error('Revoke all sessions error:', error);
    res.status(500).json({
      error: 'Failed to revoke sessions',
      code: 'REVOKE_ALL_SESSIONS_ERROR'
    });
  }
});

module.exports = router;
