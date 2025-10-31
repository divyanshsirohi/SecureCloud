/**
 * File sharing routes
 * Handles secure file sharing between users with key wrapping
 */
const express = require('express');
const { pool } = require('../db');
const { authenticate } = require('../middleware/auth');
const { shareLimiter } = require('../middleware/rateLimit');
const { logAudit } = require('../middleware/audit');

const router = express.Router();

/**
 * POST /shares
 * Share file with another user
 */
router.post('/', authenticate, shareLimiter, async (req, res) => {
    const client = await pool.connect();

    try {
        const {
            fileId,
            recipientUsername,
            wrappedKey,
            permissions = 'read'
        } = req.body;

        // Validate required fields
        if (!fileId || !recipientUsername || !wrappedKey) {
            return res.status(400).json({
                error: 'Missing required fields',
                code: 'MISSING_FIELDS'
            });
        }

        // Validate permissions
        if (!['read', 'write'].includes(permissions)) {
            return res.status(400).json({
                error: 'Invalid permissions. Must be "read" or "write"',
                code: 'INVALID_PERMISSIONS'
            });
        }

        await client.query('BEGIN');

        // Check file ownership
        const fileResult = await client.query(`
      SELECT owner_id, file_name, is_deleted
      FROM files
      WHERE file_id = $1
    `, [fileId]);

        if (fileResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                error: 'File not found',
                code: 'FILE_NOT_FOUND'
            });
        }

        const file = fileResult.rows[0];

        if (file.is_deleted) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                error: 'Cannot share deleted file',
                code: 'FILE_DELETED'
            });
        }

        if (file.owner_id !== req.user.userId) {
            await client.query('ROLLBACK');

            await logAudit({
                userId: req.user.userId,
                fileId: fileId,
                action: 'SHARE_UNAUTHORIZED',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                success: false,
                errorMessage: 'Not file owner'
            });

            return res.status(403).json({
                error: 'Only file owner can share',
                code: 'NOT_OWNER'
            });
        }

        // Get recipient user
        const recipientResult = await client.query(
            'SELECT user_id, username, email, public_key FROM users WHERE username = $1 AND is_active = TRUE',
            [recipientUsername]
        );

        if (recipientResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                error: 'Recipient user not found',
                code: 'RECIPIENT_NOT_FOUND'
            });
        }

        const recipient = recipientResult.rows[0];

        // Cannot share with self
        if (recipient.user_id === req.user.userId) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                error: 'Cannot share file with yourself',
                code: 'SHARE_WITH_SELF'
            });
        }

        // Check if already shared
        const existingShare = await client.query(`
      SELECT share_id, is_active, permissions
      FROM file_shares
      WHERE file_id = $1 AND recipient_id = $2
    `, [fileId, recipient.user_id]);

        let shareId;

        if (existingShare.rows.length > 0) {
            // Update existing share
            const share = existingShare.rows[0];

            if (share.is_active) {
                await client.query('ROLLBACK');
                return res.status(409).json({
                    error: 'File already shared with this user',
                    code: 'ALREADY_SHARED',
                    currentPermissions: share.permissions
                });
            }

            // Reactivate share
            const updateResult = await client.query(`
        UPDATE file_shares
        SET wrapped_key = $1,
            permissions = $2,
            is_active = TRUE,
            revoked_at = NULL,
            created_at = CURRENT_TIMESTAMP
        WHERE share_id = $3
        RETURNING share_id
      `, [wrappedKey, permissions, share.share_id]);

            shareId = updateResult.rows[0].share_id;

        } else {
            // Create new share
            const insertResult = await client.query(`
        INSERT INTO file_shares (
          file_id,
          owner_id,
          recipient_id,
          wrapped_key,
          permissions
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING share_id
      `, [fileId, req.user.userId, recipient.user_id, wrappedKey, permissions]);

            shareId = insertResult.rows[0].share_id;
        }

        await client.query('COMMIT');

        await logAudit({
            userId: req.user.userId,
            fileId: fileId,
            action: 'FILE_SHARED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: {
                recipientId: recipient.user_id,
                recipientUsername: recipient.username,
                permissions: permissions,
                fileName: file.file_name
            },
            success: true
        });

        res.status(201).json({
            message: 'File shared successfully',
            share: {
                shareId: shareId,
                fileId: fileId,
                recipient: {
                    userId: recipient.user_id,
                    username: recipient.username,
                    email: recipient.email
                },
                permissions: permissions
            }
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Share file error:', error);

        await logAudit({
            userId: req.user.userId,
            fileId: req.body.fileId,
            action: 'FILE_SHARE_ERROR',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({
            error: 'Failed to share file',
            code: 'SHARE_ERROR',
            details: error.message
        });
    } finally {
        client.release();
    }
});

/**
 * GET /shares/sent
 * Get files shared by current user
 */
router.get('/sent', authenticate, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        const sharesResult = await pool.query(`
      SELECT 
        fs.share_id,
        fs.file_id,
        fs.permissions,
        fs.created_at,
        fs.is_active,
        f.file_name,
        f.file_size,
        f.mime_type,
        u.user_id as recipient_id,
        u.username as recipient_username,
        u.email as recipient_email
      FROM file_shares fs
      JOIN files f ON fs.file_id = f.file_id
      JOIN users u ON fs.recipient_id = u.user_id
      WHERE fs.owner_id = $1 AND f.is_deleted = FALSE
      ORDER BY fs.created_at DESC
      LIMIT $2 OFFSET $3
    `, [req.user.userId, limit, offset]);

        // Get total count
        const countResult = await pool.query(`
      SELECT COUNT(*) as total
      FROM file_shares fs
      JOIN files f ON fs.file_id = f.file_id
      WHERE fs.owner_id = $1 AND f.is_deleted = FALSE
    `, [req.user.userId]);

        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);

        res.json({
            shares: sharesResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages
            }
        });

    } catch (error) {
        console.error('Get sent shares error:', error);
        res.status(500).json({
            error: 'Failed to get shared files',
            code: 'GET_SHARES_ERROR'
        });
    }
});

/**
 * GET /shares/received
 * Get files shared with current user
 */
router.get('/received', authenticate, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        const sharesResult = await pool.query(`
      SELECT 
        fs.share_id,
        fs.file_id,
        fs.permissions,
        fs.wrapped_key,
        fs.created_at,
        fs.is_active,
        f.file_name,
        f.encrypted_file_name,
        f.file_size,
        f.encrypted_size,
        f.mime_type,
        f.signature,
        u.user_id as owner_id,
        u.username as owner_username,
        u.email as owner_email
      FROM file_shares fs
      JOIN files f ON fs.file_id = f.file_id
      JOIN users u ON fs.owner_id = u.user_id
      WHERE fs.recipient_id = $1 AND fs.is_active = TRUE AND f.is_deleted = FALSE
      ORDER BY fs.created_at DESC
      LIMIT $2 OFFSET $3
    `, [req.user.userId, limit, offset]);

        // Get total count
        const countResult = await pool.query(`
      SELECT COUNT(*) as total
      FROM file_shares fs
      JOIN files f ON fs.file_id = f.file_id
      WHERE fs.recipient_id = $1 AND fs.is_active = TRUE AND f.is_deleted = FALSE
    `, [req.user.userId]);

        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);

        res.json({
            shares: sharesResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages
            }
        });

    } catch (error) {
        console.error('Get received shares error:', error);
        res.status(500).json({
            error: 'Failed to get shared files',
            code: 'GET_SHARES_ERROR'
        });
    }
});

/**
 * GET /shares/file/:fileId
 * Get all shares for a specific file
 */
router.get('/file/:fileId', authenticate, async (req, res) => {
    try {
        const { fileId } = req.params;

        // Check ownership
        const fileResult = await pool.query(
            'SELECT owner_id FROM files WHERE file_id = $1',
            [fileId]
        );

        if (fileResult.rows.length === 0) {
            return res.status(404).json({
                error: 'File not found',
                code: 'FILE_NOT_FOUND'
            });
        }

        if (fileResult.rows[0].owner_id !== req.user.userId) {
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        // Get shares
        const sharesResult = await pool.query(`
      SELECT 
        fs.share_id,
        fs.permissions,
        fs.created_at,
        fs.is_active,
        fs.revoked_at,
        u.user_id as recipient_id,
        u.username as recipient_username,
        u.email as recipient_email
      FROM file_shares fs
      JOIN users u ON fs.recipient_id = u.user_id
      WHERE fs.file_id = $1
      ORDER BY fs.created_at DESC
    `, [fileId]);

        res.json({ shares: sharesResult.rows });

    } catch (error) {
        console.error('Get file shares error:', error);
        res.status(500).json({
            error: 'Failed to get file shares',
            code: 'GET_FILE_SHARES_ERROR'
        });
    }
});

/**
 * PATCH /shares/:shareId
 * Update share permissions
 */
router.patch('/:shareId', authenticate, async (req, res) => {
    try {
        const { shareId } = req.params;
        const { permissions } = req.body;

        if (!permissions || !['read', 'write'].includes(permissions)) {
            return res.status(400).json({
                error: 'Invalid permissions',
                code: 'INVALID_PERMISSIONS'
            });
        }

        // Check ownership
        const shareResult = await pool.query(`
      SELECT fs.owner_id, fs.file_id, fs.permissions as current_permissions,
             u.username as recipient_username
      FROM file_shares fs
      JOIN users u ON fs.recipient_id = u.user_id
      WHERE fs.share_id = $1
    `, [shareId]);

        if (shareResult.rows.length === 0) {
            return res.status(404).json({
                error: 'Share not found',
                code: 'SHARE_NOT_FOUND'
            });
        }

        const share = shareResult.rows[0];

        if (share.owner_id !== req.user.userId) {
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        // Update permissions
        await pool.query(
            'UPDATE file_shares SET permissions = $1 WHERE share_id = $2',
            [permissions, shareId]
        );

        await logAudit({
            userId: req.user.userId,
            fileId: share.file_id,
            action: 'SHARE_UPDATED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: {
                shareId: shareId,
                oldPermissions: share.current_permissions,
                newPermissions: permissions,
                recipient: share.recipient_username
            },
            success: true
        });

        res.json({
            message: 'Share permissions updated',
            permissions: permissions
        });

    } catch (error) {
        console.error('Update share error:', error);
        res.status(500).json({
            error: 'Failed to update share',
            code: 'UPDATE_SHARE_ERROR'
        });
    }
});

/**
 * DELETE /shares/:shareId
 * Revoke file share
 */
router.delete('/:shareId', authenticate, async (req, res) => {
    try {
        const { shareId } = req.params;

        // Check ownership
        const shareResult = await pool.query(`
      SELECT fs.owner_id, fs.file_id, u.username as recipient_username
      FROM file_shares fs
      JOIN users u ON fs.recipient_id = u.user_id
      WHERE fs.share_id = $1
    `, [shareId]);

        if (shareResult.rows.length === 0) {
            return res.status(404).json({
                error: 'Share not found',
                code: 'SHARE_NOT_FOUND'
            });
        }

        const share = shareResult.rows[0];

        if (share.owner_id !== req.user.userId) {
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        // Revoke share
        await pool.query(`
      UPDATE file_shares
      SET is_active = FALSE, revoked_at = CURRENT_TIMESTAMP
      WHERE share_id = $1
    `, [shareId]);

        await logAudit({
            userId: req.user.userId,
            fileId: share.file_id,
            action: 'SHARE_REVOKED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: {
                shareId: shareId,
                recipient: share.recipient_username
            },
            success: true
        });

        res.json({ message: 'Share revoked successfully' });

    } catch (error) {
        console.error('Revoke share error:', error);

        await logAudit({
            userId: req.user.userId,
            action: 'SHARE_REVOKE_ERROR',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({
            error: 'Failed to revoke share',
            code: 'REVOKE_SHARE_ERROR'
        });
    }
});

/**
 * POST /shares/:shareId/rekey
 * Re-encrypt and update wrapped key for a share
 * Used when recipient's keys change
 */
router.post('/:shareId/rekey', authenticate, async (req, res) => {
    try {
        const { shareId } = req.params;
        const { wrappedKey } = req.body;

        if (!wrappedKey) {
            return res.status(400).json({
                error: 'Missing wrapped key',
                code: 'MISSING_WRAPPED_KEY'
            });
        }

        // Check ownership
        const shareResult = await pool.query(
            'SELECT owner_id, file_id FROM file_shares WHERE share_id = $1',
            [shareId]
        );

        if (shareResult.rows.length === 0) {
            return res.status(404).json({
                error: 'Share not found',
                code: 'SHARE_NOT_FOUND'
            });
        }

        const share = shareResult.rows[0];

        if (share.owner_id !== req.user.userId) {
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        // Update wrapped key
        await pool.query(
            'UPDATE file_shares SET wrapped_key = $1 WHERE share_id = $2',
            [wrappedKey, shareId]
        );

        await logAudit({
            userId: req.user.userId,
            fileId: share.file_id,
            action: 'SHARE_REKEYED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { shareId: shareId },
            success: true
        });

        res.json({ message: 'Share key updated successfully' });

    } catch (error) {
        console.error('Rekey share error:', error);
        res.status(500).json({
            error: 'Failed to update share key',
            code: 'REKEY_ERROR'
        });
    }
});

/**
 * GET /shares/stats
 * Get sharing statistics for current user
 */
router.get('/stats', authenticate, async (req, res) => {
    try {
        const statsResult = await pool.query(`
      SELECT
        COUNT(CASE WHEN owner_id = $1 AND is_active = TRUE THEN 1 END) as files_shared_by_me,
        COUNT(CASE WHEN recipient_id = $1 AND is_active = TRUE THEN 1 END) as files_shared_with_me,
        COUNT(CASE WHEN owner_id = $1 AND is_active = FALSE THEN 1 END) as revoked_shares
      FROM file_shares
      WHERE owner_id = $1 OR recipient_id = $1
    `, [req.user.userId]);

        const stats = statsResult.rows[0];

        res.json({
            stats: {
                filesSharedByMe: parseInt(stats.files_shared_by_me),
                filesSharedWithMe: parseInt(stats.files_shared_with_me),
                revokedShares: parseInt(stats.revoked_shares)
            }
        });

    } catch (error) {
        console.error('Get share stats error:', error);
        res.status(500).json({
            error: 'Failed to get share statistics',
            code: 'GET_STATS_ERROR'
        });
    }
});

module.exports = router;
