/**
 * File management routes
 * Handles file upload, download, deletion, and versioning
 */
const express = require('express');
const multer = require('multer');
const { pool } = require('../db');
const { uploadFile, downloadFile, deleteFile, copyFile } = require('../utils/s3');
const { authenticate } = require('../middleware/auth');
const { uploadLimiter } = require('../middleware/rateLimit');
const { logAudit } = require('../middleware/audit');
const { analyzeEncryptionQuality, timeCryptoOperation } = require('../utils/cryptoMetrics');
const { generateFileId } = require('../utils/token');
const config = require('../config');

const router = express.Router();

// Configure multer for file uploads
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: config.upload.maxFileSize,
        files: 1
    },
    fileFilter: (req, file, cb) => {
        // Allow all file types (they're encrypted anyway)
        cb(null, true);
    }
});

/**
 * POST /files/upload
 * Upload encrypted file
 */
router.post('/upload', authenticate, uploadLimiter, upload.single('file'), async (req, res) => {
    const client = await pool.connect();
    const startTime = Date.now();

    try {
        // Debug logging
        console.log('Upload request received');
        console.log('File:', req.file ? 'Present' : 'Missing');
        console.log('Body keys:', Object.keys(req.body));

        if (!req.file) {
            console.error('No file in request');
            return res.status(400).json({
                error: 'No file provided',
                code: 'NO_FILE',
                debug: {
                    hasFile: !!req.file,
                    bodyKeys: Object.keys(req.body)
                }
            });
        }

        const {
            fileName,
            encryptedFileName,
            encryptedSymmetricKey,
            signature,
            mimeType
        } = req.body;

        console.log('Upload details:', { fileName, mimeType, size: req.file.size });

        // Validate required fields
        if (!fileName || !encryptedFileName || !encryptedSymmetricKey || !signature) {
            console.error('Missing required fields:', {
                fileName: !!fileName,
                encryptedFileName: !!encryptedFileName,
                encryptedSymmetricKey: !!encryptedSymmetricKey,
                signature: !!signature
            });

            return res.status(400).json({
                error: 'Missing required fields',
                code: 'MISSING_FIELDS',
                required: ['fileName', 'encryptedFileName', 'encryptedSymmetricKey', 'signature'],
                received: Object.keys(req.body)
            });
        }

        const fileBuffer = req.file.buffer;
        const fileSize = req.file.size;

        console.log('Analyzing encryption...');

        // Analyze encryption quality
        const cryptoMetrics = analyzeEncryptionQuality(fileBuffer);

        // Generate unique S3 key
        const fileId = generateFileId();
        const s3Key = `files_${req.user.userId}_${fileId}`;

        console.log('Starting database transaction...');
        await client.query('BEGIN');

        console.log('Uploading to storage...');
        // Upload to storage
        const uploadResult = await timeCryptoOperation(
            () => uploadFile(fileBuffer, s3Key, {
                userId: req.user.userId,
                originalFileName: fileName,
                mimeType: mimeType || 'application/octet-stream'
            })
        );

        console.log('Upload successful, saving to database...');

        // Store file metadata in database
        const fileResult = await client.query(`
      INSERT INTO files (
        file_id,
        owner_id,
        file_name,
        encrypted_file_name,
        s3_key,
        file_size,
        encrypted_size,
        mime_type,
        encrypted_symmetric_key,
        signature,
        version
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1)
      RETURNING file_id, created_at
    `, [
            fileId,
            req.user.userId,
            fileName,
            encryptedFileName,
            s3Key,
            parseInt(req.body.originalSize || fileSize),
            fileSize,
            mimeType || 'application/octet-stream',
            encryptedSymmetricKey,
            signature
        ]);

        // Store initial version
        await client.query(`
      INSERT INTO file_versions (
        file_id,
        version_number,
        s3_key,
        encrypted_symmetric_key,
        signature,
        file_size,
        created_by
      )
      VALUES ($1, 1, $2, $3, $4, $5, $6)
    `, [
            fileId,
            s3Key,
            encryptedSymmetricKey,
            signature,
            fileSize,
            req.user.userId
        ]);

        await client.query('COMMIT');

        const totalTime = Date.now() - startTime;

        console.log(`✓ Upload complete: ${fileName} (${totalTime}ms)`);

        // Log audit with crypto metrics
        await logAudit({
            userId: req.user.userId,
            fileId: fileId,
            action: 'FILE_UPLOAD',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            encryptionTime: totalTime,
            avalancheEffect: cryptoMetrics.avalancheEffect,
            collisionResistance: cryptoMetrics.collisionResistance,
            fileSize: fileSize,
            encryptionAlgorithm: 'AES-256-GCM',
            keySize: 256,
            metadata: {
                fileName: fileName,
                mimeType: mimeType,
                quality: cryptoMetrics.quality
            },
            success: true
        });

        res.status(201).json({
            message: 'File uploaded successfully',
            file: {
                fileId: fileId,
                fileName: fileName,
                fileSize: fileSize,
                createdAt: fileResult.rows[0].created_at,
                version: 1
            },
            metrics: {
                uploadTime: totalTime,
                s3UploadTime: uploadResult.durationMs,
                avalancheEffect: cryptoMetrics.avalancheEffect,
                collisionResistance: cryptoMetrics.collisionResistance,
                quality: cryptoMetrics.quality
            }
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('File upload error:', error);
        console.error('Error stack:', error.stack);

        await logAudit({
            userId: req.user.userId,
            action: 'FILE_UPLOAD_FAILED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({
            error: 'File upload failed',
            code: 'UPLOAD_ERROR',
            details: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    } finally {
        client.release();
    }
});

/**
 * GET /files
 * List user's files
 */
router.get('/', authenticate, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            sortBy = 'created_at',
            sortOrder = 'DESC',
            search = ''
        } = req.query;

        const offset = (page - 1) * limit;

        // Build search condition
        let searchCondition = '';
        let queryParams = [req.user.userId, limit, offset];

        if (search) {
            searchCondition = 'AND file_name ILIKE $4';
            queryParams.push(`%${search}%`);
        }

        // Get files with pagination
        const filesResult = await pool.query(`
      SELECT 
        file_id,
        file_name,
        file_size,
        encrypted_size,
        mime_type,
        version,
        created_at,
        updated_at
      FROM files
      WHERE owner_id = $1 AND is_deleted = FALSE ${searchCondition}
      ORDER BY ${sortBy} ${sortOrder}
      LIMIT $2 OFFSET $3
    `, queryParams);

        // Get total count
        const countResult = await pool.query(`
      SELECT COUNT(*) as total
      FROM files
      WHERE owner_id = $1 AND is_deleted = FALSE ${searchCondition}
    `, searchCondition ? [req.user.userId, `%${search}%`] : [req.user.userId]);

        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);

        res.json({
            files: filesResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                totalPages
            }
        });

    } catch (error) {
        console.error('List files error:', error);
        res.status(500).json({
            error: 'Failed to list files',
            code: 'LIST_FILES_ERROR'
        });
    }
});

/**
 * GET /files/:fileId
 * Download file
 */
router.get('/:fileId', authenticate, async (req, res) => {
    const startTime = Date.now();

    try {
        const { fileId } = req.params;

        // Check file access (owner or shared)
        const fileResult = await pool.query(`
      SELECT 
        f.file_id,
        f.owner_id,
        f.file_name,
        f.encrypted_file_name,
        f.s3_key,
        f.file_size,
        f.encrypted_size,
        f.mime_type,
        f.encrypted_symmetric_key,
        f.signature,
        CASE 
          WHEN f.owner_id = $2 THEN 'owner'
          WHEN EXISTS (
            SELECT 1 FROM file_shares 
            WHERE file_id = f.file_id 
            AND recipient_id = $2 
            AND is_active = TRUE
          ) THEN 'shared'
          ELSE NULL
        END as access_type
      FROM files f
      WHERE f.file_id = $1 AND f.is_deleted = FALSE
    `, [fileId, req.user.userId]);

        if (fileResult.rows.length === 0) {
            await logAudit({
                userId: req.user.userId,
                fileId: fileId,
                action: 'FILE_DOWNLOAD_FAILED',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                success: false,
                errorMessage: 'File not found'
            });

            return res.status(404).json({
                error: 'File not found',
                code: 'FILE_NOT_FOUND'
            });
        }

        const file = fileResult.rows[0];

        if (!file.access_type) {
            await logAudit({
                userId: req.user.userId,
                fileId: fileId,
                action: 'FILE_DOWNLOAD_UNAUTHORIZED',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                success: false,
                errorMessage: 'Unauthorized access'
            });

            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        // Download from S3
        const downloadResult = await timeCryptoOperation(
            () => downloadFile(file.s3_key)
        );

        const totalTime = Date.now() - startTime;

        // Log download
        await logAudit({
            userId: req.user.userId,
            fileId: fileId,
            action: 'FILE_DOWNLOAD',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            decryptionTime: totalTime,
            fileSize: file.encrypted_size,
            metadata: {
                fileName: file.file_name,
                accessType: file.access_type
            },
            success: true
        });

        res.json({
            file: {
                fileId: file.file_id,
                fileName: file.file_name,
                encryptedFileName: file.encrypted_file_name,
                fileSize: file.file_size,
                mimeType: file.mime_type,
                encryptedSymmetricKey: file.encrypted_symmetric_key,
                signature: file.signature,
                accessType: file.access_type
            },
            encryptedData: downloadResult.result.toString('base64'),
            metrics: {
                downloadTime: totalTime,
                s3DownloadTime: downloadResult.durationMs
            }
        });

    } catch (error) {
        console.error('File download error:', error);

        await logAudit({
            userId: req.user.userId,
            fileId: req.params.fileId,
            action: 'FILE_DOWNLOAD_ERROR',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({
            error: 'File download failed',
            code: 'DOWNLOAD_ERROR',
            details: error.message
        });
    }
});

/**
 * DELETE /files/:fileId
 * Delete file (soft delete)
 */
router.delete('/:fileId', authenticate, async (req, res) => {
    const client = await pool.connect();

    try {
        const { fileId } = req.params;
        const { permanent = false } = req.query;

        await client.query('BEGIN');

        // Check ownership
        const fileResult = await client.query(
            'SELECT owner_id, s3_key, file_name FROM files WHERE file_id = $1',
            [fileId]
        );

        if (fileResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                error: 'File not found',
                code: 'FILE_NOT_FOUND'
            });
        }

        const file = fileResult.rows[0];

        if (file.owner_id !== req.user.userId) {
            await client.query('ROLLBACK');
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        if (permanent === 'true') {
            // Permanent deletion
            // Delete from S3
            await deleteFile(file.s3_key);

            // Delete from database (cascade will handle shares and versions)
            await client.query('DELETE FROM files WHERE file_id = $1', [fileId]);

            await logAudit({
                userId: req.user.userId,
                fileId: fileId,
                action: 'FILE_DELETE_PERMANENT',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                metadata: { fileName: file.file_name },
                success: true
            });

            await client.query('COMMIT');

            res.json({
                message: 'File permanently deleted',
                permanent: true
            });
        } else {
            // Soft deletion
            await client.query(
                'UPDATE files SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE file_id = $1',
                [fileId]
            );

            await logAudit({
                userId: req.user.userId,
                fileId: fileId,
                action: 'FILE_DELETE_SOFT',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                metadata: { fileName: file.file_name },
                success: true
            });

            await client.query('COMMIT');

            res.json({
                message: 'File deleted',
                permanent: false
            });
        }

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('File deletion error:', error);

        await logAudit({
            userId: req.user.userId,
            fileId: req.params.fileId,
            action: 'FILE_DELETE_ERROR',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({
            error: 'File deletion failed',
            code: 'DELETE_ERROR'
        });
    } finally {
        client.release();
    }
});

/**
 * GET /files/:fileId/versions
 * Get file version history
 */
router.get('/:fileId/versions', authenticate, async (req, res) => {
    try {
        const { fileId } = req.params;

        // Check access
        const accessCheck = await pool.query(`
      SELECT 1 FROM files
      WHERE file_id = $1 
      AND (owner_id = $2 OR EXISTS (
        SELECT 1 FROM file_shares 
        WHERE file_id = $1 
        AND recipient_id = $2 
        AND is_active = TRUE
      ))
    `, [fileId, req.user.userId]);

        if (accessCheck.rows.length === 0) {
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        // Get versions
        const versionsResult = await pool.query(`
      SELECT 
        version_id,
        version_number,
        file_size,
        created_at,
        created_by,
        u.username as created_by_username
      FROM file_versions fv
      LEFT JOIN users u ON fv.created_by = u.user_id
      WHERE fv.file_id = $1
      ORDER BY version_number DESC
    `, [fileId]);

        res.json({ versions: versionsResult.rows });

    } catch (error) {
        console.error('Get versions error:', error);
        res.status(500).json({
            error: 'Failed to get file versions',
            code: 'GET_VERSIONS_ERROR'
        });
    }
});

/**
 * POST /files/:fileId/versions
 * Create new file version
 */
router.post('/:fileId/versions', authenticate, uploadLimiter, upload.single('file'), async (req, res) => {
    const client = await pool.connect();

    try {
        const { fileId } = req.params;

        if (!req.file) {
            return res.status(400).json({
                error: 'No file provided',
                code: 'NO_FILE'
            });
        }

        const {
            encryptedSymmetricKey,
            signature
        } = req.body;

        if (!encryptedSymmetricKey || !signature) {
            return res.status(400).json({
                error: 'Missing required fields',
                code: 'MISSING_FIELDS'
            });
        }

        await client.query('BEGIN');

        // Check ownership
        const fileResult = await client.query(
            'SELECT owner_id, version FROM files WHERE file_id = $1 AND is_deleted = FALSE',
            [fileId]
        );

        if (fileResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                error: 'File not found',
                code: 'FILE_NOT_FOUND'
            });
        }

        const file = fileResult.rows[0];

        if (file.owner_id !== req.user.userId) {
            await client.query('ROLLBACK');
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED'
            });
        }

        const newVersion = file.version + 1;
        const fileBuffer = req.file.buffer;
        const fileSize = req.file.size;

        // Generate S3 key for new version
        const s3Key = `files/${req.user.userId}/${fileId}/v${newVersion}`;

        // Upload to S3
        await uploadFile(fileBuffer, s3Key);

        // Update file record
        await client.query(`
      UPDATE files
      SET version = $1, 
          encrypted_size = $2,
          encrypted_symmetric_key = $3,
          signature = $4,
          s3_key = $5,
          updated_at = CURRENT_TIMESTAMP
      WHERE file_id = $6
    `, [newVersion, fileSize, encryptedSymmetricKey, signature, s3Key, fileId]);

        // Store version
        await client.query(`
      INSERT INTO file_versions (
        file_id,
        version_number,
        s3_key,
        encrypted_symmetric_key,
        signature,
        file_size,
        created_by
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [fileId, newVersion, s3Key, encryptedSymmetricKey, signature, fileSize, req.user.userId]);

        await client.query('COMMIT');

        await logAudit({
            userId: req.user.userId,
            fileId: fileId,
            action: 'FILE_VERSION_CREATED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            fileSize: fileSize,
            metadata: { version: newVersion },
            success: true
        });

        res.status(201).json({
            message: 'New version created',
            version: newVersion,
            fileSize: fileSize
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Create version error:', error);

        await logAudit({
            userId: req.user.userId,
            fileId: req.params.fileId,
            action: 'FILE_VERSION_ERROR',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({
            error: 'Failed to create version',
            code: 'CREATE_VERSION_ERROR'
        });
    } finally {
        client.release();
    }
});

module.exports = router;