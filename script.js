const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const argon2 = require('argon2');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

//config
const app = express();
const PORT = process.env.PORT || 3000;

// Database Configuration
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'secure_cloud',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// S3 Configuration
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION || 'us-east-1'
});

const S3_BUCKET = process.env.S3_BUCKET || 'secure-cloud-storage';

// Multer Configuration (memory storage for encrypted files)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

//middleware

app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Request logging middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

//db schema
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Users table
        await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        encrypted_private_key TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);

        // Files table
        await client.query(`
      CREATE TABLE IF NOT EXISTS files (
        file_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
        file_name TEXT NOT NULL,
        encrypted_file_name TEXT NOT NULL,
        s3_key TEXT NOT NULL,
        file_size BIGINT NOT NULL,
        encrypted_size BIGINT NOT NULL,
        mime_type VARCHAR(255),
        encrypted_symmetric_key TEXT NOT NULL,
        signature TEXT NOT NULL,
        version INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_deleted BOOLEAN DEFAULT FALSE
      )
    `);

        // File shares table
        await client.query(`
      CREATE TABLE IF NOT EXISTS file_shares (
        share_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        file_id UUID REFERENCES files(file_id) ON DELETE CASCADE,
        owner_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
        recipient_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
        wrapped_key TEXT NOT NULL,
        permissions VARCHAR(50) DEFAULT 'read',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        revoked_at TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE(file_id, recipient_id)
      )
    `);

        // Audit logs table
        await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
        file_id UUID REFERENCES files(file_id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        ip_address INET,
        user_agent TEXT,
        encryption_time_ms NUMERIC(10, 3),
        decryption_time_ms NUMERIC(10, 3),
        key_generation_time_ms NUMERIC(10, 3),
        avalanche_effect_percentage NUMERIC(5, 2),
        collision_resistance_score NUMERIC(10, 6),
        signature_verification_time_ms NUMERIC(10, 3),
        file_size_bytes BIGINT,
        encryption_algorithm VARCHAR(50),
        key_size INTEGER,
        metadata JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success BOOLEAN DEFAULT TRUE,
        error_message TEXT
      )
    `);

        // File versions table
        await client.query(`
      CREATE TABLE IF NOT EXISTS file_versions (
        version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        file_id UUID REFERENCES files(file_id) ON DELETE CASCADE,
        version_number INTEGER NOT NULL,
        s3_key TEXT NOT NULL,
        encrypted_symmetric_key TEXT NOT NULL,
        signature TEXT NOT NULL,
        file_size BIGINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by UUID REFERENCES users(user_id) ON DELETE SET NULL
      )
    `);

        // Session tokens table
        await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);

        // Create indexes
        await client.query(`
      CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
      CREATE INDEX IF NOT EXISTS idx_file_shares_file ON file_shares(file_id);
      CREATE INDEX IF NOT EXISTS idx_file_shares_recipient ON file_shares(recipient_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_file ON audit_logs(file_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
    `);

        await client.query('COMMIT');
        console.log('Database initialized successfully');
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Database initialization error:', error);
        throw error;
    } finally {
        client.release();
    }
}

//utils

// Generate secure random token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Hash token for storage
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

// Calculate avalanche effect (change in output bits for 1-bit input change)
function calculateAvalancheEffect(original, modified) {
    const hash1 = crypto.createHash('sha256').update(original).digest();
    const hash2 = crypto.createHash('sha256').update(modified).digest();

    let differentBits = 0;
    for (let i = 0; i < hash1.length; i++) {
        const xor = hash1[i] ^ hash2[i];
        differentBits += xor.toString(2).split('1').length - 1;
    }

    return (differentBits / (hash1.length * 8)) * 100;
}

// Calculate collision resistance score (entropy measure)
function calculateCollisionResistance(data) {
    const hash = crypto.createHash('sha256').update(data).digest();
    let entropy = 0;
    const freq = new Array(256).fill(0);

    for (let i = 0; i < hash.length; i++) {
        freq[hash[i]]++;
    }

    for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            const p = freq[i] / hash.length;
            entropy -= p * Math.log2(p);
        }
    }

    return entropy; // Higher is better (max 8.0 for perfect randomness)
}

// Authentication middleware
async function authenticate(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        const tokenHash = hashToken(token);

        const result = await pool.query(`
      SELECT s.user_id, s.expires_at, u.username, u.email, u.is_active
      FROM sessions s
      JOIN users u ON s.user_id = u.user_id
      WHERE s.token_hash = $1 AND s.is_active = TRUE
    `, [tokenHash]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        const session = result.rows[0];
        if (new Date(session.expires_at) < new Date()) {
            return res.status(401).json({ error: 'Token expired' });
        }

        if (!session.is_active) {
            return res.status(401).json({ error: 'User account is inactive' });
        }

        req.user = {
            userId: session.user_id,
            username: session.username,
            email: session.email
        };

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
}

// Audit logging function
async function logAudit(data) {
    try {
        await pool.query(`
      INSERT INTO audit_logs (
        user_id, file_id, action, ip_address, user_agent,
        encryption_time_ms, decryption_time_ms, key_generation_time_ms,
        avalanche_effect_percentage, collision_resistance_score,
        signature_verification_time_ms, file_size_bytes,
        encryption_algorithm, key_size, metadata, success, error_message
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
            data.metadata || null,
            data.success !== false,
            data.errorMessage || null
        ]);
    } catch (error) {
        console.error('Audit logging error:', error);
    }
}


//API endpoints


// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});


//user functions

// User registration
app.post('/api/auth/register', async (req, res) => {
    const startTime = Date.now();
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

        // Validate input
        if (!username || !email || !passwordHash || !publicKey || !encryptedPrivateKey || !salt) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        await client.query('BEGIN');

        // Check if user already exists
        const existingUser = await client.query(
            'SELECT user_id FROM users WHERE username = $1 OR email = $2',
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        // Hash password with Argon2
        const argon2Hash = await argon2.hash(passwordHash, {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 4
        });

        // Insert user
        const result = await client.query(`
      INSERT INTO users (username, email, password_hash, public_key, encrypted_private_key, salt)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING user_id, username, email, created_at
    `, [username, email, argon2Hash, publicKey, encryptedPrivateKey, salt]);

        await client.query('COMMIT');

        const keyGenerationTime = Date.now() - startTime;

        // Log audit
        await logAudit({
            userId: result.rows[0].user_id,
            action: 'USER_REGISTRATION',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            keyGenerationTime,
            keySize: 2048,
            metadata: { username, email },
            success: true
        });

        res.status(201).json({
            message: 'User registered successfully',
            user: result.rows[0]
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Registration error:', error);

        await logAudit({
            action: 'USER_REGISTRATION',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({ error: 'Registration failed' });
    } finally {
        client.release();
    }
});

// User login
app.post('/api/auth/login', async (req, res) => {
    const startTime = Date.now();

    try {
        const { username, passwordHash } = req.body;

        if (!username || !passwordHash) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Get user
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 AND is_active = TRUE',
            [username]
        );

        if (result.rows.length === 0) {
            await logAudit({
                action: 'LOGIN_FAILED',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                metadata: { username, reason: 'User not found' },
                success: false
            });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // Verify password
        const validPassword = await argon2.verify(user.password_hash, passwordHash);
        if (!validPassword) {
            await logAudit({
                userId: user.user_id,
                action: 'LOGIN_FAILED',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                metadata: { username, reason: 'Invalid password' },
                success: false
            });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate session token
        const token = generateToken();
        const tokenHash = hashToken(token);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        await pool.query(`
      INSERT INTO sessions (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)
    `, [user.user_id, tokenHash, expiresAt]);

        // Update last login
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = $1',
            [user.user_id]
        );

        const loginTime = Date.now() - startTime;

        await logAudit({
            userId: user.user_id,
            action: 'LOGIN_SUCCESS',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            keyGenerationTime: loginTime,
            metadata: { username },
            success: true
        });

        res.json({
            message: 'Login successful',
            token,
            expiresAt,
            user: {
                userId: user.user_id,
                username: user.username,
                email: user.email,
                publicKey: user.public_key,
                encryptedPrivateKey: user.encrypted_private_key,
                salt: user.salt
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// User logout
app.post('/api/auth/logout', authenticate, async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader.substring(7);
        const tokenHash = hashToken(token);

        await pool.query(
            'UPDATE sessions SET is_active = FALSE WHERE token_hash = $1',
            [tokenHash]
        );

        await logAudit({
            userId: req.user.userId,
            action: 'LOGOUT',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: true
        });

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Get user's public key
app.get('/api/users/:username/public-key', authenticate, async (req, res) => {
    try {
        const { username } = req.params;

        const result = await pool.query(
            'SELECT username, public_key FROM users WHERE username = $1 AND is_active = TRUE',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            username: result.rows[0].username,
            publicKey: result.rows[0].public_key
        });
    } catch (error) {
        console.error('Error fetching public key:', error);
        res.status(500).json({ error: 'Failed to fetch public key' });
    }
});


//file mgmt

// Upload file
app.post('/api/files/upload', authenticate, upload.single('file'), async (req, res) => {
    const startTime = Date.now();
    const client = await pool.connect();

    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const {
            fileName,
            encryptedFileName,
            encryptedSymmetricKey,
            signature,
            mimeType,
            originalSize
        } = req.body;

        if (!fileName || !encryptedFileName || !encryptedSymmetricKey || !signature) {
            return res.status(400).json({ error: 'Missing required metadata' });
        }

        const encryptedBuffer = req.file.buffer;
        const s3Key = `${req.user.userId}/${uuidv4()}`;

        // Calculate cryptographic metrics
        const testData = encryptedBuffer.slice(0, 1024).toString('hex');
        const modifiedData = testData.substring(0, testData.length - 1) +
            (testData[testData.length - 1] === '0' ? '1' : '0');

        const avalancheEffect = calculateAvalancheEffect(testData, modifiedData);
        const collisionResistance = calculateCollisionResistance(encryptedBuffer);

        // Upload to S3
        const uploadParams = {
            Bucket: S3_BUCKET,
            Key: s3Key,
            Body: encryptedBuffer,
            ContentType: 'application/octet-stream',
            ServerSideEncryption: 'AES256'
        };

        await s3.upload(uploadParams).promise();
        const uploadTime = Date.now() - startTime;

        await client.query('BEGIN');

        // Insert file record
        const result = await client.query(`
      INSERT INTO files (
        owner_id, file_name, encrypted_file_name, s3_key,
        file_size, encrypted_size, mime_type,
        encrypted_symmetric_key, signature
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING file_id, created_at
    `, [
            req.user.userId,
            fileName,
            encryptedFileName,
            s3Key,
            parseInt(originalSize),
            encryptedBuffer.length,
            mimeType,
            encryptedSymmetricKey,
            signature
        ]);

        const fileId = result.rows[0].file_id;

        // Create initial version
        await client.query(`
      INSERT INTO file_versions (
        file_id, version_number, s3_key, encrypted_symmetric_key,
        signature, file_size, created_by
      ) VALUES ($1, 1, $2, $3, $4, $5, $6)
    `, [fileId, s3Key, encryptedSymmetricKey, signature, encryptedBuffer.length, req.user.userId]);

        await client.query('COMMIT');

        // Log audit
        await logAudit({
            userId: req.user.userId,
            fileId,
            action: 'FILE_UPLOAD',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            encryptionTime: uploadTime,
            avalancheEffect,
            collisionResistance,
            fileSize: encryptedBuffer.length,
            encryptionAlgorithm: 'AES-256-GCM',
            keySize: 256,
            metadata: { fileName, mimeType },
            success: true
        });

        res.status(201).json({
            message: 'File uploaded successfully',
            file: {
                fileId,
                fileName,
                encryptedFileName,
                fileSize: parseInt(originalSize),
                encryptedSize: encryptedBuffer.length,
                mimeType,
                createdAt: result.rows[0].created_at,
                metrics: {
                    uploadTimeMs: uploadTime,
                    avalancheEffect: avalancheEffect.toFixed(2),
                    collisionResistance: collisionResistance.toFixed(6)
                }
            }
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('File upload error:', error);

        await logAudit({
            userId: req.user.userId,
            action: 'FILE_UPLOAD',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({ error: 'File upload failed' });
    } finally {
        client.release();
    }
});

// List user's files
app.get('/api/files', authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
      SELECT 
        f.file_id, f.file_name, f.encrypted_file_name, f.file_size,
        f.encrypted_size, f.mime_type, f.version, f.created_at, f.updated_at,
        COUNT(DISTINCT fs.share_id) as share_count
      FROM files f
      LEFT JOIN file_shares fs ON f.file_id = fs.file_id AND fs.is_active = TRUE
      WHERE f.owner_id = $1 AND f.is_deleted = FALSE
      GROUP BY f.file_id
      ORDER BY f.created_at DESC
    `, [req.user.userId]);

        res.json({ files: result.rows });
    } catch (error) {
        console.error('Error fetching files:', error);
        res.status(500).json({ error: 'Failed to fetch files' });
    }
});

// Get file metadata and download
app.get('/api/files/:fileId', authenticate, async (req, res) => {
    const startTime = Date.now();

    try {
        const { fileId } = req.params;

        // Check if user owns the file or has access via sharing
        const result = await pool.query(`
      SELECT 
        f.*, 
        fs.wrapped_key as shared_wrapped_key,
        CASE 
          WHEN f.owner_id = $1 THEN TRUE
          WHEN fs.recipient_id = $1 AND fs.is_active = TRUE THEN TRUE
          ELSE FALSE
        END as has_access
      FROM files f
      LEFT JOIN file_shares fs ON f.file_id = fs.file_id AND fs.recipient_id = $1
      WHERE f.file_id = $2 AND f.is_deleted = FALSE
    `, [req.user.userId, fileId]);

        if (result.rows.length === 0 || !result.rows[0].has_access) {
            return res.status(404).json({ error: 'File not found or access denied' });
        }

        const file = result.rows[0];

        // Download from S3
        const downloadParams = {
            Bucket: S3_BUCKET,
            Key: file.s3_key
        };

        const s3Object = await s3.getObject(downloadParams).promise();
        const downloadTime = Date.now() - startTime;

        // Calculate metrics
        const collisionResistance = calculateCollisionResistance(s3Object.Body);

        // Log audit
        await logAudit({
            userId: req.user.userId,
            fileId: file.file_id,
            action: 'FILE_DOWNLOAD',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            decryptionTime: downloadTime,
            collisionResistance,
            fileSize: s3Object.Body.length,
            encryptionAlgorithm: 'AES-256-GCM',
            metadata: { fileName: file.file_name },
            success: true
        });

        res.json({
            file: {
                fileId: file.file_id,
                fileName: file.file_name,
                encryptedFileName: file.encrypted_file_name,
                fileSize: file.file_size,
                encryptedSize: file.encrypted_size,
                mimeType: file.mime_type,
                encryptedSymmetricKey: file.owner_id === req.user.userId
                    ? file.encrypted_symmetric_key
                    : file.shared_wrapped_key,
                signature: file.signature,
                version: file.version,
                createdAt: file.created_at,
                updatedAt: file.updated_at
            },
            encryptedData: s3Object.Body.toString('base64'),
            metrics: {
                downloadTimeMs: downloadTime,
                collisionResistance: collisionResistance.toFixed(6)
            }
        });
    } catch (error) {
        console.error('File download error:', error);

        await logAudit({
            userId: req.user.userId,
            fileId: req.params.fileId,
            action: 'FILE_DOWNLOAD',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({ error: 'File download failed' });
    }
});

// Delete file
app.delete('/api/files/:fileId', authenticate, async (req, res) => {
    const client = await pool.connect();

    try {
        const { fileId } = req.params;

        await client.query('BEGIN');

        // Verify ownership
        const result = await pool.query(
            'SELECT s3_key FROM files WHERE file_id = $1 AND owner_id = $2 AND is_deleted = FALSE',
            [fileId, req.user.userId]
        );

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'File not found' });
        }

        // Soft delete
        await client.query(
            'UPDATE files SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE file_id = $1',
            [fileId]
        );

        // Deactivate all shares
        await client.query(
            'UPDATE file_shares SET is_active = FALSE, revoked_at = CURRENT_TIMESTAMP WHERE file_id = $1',
            [fileId]
        );

        await client.query('COMMIT');

        // Log audit
        await logAudit({
            userId: req.user.userId,
            fileId,
            action: 'FILE_DELETE',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: true
        });

        res.json({ message: 'File deleted successfully' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('File deletion error:', error);
        res.status(500).json({ error: 'File deletion failed' });
    } finally {
        client.release();
    }
});


//file sharing

// Share file with user
app.post('/api/files/:fileId/share', authenticate, async (req, res) => {
    const startTime = Date.now();
    const client = await pool.connect();

    try {
        const { fileId } = req.params;
        const { recipientUsername, wrappedKey, permissions } = req.body;

        if (!recipientUsername || !wrappedKey) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        await client.query('BEGIN');

        // Verify file ownership
        const fileResult = await client.query(
            'SELECT file_id, file_name FROM files WHERE file_id = $1 AND owner_id = $2 AND is_deleted = FALSE',
            [fileId, req.user.userId]
        );

        if (fileResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'File not found' });
        }

        // Get recipient user
        const recipientResult = await client.query(
            'SELECT user_id, username FROM users WHERE username = $1 AND is_active = TRUE',
            [recipientUsername]
        );

        if (recipientResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Recipient user not found' });
        }

        const recipientId = recipientResult.rows[0].user_id;

        // Check if share already exists
        const existingShare = await client.query(
            'SELECT share_id, is_active FROM file_shares WHERE file_id = $1 AND recipient_id = $2',
            [fileId, recipientId]
        );

        let shareId;
        if (existingShare.rows.length > 0) {
            // Update existing share
            const updateResult = await client.query(`
        UPDATE file_shares 
        SET wrapped_key = $1, permissions = $2, is_active = TRUE, 
            revoked_at = NULL, created_at = CURRENT_TIMESTAMP
        WHERE file_id = $3 AND recipient_id = $4
        RETURNING share_id
      `, [wrappedKey, permissions || 'read', fileId, recipientId]);
            shareId = updateResult.rows[0].share_id;
        } else {
            // Create new share
            const insertResult = await client.query(`
        INSERT INTO file_shares (file_id, owner_id, recipient_id, wrapped_key, permissions)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING share_id
      `, [fileId, req.user.userId, recipientId, wrappedKey, permissions || 'read']);
            shareId = insertResult.rows[0].share_id;
        }

        await client.query('COMMIT');

        const shareTime = Date.now() - startTime;

        // Log audit
        await logAudit({
            userId: req.user.userId,
            fileId,
            action: 'FILE_SHARE',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            encryptionTime: shareTime,
            metadata: {
                recipientUsername,
                recipientId,
                permissions: permissions || 'read',
                fileName: fileResult.rows[0].file_name
            },
            success: true
        });

        res.status(201).json({
            message: 'File shared successfully',
            share: {
                shareId,
                fileId,
                recipientUsername,
                permissions: permissions || 'read',
                createdAt: new Date().toISOString()
            }
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('File sharing error:', error);

        await logAudit({
            userId: req.user.userId,
            fileId: req.params.fileId,
            action: 'FILE_SHARE',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({ error: 'File sharing failed' });
    } finally {
        client.release();
    }
});

// List file shares
app.get('/api/files/:fileId/shares', authenticate, async (req, res) => {
    try {
        const { fileId } = req.params;

        // Verify ownership
        const fileResult = await pool.query(
            'SELECT file_id FROM files WHERE file_id = $1 AND owner_id = $2 AND is_deleted = FALSE',
            [fileId, req.user.userId]
        );

        if (fileResult.rows.length === 0) {
            return res.status(404).json({ error: 'File not found' });
        }

        const result = await pool.query(`
      SELECT 
        fs.share_id, fs.permissions, fs.created_at, fs.revoked_at, fs.is_active,
        u.username, u.email
      FROM file_shares fs
      JOIN users u ON fs.recipient_id = u.user_id
      WHERE fs.file_id = $1 AND fs.owner_id = $2
      ORDER BY fs.created_at DESC
    `, [fileId, req.user.userId]);

        res.json({ shares: result.rows });
    } catch (error) {
        console.error('Error fetching shares:', error);
        res.status(500).json({ error: 'Failed to fetch shares' });
    }
});

// Revoke file share
app.delete('/api/files/:fileId/shares/:shareId', authenticate, async (req, res) => {
    const client = await pool.connect();

    try {
        const { fileId, shareId } = req.params;

        await client.query('BEGIN');

        // Verify ownership and revoke
        const result = await client.query(`
      UPDATE file_shares 
      SET is_active = FALSE, revoked_at = CURRENT_TIMESTAMP
      WHERE share_id = $1 AND file_id = $2 AND owner_id = $3 AND is_active = TRUE
      RETURNING recipient_id
    `, [shareId, fileId, req.user.userId]);

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Share not found' });
        }

        await client.query('COMMIT');

        // Log audit
        await logAudit({
            userId: req.user.userId,
            fileId,
            action: 'FILE_SHARE_REVOKE',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { shareId, recipientId: result.rows[0].recipient_id },
            success: true
        });

        res.json({ message: 'Share revoked successfully' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Share revocation error:', error);
        res.status(500).json({ error: 'Share revocation failed' });
    } finally {
        client.release();
    }
});

// List shared with me
app.get('/api/files/shared-with-me', authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
      SELECT 
        f.file_id, f.file_name, f.encrypted_file_name, f.file_size,
        f.encrypted_size, f.mime_type, f.created_at,
        u.username as owner_username,
        fs.permissions, fs.created_at as shared_at
      FROM file_shares fs
      JOIN files f ON fs.file_id = f.file_id
      JOIN users u ON f.owner_id = u.user_id
      WHERE fs.recipient_id = $1 AND fs.is_active = TRUE AND f.is_deleted = FALSE
      ORDER BY fs.created_at DESC
    `, [req.user.userId]);

        res.json({ sharedFiles: result.rows });
    } catch (error) {
        console.error('Error fetching shared files:', error);
        res.status(500).json({ error: 'Failed to fetch shared files' });
    }
});

//file endpoints

// Create new file version
app.post('/api/files/:fileId/versions', authenticate, upload.single('file'), async (req, res) => {
    const startTime = Date.now();
    const client = await pool.connect();

    try {
        const { fileId } = req.params;

        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const { encryptedSymmetricKey, signature } = req.body;

        if (!encryptedSymmetricKey || !signature) {
            return res.status(400).json({ error: 'Missing required metadata' });
        }

        await client.query('BEGIN');

        // Verify ownership
        const fileResult = await client.query(
            'SELECT file_id, version, file_name FROM files WHERE file_id = $1 AND owner_id = $2 AND is_deleted = FALSE',
            [fileId, req.user.userId]
        );

        if (fileResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'File not found' });
        }

        const currentVersion = fileResult.rows[0].version;
        const newVersion = currentVersion + 1;

        const encryptedBuffer = req.file.buffer;
        const s3Key = `${req.user.userId}/${uuidv4()}-v${newVersion}`;

        // Upload to S3
        const uploadParams = {
            Bucket: S3_BUCKET,
            Key: s3Key,
            Body: encryptedBuffer,
            ContentType: 'application/octet-stream',
            ServerSideEncryption: 'AES256'
        };

        await s3.upload(uploadParams).promise();

        // Create version record
        await client.query(`
      INSERT INTO file_versions (
        file_id, version_number, s3_key, encrypted_symmetric_key,
        signature, file_size, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [fileId, newVersion, s3Key, encryptedSymmetricKey, signature, encryptedBuffer.length, req.user.userId]);

        // Update file record
        await client.query(`
      UPDATE files 
      SET version = $1, s3_key = $2, encrypted_symmetric_key = $3, 
          signature = $4, encrypted_size = $5, updated_at = CURRENT_TIMESTAMP
      WHERE file_id = $6
    `, [newVersion, s3Key, encryptedSymmetricKey, signature, encryptedBuffer.length, fileId]);

        await client.query('COMMIT');

        const versionTime = Date.now() - startTime;

        // Log audit
        await logAudit({
            userId: req.user.userId,
            fileId,
            action: 'FILE_VERSION_CREATE',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            encryptionTime: versionTime,
            fileSize: encryptedBuffer.length,
            metadata: {
                fileName: fileResult.rows[0].file_name,
                versionNumber: newVersion
            },
            success: true
        });

        res.status(201).json({
            message: 'New version created successfully',
            version: {
                fileId,
                versionNumber: newVersion,
                fileSize: encryptedBuffer.length,
                createdAt: new Date().toISOString()
            }
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Version creation error:', error);

        await logAudit({
            userId: req.user.userId,
            fileId: req.params.fileId,
            action: 'FILE_VERSION_CREATE',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            success: false,
            errorMessage: error.message
        });

        res.status(500).json({ error: 'Version creation failed' });
    } finally {
        client.release();
    }
});

// List file versions
app.get('/api/files/:fileId/versions', authenticate, async (req, res) => {
    try {
        const { fileId } = req.params;

        // Verify access
        const accessCheck = await pool.query(`
      SELECT f.file_id 
      FROM files f
      LEFT JOIN file_shares fs ON f.file_id = fs.file_id AND fs.recipient_id = $1 AND fs.is_active = TRUE
      WHERE f.file_id = $2 AND f.is_deleted = FALSE
        AND (f.owner_id = $1 OR fs.share_id IS NOT NULL)
    `, [req.user.userId, fileId]);

        if (accessCheck.rows.length === 0) {
            return res.status(404).json({ error: 'File not found or access denied' });
        }

        const result = await pool.query(`
      SELECT 
        fv.version_id, fv.version_number, fv.file_size, fv.created_at,
        u.username as created_by_username
      FROM file_versions fv
      JOIN users u ON fv.created_by = u.user_id
      WHERE fv.file_id = $1
      ORDER BY fv.version_number DESC
    `, [fileId]);

        res.json({ versions: result.rows });
    } catch (error) {
        console.error('Error fetching versions:', error);
        res.status(500).json({ error: 'Failed to fetch versions' });
    }
});

// Download specific version
app.get('/api/files/:fileId/versions/:versionNumber', authenticate, async (req, res) => {
    const startTime = Date.now();

    try {
        const { fileId, versionNumber } = req.params;

        // Verify access
        const result = await pool.query(`
      SELECT 
        fv.*, f.file_name, f.mime_type,
        CASE 
          WHEN f.owner_id = $1 THEN TRUE
          WHEN fs.recipient_id = $1 AND fs.is_active = TRUE THEN TRUE
          ELSE FALSE
        END as has_access
      FROM file_versions fv
      JOIN files f ON fv.file_id = f.file_id
      LEFT JOIN file_shares fs ON f.file_id = fs.file_id AND fs.recipient_id = $1
      WHERE fv.file_id = $2 AND fv.version_number = $3 AND f.is_deleted = FALSE
    `, [req.user.userId, fileId, versionNumber]);

        if (result.rows.length === 0 || !result.rows[0].has_access) {
            return res.status(404).json({ error: 'Version not found or access denied' });
        }

        const version = result.rows[0];

        // Download from S3
        const downloadParams = {
            Bucket: S3_BUCKET,
            Key: version.s3_key
        };

        const s3Object = await s3.getObject(downloadParams).promise();
        const downloadTime = Date.now() - startTime;

        // Log audit
        await logAudit({
            userId: req.user.userId,
            fileId,
            action: 'FILE_VERSION_DOWNLOAD',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            decryptionTime: downloadTime,
            fileSize: s3Object.Body.length,
            metadata: {
                fileName: version.file_name,
                versionNumber: version.version_number
            },
            success: true
        });

        res.json({
            version: {
                fileId: version.file_id,
                versionNumber: version.version_number,
                fileName: version.file_name,
                mimeType: version.mime_type,
                fileSize: version.file_size,
                encryptedSymmetricKey: version.encrypted_symmetric_key,
                signature: version.signature,
                createdAt: version.created_at
            },
            encryptedData: s3Object.Body.toString('base64'),
            metrics: {
                downloadTimeMs: downloadTime
            }
        });
    } catch (error) {
        console.error('Version download error:', error);
        res.status(500).json({ error: 'Version download failed' });
    }
});

//audit logs


// Get user's audit logs
app.get('/api/audit/logs', authenticate, async (req, res) => {
    try {
        const { limit = 50, offset = 0, action, fileId, startDate, endDate } = req.query;

        let query = `
      SELECT 
        al.log_id, al.action, al.timestamp, al.ip_address,
        al.encryption_time_ms, al.decryption_time_ms, al.key_generation_time_ms,
        al.avalanche_effect_percentage, al.collision_resistance_score,
        al.signature_verification_time_ms, al.file_size_bytes,
        al.encryption_algorithm, al.key_size, al.metadata,
        al.success, al.error_message,
        f.file_name
      FROM audit_logs al
      LEFT JOIN files f ON al.file_id = f.file_id
      WHERE al.user_id = $1
    `;

        const params = [req.user.userId];
        let paramIndex = 2;

        if (action) {
            query += ` AND al.action = ${paramIndex}`;
            params.push(action);
            paramIndex++;
        }

        if (fileId) {
            query += ` AND al.file_id = ${paramIndex}`;
            params.push(fileId);
            paramIndex++;
        }

        if (startDate) {
            query += ` AND al.timestamp >= ${paramIndex}`;
            params.push(startDate);
            paramIndex++;
        }

        if (endDate) {
            query += ` AND al.timestamp <= ${paramIndex}`;
            params.push(endDate);
            paramIndex++;
        }

        query += ` ORDER BY al.timestamp DESC LIMIT ${paramIndex} OFFSET ${paramIndex + 1}`;
        params.push(parseInt(limit), parseInt(offset));

        const result = await pool.query(query, params);

        // Get total count
        let countQuery = `
      SELECT COUNT(*) 
      FROM audit_logs 
      WHERE user_id = $1
    `;
        const countParams = [req.user.userId];

        if (action || fileId || startDate || endDate) {
            let countParamIndex = 2;
            if (action) {
                countQuery += ` AND action = ${countParamIndex}`;
                countParams.push(action);
                countParamIndex++;
            }
            if (fileId) {
                countQuery += ` AND file_id = ${countParamIndex}`;
                countParams.push(fileId);
                countParamIndex++;
            }
            if (startDate) {
                countQuery += ` AND timestamp >= ${countParamIndex}`;
                countParams.push(startDate);
                countParamIndex++;
            }
            if (endDate) {
                countQuery += ` AND timestamp <= ${countParamIndex}`;
                countParams.push(endDate);
            }
        }

        const countResult = await pool.query(countQuery, countParams);

        res.json({
            logs: result.rows,
            pagination: {
                total: parseInt(countResult.rows[0].count),
                limit: parseInt(limit),
                offset: parseInt(offset)
            }
        });
    } catch (error) {
        console.error('Error fetching audit logs:', error);
        res.status(500).json({ error: 'Failed to fetch audit logs' });
    }
});

// Get audit statistics
app.get('/api/audit/statistics', authenticate, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;

        let dateFilter = '';
        const params = [req.user.userId];
        let paramIndex = 2;

        if (startDate && endDate) {
            dateFilter = ` AND timestamp BETWEEN ${paramIndex} AND ${paramIndex + 1}`;
            params.push(startDate, endDate);
        }

        // Overall statistics
        const statsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_operations,
        COUNT(*) FILTER (WHERE success = TRUE) as successful_operations,
        COUNT(*) FILTER (WHERE success = FALSE) as failed_operations,
        COUNT(DISTINCT file_id) as unique_files_accessed,
        AVG(encryption_time_ms) FILTER (WHERE encryption_time_ms IS NOT NULL) as avg_encryption_time,
        AVG(decryption_time_ms) FILTER (WHERE decryption_time_ms IS NOT NULL) as avg_decryption_time,
        AVG(key_generation_time_ms) FILTER (WHERE key_generation_time_ms IS NOT NULL) as avg_key_generation_time,
        AVG(signature_verification_time_ms) FILTER (WHERE signature_verification_time_ms IS NOT NULL) as avg_signature_verification_time,
        AVG(avalanche_effect_percentage) FILTER (WHERE avalanche_effect_percentage IS NOT NULL) as avg_avalanche_effect,
        AVG(collision_resistance_score) FILTER (WHERE collision_resistance_score IS NOT NULL) as avg_collision_resistance,
        SUM(file_size_bytes) FILTER (WHERE action = 'FILE_UPLOAD') as total_data_uploaded,
        SUM(file_size_bytes) FILTER (WHERE action = 'FILE_DOWNLOAD') as total_data_downloaded
      FROM audit_logs
      WHERE user_id = $1 ${dateFilter}
    `, params);

        // Action breakdown
        const actionBreakdown = await pool.query(`
      SELECT 
        action,
        COUNT(*) as count,
        AVG(encryption_time_ms) as avg_time_ms
      FROM audit_logs
      WHERE user_id = $1 ${dateFilter}
      GROUP BY action
      ORDER BY count DESC
    `, params);

        // Recent activity timeline
        const timeline = await pool.query(`
      SELECT 
        DATE_TRUNC('day', timestamp) as date,
        action,
        COUNT(*) as count
      FROM audit_logs
      WHERE user_id = $1 ${dateFilter}
      GROUP BY DATE_TRUNC('day', timestamp), action
      ORDER BY date DESC
      LIMIT 30
    `, params);

        // Security metrics over time
        const securityMetrics = await pool.query(`
      SELECT 
        DATE_TRUNC('day', timestamp) as date,
        AVG(avalanche_effect_percentage) as avg_avalanche_effect,
        AVG(collision_resistance_score) as avg_collision_resistance,
        COUNT(*) FILTER (WHERE success = FALSE) as failed_operations
      FROM audit_logs
      WHERE user_id = $1 ${dateFilter}
        AND (avalanche_effect_percentage IS NOT NULL OR collision_resistance_score IS NOT NULL)
      GROUP BY DATE_TRUNC('day', timestamp)
      ORDER BY date DESC
      LIMIT 30
    `, params);

        res.json({
            statistics: statsResult.rows[0],
            actionBreakdown: actionBreakdown.rows,
            timeline: timeline.rows,
            securityMetrics: securityMetrics.rows
        });
    } catch (error) {
        console.error('Error fetching audit statistics:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Get file-specific audit trail
app.get('/api/audit/files/:fileId', authenticate, async (req, res) => {
    try {
        const { fileId } = req.params;

        // Verify access to file
        const accessCheck = await pool.query(`
      SELECT f.file_id 
      FROM files f
      LEFT JOIN file_shares fs ON f.file_id = fs.file_id AND fs.recipient_id = $1 AND fs.is_active = TRUE
      WHERE f.file_id = $2 AND f.is_deleted = FALSE
        AND (f.owner_id = $1 OR fs.share_id IS NOT NULL)
    `, [req.user.userId, fileId]);

        if (accessCheck.rows.length === 0) {
            return res.status(404).json({ error: 'File not found or access denied' });
        }

        const result = await pool.query(`
      SELECT 
        al.log_id, al.action, al.timestamp, al.ip_address,
        al.encryption_time_ms, al.decryption_time_ms,
        al.signature_verification_time_ms, al.file_size_bytes,
        al.avalanche_effect_percentage, al.collision_resistance_score,
        al.metadata, al.success, al.error_message,
        u.username
      FROM audit_logs al
      JOIN users u ON al.user_id = u.user_id
      WHERE al.file_id = $1
      ORDER BY al.timestamp DESC
    `, [fileId]);

        res.json({ auditTrail: result.rows });
    } catch (error) {
        console.error('Error fetching file audit trail:', error);
        res.status(500).json({ error: 'Failed to fetch audit trail' });
    }
});

// Export audit logs (CSV format)
app.get('/api/audit/export', authenticate, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;

        let query = `
      SELECT 
        al.log_id, al.action, al.timestamp, al.ip_address, al.user_agent,
        al.encryption_time_ms, al.decryption_time_ms, al.key_generation_time_ms,
        al.avalanche_effect_percentage, al.collision_resistance_score,
        al.signature_verification_time_ms, al.file_size_bytes,
        al.encryption_algorithm, al.key_size, al.success, al.error_message,
        f.file_name
      FROM audit_logs al
      LEFT JOIN files f ON al.file_id = f.file_id
      WHERE al.user_id = $1
    `;

        const params = [req.user.userId];

        if (startDate && endDate) {
            query += ` AND al.timestamp BETWEEN $2 AND $3`;
            params.push(startDate, endDate);
        }

        query += ` ORDER BY al.timestamp DESC`;

        const result = await pool.query(query, params);

        // Convert to CSV
        let csv = 'Log ID,Action,Timestamp,IP Address,Encryption Time (ms),Decryption Time (ms),Key Generation Time (ms),Avalanche Effect (%),Collision Resistance,Signature Verification (ms),File Size (bytes),Algorithm,Key Size,Success,Error,File Name\n';

        result.rows.forEach(row => {
            csv += `${row.log_id},${row.action},${row.timestamp},${row.ip_address || ''},${row.encryption_time_ms || ''},${row.decryption_time_ms || ''},${row.key_generation_time_ms || ''},${row.avalanche_effect_percentage || ''},${row.collision_resistance_score || ''},${row.signature_verification_time_ms || ''},${row.file_size_bytes || ''},${row.encryption_algorithm || ''},${row.key_size || ''},${row.success},${row.error_message || ''},"${row.file_name || ''}"\n`;
        });

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=audit_logs_${Date.now()}.csv`);
        res.send(csv);
    } catch (error) {
        console.error('Error exporting audit logs:', error);
        res.status(500).json({ error: 'Failed to export audit logs' });
    }
});

//system checks

// Get system health metrics (for monitoring)
app.get('/api/admin/health', authenticate, async (req, res) => {
    try {
        // Check database connection
        const dbHealth = await pool.query('SELECT NOW()');

        // Get basic statistics
        const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE is_active = TRUE) as active_users,
        (SELECT COUNT(*) FROM files WHERE is_deleted = FALSE) as total_files,
        (SELECT SUM(encrypted_size) FROM files WHERE is_deleted = FALSE) as total_storage_bytes,
        (SELECT COUNT(*) FROM file_shares WHERE is_active = TRUE) as active_shares,
        (SELECT COUNT(*) FROM audit_logs WHERE timestamp > NOW() - INTERVAL '24 hours') as logs_24h
    `);

        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            database: {
                connected: true,
                serverTime: dbHealth.rows[0].now
            },
            statistics: stats.rows[0]
        });
    } catch (error) {
        console.error('Health check error:', error);
        res.status(500).json({
            status: 'unhealthy',
            error: error.message
        });
    }
});

// Cleanup old sessions
app.post('/api/admin/cleanup-sessions', authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
      UPDATE sessions 
      SET is_active = FALSE 
      WHERE expires_at < NOW() AND is_active = TRUE
      RETURNING session_id
    `);

        await logAudit({
            userId: req.user.userId,
            action: 'SESSION_CLEANUP',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { cleanedSessions: result.rows.length },
            success: true
        });

        res.json({
            message: 'Session cleanup completed',
            cleanedSessions: result.rows.length
        });
    } catch (error) {
        console.error('Session cleanup error:', error);
        res.status(500).json({ error: 'Session cleanup failed' });
    }
});


//err handling

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);

    logAudit({
        userId: req.user?.userId,
        action: 'SYSTEM_ERROR',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        errorMessage: err.message
    }).catch(console.error);

    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});


//server

async function startServer() {
    try {
        // Initialize database
        await initializeDatabase();
        console.log('✓ Database initialized');

        // Test S3 connection
        try {
            await s3.headBucket({ Bucket: S3_BUCKET }).promise();
            console.log('S3 bucket connected');
        } catch (error) {
            console.warn('S3 bucket not accessible:', error.message);
            console.warn('Make sure AWS credentials and bucket name are configured');
        }

        // Start server
        app.listen(PORT,);
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('\nSIGINT received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

// Start the server
startServer();