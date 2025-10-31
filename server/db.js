/**
 * Database connection and schema initialization
 */
const { Pool } = require('pg');
const config = require('./config');

// Create connection pool
const pool = new Pool(
    config.database.connectionString
        ? { connectionString: config.database.connectionString, ssl: config.database.ssl }
        : config.database
);
// Test connection on startup
pool.on('connect', () => {
    console.log('✓ Database connection established');
});

pool.on('error', (err) => {
    console.error('Unexpected database error:', err);
    process.exit(-1);
});

/**
 * Initialize database schema
 * Creates all necessary tables and indexes
 */
async function initializeDatabase() {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        console.log('Creating database schema...');

        // Enable UUID extension
        await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');

        // Users table - stores user accounts and encryption keys
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

        // Files table - stores encrypted file metadata
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

        // File shares table - manages file sharing between users
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

        // Audit logs table - comprehensive security and performance tracking
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

        // File versions table - tracks file history
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
        created_by UUID REFERENCES users(user_id) ON DELETE SET NULL,
        UNIQUE(file_id, version_number)
      )
    `);

        // Session tokens table - manages user authentication
        await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);

        // Create performance indexes
        console.log('Creating indexes...');
        await client.query(`
      CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id) WHERE is_deleted = FALSE;
      CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_file_shares_file ON file_shares(file_id);
      CREATE INDEX IF NOT EXISTS idx_file_shares_recipient ON file_shares(recipient_id) WHERE is_active = TRUE;
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_file ON audit_logs(file_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
      CREATE INDEX IF NOT EXISTS idx_file_versions_file ON file_versions(file_id, version_number DESC);
    `);

        await client.query('COMMIT');
        console.log('✓ Database schema initialized successfully');

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Database initialization error:', error);
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Query helper with error handling
 */
async function query(text, params) {
    try {
        const result = await pool.query(text, params);
        return result;
    } catch (error) {
        console.error('Database query error:', error);
        throw error;
    }
}

/**
 * Transaction helper
 */
async function transaction(callback) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await callback(client);
        await client.query('COMMIT');
        return result;
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Graceful shutdown
 */
async function closePool() {
    await pool.end();
    console.log('✓ Database connection pool closed');
}

module.exports = {
    pool,
    query,
    transaction,
    initializeDatabase,
    closePool,
};
