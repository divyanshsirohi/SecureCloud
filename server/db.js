// db.js
const { Pool } = require('pg');

// Database connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false,
  max: 20, // maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Test connection
pool.on('connect', () => {
  console.log('[DB] Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected error on idle client', err);
  process.exit(-1);
});

/**
 * Initialize database schema
 * Creates all necessary tables and indexes
 */
async function initializeDatabase() {
    const client = await pool.connect();

    try {
        console.log('[DB] Starting database initialization...');

        await client.query('BEGIN');

        console.log('[DB] Creating UUID extension...');
        await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');

        console.log('[DB] Creating users table...');
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

        console.log('[DB] Creating files table...');
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

        console.log('[DB] Creating file_shares table...');
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

        console.log('[DB] Creating audit_logs table...');
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

        console.log('[DB] Creating file_versions table...');
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

        console.log('[DB] Creating sessions table...');
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

        console.log('[DB] Creating indexes...');
        await client.query(`
      CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id) WHERE is_deleted = FALSE;
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
    `);

        await client.query('COMMIT');
        console.log('[DB] ✓ Database schema initialized successfully');

        return true;

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('[DB] ✗ Database initialization error:', error.message);
        throw error;
    } finally {
        client.release();
    }
}

// CRITICAL: Export the function and pool
module.exports = {
  pool,
  initializeDatabase,
  // Add any other database functions you have
};
