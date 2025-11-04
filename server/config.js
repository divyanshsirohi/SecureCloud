require('dotenv').config();

module.exports = {
    PORT: process.env.PORT || 3000,
    NODE_ENV: process.env.NODE_ENV || 'development',
    FRONTEND_URL: process.env.FRONTEND_URL || '*',

    database: {
        // Railway provides DATABASE_URL
        connectionString: process.env.DATABASE_URL,
        // Fallback to individual vars
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        database: process.env.DB_NAME || 'secure_cloud',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'password',
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    },

    aws: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        region: process.env.AWS_REGION || 'eu-north-1',
        bucket: process.env.S3_BUCKET || 'vercel-clone-outputs-divyansh',
        storageProvider: process.env.STORAGE_PROVIDER || 'local',
    },

    security: {
        argon2: {
            type: 2,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 4,
        },
        sessionExpiryHours: 24,
        tokenLength: 32,
    },

    rateLimit: {
        windowMs: 15 * 60 * 1000,
        max: 100,
        message: 'Too many requests from this IP, please try again later.',
    },

    upload: {
        maxFileSize: 100 * 1024 * 1024,
        requestSizeLimit: '50mb',
    },

    encryption: {
        algorithm: 'AES-256-GCM',
        keySize: 256,
        rsaKeySize: 2048,
    },

    audit: {
        retention_days: 90,
        exportMaxRecords: 10000,
    },
};
