/**
 * Local File Storage with Auto-Create Directory
 */
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');

// Use /tmp for Render (persists during request but not between deploys)
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, '../../uploads');

// Create directory synchronously on module load
try {
    if (!fsSync.existsSync(UPLOAD_DIR)) {
        fsSync.mkdirSync(UPLOAD_DIR, { recursive: true });
        console.log(`✓ Created upload directory: ${UPLOAD_DIR}`);
    }
} catch (error) {
    console.error('Failed to create upload directory:', error);
}

/**
 * Ensure upload directory exists
 */
async function ensureUploadDir() {
    try {
        await fs.access(UPLOAD_DIR);
    } catch {
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        console.log(`✓ Created upload directory: ${UPLOAD_DIR}`);
    }
}

/**
 * Upload file to local storage
 */
async function uploadFile(buffer, key, metadata = {}) {
    try {
        await ensureUploadDir();

        // Sanitize filename
        const safeKey = key.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        const filePath = path.join(UPLOAD_DIR, safeKey);

        // Ensure subdirectories exist
        const dir = path.dirname(filePath);
        await fs.mkdir(dir, { recursive: true });

        // Write file
        await fs.writeFile(filePath, buffer);

        console.log(`✓ [STORAGE] Uploaded: ${safeKey} (${buffer.length} bytes)`);

        return {
            location: filePath,
            etag: `"${crypto.createHash('md5').update(buffer).digest('hex')}"`,
            key: safeKey,
            bucket: 'local-storage',
            versionId: null
        };
    } catch (error) {
        console.error('Upload error:', error);
        throw new Error(`Failed to upload file: ${error.message}`);
    }
}

/**
 * Download file from local storage
 */
async function downloadFile(key) {
    try {
        const safeKey = key.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        const filePath = path.join(UPLOAD_DIR, safeKey);

        const buffer = await fs.readFile(filePath);
        console.log(`✓ [STORAGE] Downloaded: ${safeKey}`);
        return buffer;
    } catch (error) {
        console.error('Download error:', error);

        if (error.code === 'ENOENT') {
            throw new Error('File not found');
        }

        throw new Error(`Failed to download file: ${error.message}`);
    }
}

/**
 * Delete file from local storage
 */
async function deleteFile(key) {
    try {
        const safeKey = key.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        const filePath = path.join(UPLOAD_DIR, safeKey);

        await fs.unlink(filePath);
        console.log(`✓ [STORAGE] Deleted: ${safeKey}`);
    } catch (error) {
        console.error('Delete error:', error);
        if (error.code !== 'ENOENT') {
            throw new Error(`Failed to delete file: ${error.message}`);
        }
    }
}

/**
 * Delete multiple files
 */
async function deleteMultipleFiles(keys) {
    const deleted = [];
    const errors = [];

    for (const key of keys) {
        try {
            await deleteFile(key);
            deleted.push({ Key: key });
        } catch (error) {
            errors.push({ Key: key, Message: error.message });
        }
    }

    return { deleted, errors };
}

/**
 * Check if file exists
 */
async function fileExists(key) {
    try {
        const safeKey = key.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        const filePath = path.join(UPLOAD_DIR, safeKey);
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

/**
 * Test storage connection
 */
async function testConnection() {
    try {
        await ensureUploadDir();

        // Test write
        const testFile = path.join(UPLOAD_DIR, '.test');
        await fs.writeFile(testFile, 'test');
        await fs.unlink(testFile);

        console.log('✓ [STORAGE] Local storage initialized:', UPLOAD_DIR);
        return true;
    } catch (error) {
        console.error('✗ [STORAGE] Initialization failed:', error);
        return false;
    }
}

// Stubs for unused functions
function getFileStream(key) {
    throw new Error('getFileStream not implemented for local storage');
}

async function getFileMetadata(key) {
    const safeKey = key.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
    const filePath = path.join(UPLOAD_DIR, safeKey);
    const stats = await fs.stat(filePath);
    return {
        contentLength: stats.size,
        lastModified: stats.mtime,
    };
}

async function generatePresignedUrl(key, expiresIn = 3600) {
    throw new Error('generatePresignedUrl not implemented for local storage');
}

async function listFiles(prefix = '', maxKeys = 1000) {
    try {
        await ensureUploadDir();
        const files = await fs.readdir(UPLOAD_DIR);
        return files
            .filter(f => !f.startsWith('.'))
            .slice(0, maxKeys)
            .map(f => ({ key: f }));
    } catch {
        return [];
    }
}

async function copyFile(sourceKey, destinationKey) {
    const safeSource = sourceKey.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
    const safeDest = destinationKey.replace(/[^a-zA-Z0-9_\-\.]/g, '_');

    const sourcePath = path.join(UPLOAD_DIR, safeSource);
    const destPath = path.join(UPLOAD_DIR, safeDest);

    await fs.copyFile(sourcePath, destPath);
    return { success: true };
}

module.exports = {
    uploadFile,
    downloadFile,
    getFileStream,
    deleteFile,
    deleteMultipleFiles,
    fileExists,
    getFileMetadata,
    generatePresignedUrl,
    listFiles,
    copyFile,
    testConnection,
};
