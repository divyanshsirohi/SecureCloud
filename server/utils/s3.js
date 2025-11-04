/**
 * Storage Service - S3 with Local Storage Fallback
 * Supports both AWS S3 and local file system based on configuration
 */

const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, 
        DeleteObjectsCommand, HeadObjectCommand, ListObjectsV2Command, 
        CopyObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Readable } = require('stream');
const config = require('../config');

// Storage provider configuration
const STORAGE_PROVIDER = config.aws.storageProvider || 'local';
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, '../../uploads');

// S3 Client initialization
let s3Client = null;

if (STORAGE_PROVIDER === 's3') {
    if (!config.aws.accessKeyId || !config.aws.secretAccessKey) {
        console.error('✗ [S3] Missing AWS credentials');
        throw new Error('AWS credentials not configured');
    }

    s3Client = new S3Client({
        region: config.aws.region,
        credentials: {
            accessKeyId: config.aws.accessKeyId,
            secretAccessKey: config.aws.secretAccessKey,
        },
    });

    console.log(`✓ [S3] Client initialized - Region: ${config.aws.region}, Bucket: ${config.aws.bucket}`);
} else {
    // Create local storage directory
    try {
        if (!fsSync.existsSync(UPLOAD_DIR)) {
            fsSync.mkdirSync(UPLOAD_DIR, { recursive: true });
            console.log(`✓ [LOCAL] Created upload directory: ${UPLOAD_DIR}`);
        }
    } catch (error) {
        console.error('✗ [LOCAL] Failed to create upload directory:', error);
    }
}

/**
 * Sanitize file key to prevent path traversal
 */
function sanitizeKey(key) {
    return key.replace(/[^a-zA-Z0-9_\-\.\/]/g, '_').replace(/\.\./g, '_');
}

/**
 * Ensure local upload directory exists
 */
async function ensureUploadDir() {
    try {
        await fs.access(UPLOAD_DIR);
    } catch {
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        console.log(`✓ [LOCAL] Created upload directory: ${UPLOAD_DIR}`);
    }
}

/**
 * Upload file to S3
 */
async function uploadToS3(buffer, key, metadata = {}) {
    const command = new PutObjectCommand({
        Bucket: config.aws.bucket,
        Key: key,
        Body: buffer,
        Metadata: metadata,
        ContentType: metadata.contentType || 'application/octet-stream',
    });

    const response = await s3Client.send(command);

    return {
        location: `https://${config.aws.bucket}.s3.${config.aws.region}.amazonaws.com/${key}`,
        etag: response.ETag,
        key: key,
        bucket: config.aws.bucket,
        versionId: response.VersionId || null,
    };
}

/**
 * Upload file to local storage
 */
async function uploadToLocal(buffer, key, metadata = {}) {
    await ensureUploadDir();

    const safeKey = sanitizeKey(key);
    const filePath = path.join(UPLOAD_DIR, safeKey);

    // Ensure subdirectories exist
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true });

    // Write file
    await fs.writeFile(filePath, buffer);

    return {
        location: filePath,
        etag: `"${crypto.createHash('md5').update(buffer).digest('hex')}"`,
        key: safeKey,
        bucket: 'local-storage',
        versionId: null,
    };
}

/**
 * Upload file (unified interface)
 */
async function uploadFile(buffer, key, metadata = {}) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            const result = await uploadToS3(buffer, key, metadata);
            console.log(`✓ [S3] Uploaded: ${key} (${buffer.length} bytes)`);
            return result;
        } else {
            const result = await uploadToLocal(buffer, key, metadata);
            console.log(`✓ [LOCAL] Uploaded: ${key} (${buffer.length} bytes)`);
            return result;
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] Upload error:`, error);
        throw new Error(`Failed to upload file: ${error.message}`);
    }
}

/**
 * Download file from S3
 */
async function downloadFromS3(key) {
    const command = new GetObjectCommand({
        Bucket: config.aws.bucket,
        Key: key,
    });

    const response = await s3Client.send(command);

    // Convert stream to buffer
    const chunks = [];
    for await (const chunk of response.Body) {
        chunks.push(chunk);
    }

    return Buffer.concat(chunks);
}

/**
 * Download file from local storage
 */
async function downloadFromLocal(key) {
    const safeKey = sanitizeKey(key);
    const filePath = path.join(UPLOAD_DIR, safeKey);
    return await fs.readFile(filePath);
}

/**
 * Download file (unified interface)
 */
async function downloadFile(key) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            const buffer = await downloadFromS3(key);
            console.log(`✓ [S3] Downloaded: ${key}`);
            return buffer;
        } else {
            const buffer = await downloadFromLocal(key);
            console.log(`✓ [LOCAL] Downloaded: ${key}`);
            return buffer;
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] Download error:`, error);

        if (error.name === 'NoSuchKey' || error.code === 'ENOENT') {
            throw new Error('File not found');
        }

        throw new Error(`Failed to download file: ${error.message}`);
    }
}

/**
 * Get file stream from S3
 */
function getFileStreamFromS3(key) {
    const command = new GetObjectCommand({
        Bucket: config.aws.bucket,
        Key: key,
    });

    return s3Client.send(command).then(response => response.Body);
}

/**
 * Get file stream from local storage
 */
function getFileStreamFromLocal(key) {
    const safeKey = sanitizeKey(key);
    const filePath = path.join(UPLOAD_DIR, safeKey);
    return fsSync.createReadStream(filePath);
}

/**
 * Get file stream (unified interface)
 */
function getFileStream(key) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            return getFileStreamFromS3(key);
        } else {
            return getFileStreamFromLocal(key);
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] Stream error:`, error);
        throw new Error(`Failed to get file stream: ${error.message}`);
    }
}

/**
 * Delete file from S3
 */
async function deleteFromS3(key) {
    const command = new DeleteObjectCommand({
        Bucket: config.aws.bucket,
        Key: key,
    });

    await s3Client.send(command);
}

/**
 * Delete file from local storage
 */
async function deleteFromLocal(key) {
    const safeKey = sanitizeKey(key);
    const filePath = path.join(UPLOAD_DIR, safeKey);
    await fs.unlink(filePath);
}

/**
 * Delete file (unified interface)
 */
async function deleteFile(key) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            await deleteFromS3(key);
            console.log(`✓ [S3] Deleted: ${key}`);
        } else {
            await deleteFromLocal(key);
            console.log(`✓ [LOCAL] Deleted: ${key}`);
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] Delete error:`, error);
        
        // Don't throw error if file doesn't exist
        if (error.name !== 'NoSuchKey' && error.code !== 'ENOENT') {
            throw new Error(`Failed to delete file: ${error.message}`);
        }
    }
}

/**
 * Delete multiple files from S3
 */
async function deleteMultipleFromS3(keys) {
    if (keys.length === 0) {
        return { deleted: [], errors: [] };
    }

    const command = new DeleteObjectsCommand({
        Bucket: config.aws.bucket,
        Delete: {
            Objects: keys.map(key => ({ Key: key })),
            Quiet: false,
        },
    });

    const response = await s3Client.send(command);

    return {
        deleted: response.Deleted || [],
        errors: response.Errors || [],
    };
}

/**
 * Delete multiple files from local storage
 */
async function deleteMultipleFromLocal(keys) {
    const deleted = [];
    const errors = [];

    for (const key of keys) {
        try {
            await deleteFromLocal(key);
            deleted.push({ Key: key });
        } catch (error) {
            if (error.code !== 'ENOENT') {
                errors.push({ Key: key, Message: error.message });
            }
        }
    }

    return { deleted, errors };
}

/**
 * Delete multiple files (unified interface)
 */
async function deleteMultipleFiles(keys) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            const result = await deleteMultipleFromS3(keys);
            console.log(`✓ [S3] Deleted ${result.deleted.length} files`);
            return result;
        } else {
            const result = await deleteMultipleFromLocal(keys);
            console.log(`✓ [LOCAL] Deleted ${result.deleted.length} files`);
            return result;
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] Batch delete error:`, error);
        throw new Error(`Failed to delete files: ${error.message}`);
    }
}

/**
 * Check if file exists in S3
 */
async function fileExistsInS3(key) {
    try {
        const command = new HeadObjectCommand({
            Bucket: config.aws.bucket,
            Key: key,
        });
        await s3Client.send(command);
        return true;
    } catch {
        return false;
    }
}

/**
 * Check if file exists in local storage
 */
async function fileExistsInLocal(key) {
    try {
        const safeKey = sanitizeKey(key);
        const filePath = path.join(UPLOAD_DIR, safeKey);
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

/**
 * Check if file exists (unified interface)
 */
async function fileExists(key) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            return await fileExistsInS3(key);
        } else {
            return await fileExistsInLocal(key);
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] File exists check error:`, error);
        return false;
    }
}

/**
 * Get file metadata from S3
 */
async function getFileMetadataFromS3(key) {
    const command = new HeadObjectCommand({
        Bucket: config.aws.bucket,
        Key: key,
    });

    const response = await s3Client.send(command);

    return {
        contentLength: response.ContentLength,
        contentType: response.ContentType,
        lastModified: response.LastModified,
        etag: response.ETag,
        metadata: response.Metadata,
    };
}

/**
 * Get file metadata from local storage
 */
async function getFileMetadataFromLocal(key) {
    const safeKey = sanitizeKey(key);
    const filePath = path.join(UPLOAD_DIR, safeKey);
    const stats = await fs.stat(filePath);

    return {
        contentLength: stats.size,
        lastModified: stats.mtime,
        contentType: 'application/octet-stream',
    };
}

/**
 * Get file metadata (unified interface)
 */
async function getFileMetadata(key) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            return await getFileMetadataFromS3(key);
        } else {
            return await getFileMetadataFromLocal(key);
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] Metadata error:`, error);
        throw new Error(`Failed to get file metadata: ${error.message}`);
    }
}

/**
 * Generate presigned URL for S3
 */
async function generatePresignedUrl(key, expiresIn = 3600) {
    if (STORAGE_PROVIDER !== 's3') {
        throw new Error('Presigned URLs are only available for S3 storage');
    }

    try {
        const command = new GetObjectCommand({
            Bucket: config.aws.bucket,
            Key: key,
        });

        const url = await getSignedUrl(s3Client, command, { expiresIn });
        console.log(`✓ [S3] Generated presigned URL for: ${key}`);
        return url;
    } catch (error) {
        console.error('✗ [S3] Presigned URL error:', error);
        throw new Error(`Failed to generate presigned URL: ${error.message}`);
    }
}

/**
 * List files in S3
 */
async function listFilesInS3(prefix = '', maxKeys = 1000) {
    const command = new ListObjectsV2Command({
        Bucket: config.aws.bucket,
        Prefix: prefix,
        MaxKeys: maxKeys,
    });

    const response = await s3Client.send(command);

    return (response.Contents || []).map(item => ({
        key: item.Key,
        size: item.Size,
        lastModified: item.LastModified,
        etag: item.ETag,
    }));
}

/**
 * List files in local storage
 */
async function listFilesInLocal(prefix = '', maxKeys = 1000) {
    await ensureUploadDir();
    const files = await fs.readdir(UPLOAD_DIR);

    return files
        .filter(f => !f.startsWith('.') && f.startsWith(prefix))
        .slice(0, maxKeys)
        .map(f => ({ key: f }));
}

/**
 * List files (unified interface)
 */
async function listFiles(prefix = '', maxKeys = 1000) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            return await listFilesInS3(prefix, maxKeys);
        } else {
            return await listFilesInLocal(prefix, maxKeys);
        }
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] List files error:`, error);
        return [];
    }
}

/**
 * Copy file in S3
 */
async function copyFileInS3(sourceKey, destinationKey) {
    const command = new CopyObjectCommand({
        Bucket: config.aws.bucket,
        CopySource: `${config.aws.bucket}/${sourceKey}`,
        Key: destinationKey,
    });

    await s3Client.send(command);
}

/**
 * Copy file in local storage
 */
async function copyFileInLocal(sourceKey, destinationKey) {
    const safeSource = sanitizeKey(sourceKey);
    const safeDest = sanitizeKey(destinationKey);

    const sourcePath = path.join(UPLOAD_DIR, safeSource);
    const destPath = path.join(UPLOAD_DIR, safeDest);

    // Ensure destination directory exists
    const destDir = path.dirname(destPath);
    await fs.mkdir(destDir, { recursive: true });

    await fs.copyFile(sourcePath, destPath);
}

/**
 * Copy file (unified interface)
 */
async function copyFile(sourceKey, destinationKey) {
    try {
        if (STORAGE_PROVIDER === 's3') {
            await copyFileInS3(sourceKey, destinationKey);
            console.log(`✓ [S3] Copied: ${sourceKey} → ${destinationKey}`);
        } else {
            await copyFileInLocal(sourceKey, destinationKey);
            console.log(`✓ [LOCAL] Copied: ${sourceKey} → ${destinationKey}`);
        }
        return { success: true };
    } catch (error) {
        console.error(`✗ [${STORAGE_PROVIDER.toUpperCase()}] Copy error:`, error);
        throw new Error(`Failed to copy file: ${error.message}`);
    }
}

/**
 * Test S3 connection
 */
async function testS3Connection() {
    const testKey = `.test-${Date.now()}`;

    try {
        // Test write
        await uploadToS3(Buffer.from('test'), testKey);

        // Test read
        await downloadFromS3(testKey);

        // Test delete
        await deleteFromS3(testKey);

        console.log(`✓ [S3] Connection test successful - Bucket: ${config.aws.bucket}`);
        return true;
    } catch (error) {
        console.error('✗ [S3] Connection test failed:', error);
        return false;
    }
}

/**
 * Test local storage connection
 */
async function testLocalConnection() {
    try {
        await ensureUploadDir();

        const testFile = path.join(UPLOAD_DIR, '.test');
        await fs.writeFile(testFile, 'test');
        await fs.unlink(testFile);

        console.log(`✓ [LOCAL] Storage initialized: ${UPLOAD_DIR}`);
        return true;
    } catch (error) {
        console.error('✗ [LOCAL] Initialization failed:', error);
        return false;
    }
}

/**
 * Test storage connection (unified interface)
 */
async function testConnection() {
    if (STORAGE_PROVIDER === 's3') {
        return await testS3Connection();
    } else {
        return await testLocalConnection();
    }
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
    STORAGE_PROVIDER,
    UPLOAD_DIR,
};
