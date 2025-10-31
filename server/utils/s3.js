/**
 * AWS S3 utilities for encrypted file storage
 * Handles upload, download, and management of encrypted files
 */
const AWS = require('aws-sdk');
const config = require('../config');
const { generateFingerprint } = require('./cryptoMetrics');

// Configure AWS SDK
const s3 = new AWS.S3({
    accessKeyId: config.aws.accessKeyId,
    secretAccessKey: config.aws.secretAccessKey,
    region: config.aws.region,
    // Optional: Use accelerated endpoint for faster uploads
    useAccelerateEndpoint: false,
    // Retry configuration
    maxRetries: 3,
    httpOptions: {
        timeout: 300000, // 5 minutes
        connectTimeout: 5000
    }
});

const S3_BUCKET = config.aws.bucket;

/**
 * Upload encrypted file to S3
 * @param {Buffer} buffer - File buffer
 * @param {string} key - S3 object key
 * @param {Object} metadata - Optional metadata
 * @returns {Promise<Object>} Upload result with location and ETag
 */
async function uploadFile(buffer, key, metadata = {}) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Key: key,
            Body: buffer,
            ContentType: 'application/octet-stream',
            ServerSideEncryption: 'AES256', // Server-side encryption at rest
            Metadata: {
                ...metadata,
                uploadedAt: new Date().toISOString(),
                fingerprint: generateFingerprint(buffer)
            },
            // Optional: Add content hash for integrity
            ContentMD5: buffer.toString('base64').substring(0, 24)
        };

        const result = await s3.upload(params).promise();

        return {
            location: result.Location,
            etag: result.ETag,
            key: result.Key,
            bucket: result.Bucket,
            versionId: result.VersionId
        };

    } catch (error) {
        console.error('S3 upload error:', error);
        throw new Error(`Failed to upload file: ${error.message}`);
    }
}

/**
 * Download file from S3
 * @param {string} key - S3 object key
 * @returns {Promise<Buffer>} File buffer
 */
async function downloadFile(key) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Key: key
        };

        const result = await s3.getObject(params).promise();

        return result.Body;

    } catch (error) {
        console.error('S3 download error:', error);

        if (error.code === 'NoSuchKey') {
            throw new Error('File not found');
        }

        throw new Error(`Failed to download file: ${error.message}`);
    }
}

/**
 * Get file as readable stream (for large files)
 * @param {string} key - S3 object key
 * @returns {ReadableStream} File stream
 */
function getFileStream(key) {
    const params = {
        Bucket: S3_BUCKET,
        Key: key
    };

    return s3.getObject(params).createReadStream();
}

/**
 * Delete file from S3
 * @param {string} key - S3 object key
 * @returns {Promise<void>}
 */
async function deleteFile(key) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Key: key
        };

        await s3.deleteObject(params).promise();

    } catch (error) {
        console.error('S3 deletion error:', error);
        throw new Error(`Failed to delete file: ${error.message}`);
    }
}

/**
 * Delete multiple files from S3
 * @param {string[]} keys - Array of S3 object keys
 * @returns {Promise<Object>} Deletion results
 */
async function deleteMultipleFiles(keys) {
    try {
        if (keys.length === 0) return { deleted: [], errors: [] };

        const params = {
            Bucket: S3_BUCKET,
            Delete: {
                Objects: keys.map(key => ({ Key: key })),
                Quiet: false
            }
        };

        const result = await s3.deleteObjects(params).promise();

        return {
            deleted: result.Deleted || [],
            errors: result.Errors || []
        };

    } catch (error) {
        console.error('S3 batch deletion error:', error);
        throw new Error(`Failed to delete files: ${error.message}`);
    }
}

/**
 * Check if file exists in S3
 * @param {string} key - S3 object key
 * @returns {Promise<boolean>} True if file exists
 */
async function fileExists(key) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Key: key
        };

        await s3.headObject(params).promise();
        return true;

    } catch (error) {
        if (error.code === 'NotFound') {
            return false;
        }
        throw error;
    }
}

/**
 * Get file metadata without downloading
 * @param {string} key - S3 object key
 * @returns {Promise<Object>} File metadata
 */
async function getFileMetadata(key) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Key: key
        };

        const result = await s3.headObject(params).promise();

        return {
            contentLength: result.ContentLength,
            contentType: result.ContentType,
            lastModified: result.LastModified,
            etag: result.ETag,
            metadata: result.Metadata,
            versionId: result.VersionId
        };

    } catch (error) {
        console.error('S3 metadata error:', error);
        throw new Error(`Failed to get file metadata: ${error.message}`);
    }
}

/**
 * Generate pre-signed URL for temporary access
 * @param {string} key - S3 object key
 * @param {number} expiresIn - Expiration time in seconds (default: 1 hour)
 * @returns {Promise<string>} Pre-signed URL
 */
async function generatePresignedUrl(key, expiresIn = 3600) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Key: key,
            Expires: expiresIn
        };

        const url = await s3.getSignedUrlPromise('getObject', params);
        return url;

    } catch (error) {
        console.error('Pre-signed URL generation error:', error);
        throw new Error(`Failed to generate download URL: ${error.message}`);
    }
}

/**
 * List files with prefix
 * @param {string} prefix - Key prefix to filter
 * @param {number} maxKeys - Maximum number of keys to return
 * @returns {Promise<Array>} Array of file objects
 */
async function listFiles(prefix = '', maxKeys = 1000) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Prefix: prefix,
            MaxKeys: maxKeys
        };

        const result = await s3.listObjectsV2(params).promise();

        return result.Contents.map(item => ({
            key: item.Key,
            size: item.Size,
            lastModified: item.LastModified,
            etag: item.ETag
        }));

    } catch (error) {
        console.error('S3 list error:', error);
        throw new Error(`Failed to list files: ${error.message}`);
    }
}

/**
 * Copy file within S3
 * @param {string} sourceKey - Source object key
 * @param {string} destinationKey - Destination object key
 * @returns {Promise<Object>} Copy result
 */
async function copyFile(sourceKey, destinationKey) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            CopySource: `${S3_BUCKET}/${sourceKey}`,
            Key: destinationKey,
            ServerSideEncryption: 'AES256'
        };

        const result = await s3.copyObject(params).promise();

        return {
            etag: result.CopyObjectResult.ETag,
            lastModified: result.CopyObjectResult.LastModified
        };

    } catch (error) {
        console.error('S3 copy error:', error);
        throw new Error(`Failed to copy file: ${error.message}`);
    }
}

/**
 * Test S3 connection
 * @returns {Promise<boolean>} True if connection successful
 */
async function testConnection() {
    try {
        await s3.headBucket({ Bucket: S3_BUCKET }).promise();
        return true;
    } catch (error) {
        console.error('S3 connection test failed:', error);
        return false;
    }
}

module.exports = {
    s3, // Export S3 client for advanced usage
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
