/**
 * Cryptography Module
 * Handles all client-side encryption/decryption operations
 */

class CryptoManager {
    constructor() {
        this.subtle = window.crypto.subtle;
    }

    /**
     * Generate RSA key pair
     */
    async generateRSAKeyPair() {
        const keyPair = await this.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: CONFIG.ENCRYPTION.RSA_KEY_SIZE,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );

        return keyPair;
    }

    /**
     * Export public key to PEM format
     */
    async exportPublicKey(publicKey) {
        const exported = await this.subtle.exportKey('spki', publicKey);
        const b64 = this.arrayBufferToBase64(exported);
        return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
    }

    /**
     * Import public key from PEM format
     */
    async importPublicKey(pemKey) {
        const b64 = pemKey
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\s/g, '');

        const binaryKey = this.base64ToArrayBuffer(b64);

        return await this.subtle.importKey(
            'spki',
            binaryKey,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'wrapKey']
        );
    }

    /**
     * Export private key to JWK format
     */
    async exportPrivateKey(privateKey) {
        const exported = await this.subtle.exportKey('jwk', privateKey);
        return JSON.stringify(exported);
    }

    /**
     * Import private key from JWK format
     */
    async importPrivateKey(jwkKey) {
        const keyData = JSON.parse(jwkKey);

        return await this.subtle.importKey(
            'jwk',
            keyData,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256',
            },
            true,
            ['decrypt', 'unwrapKey']
        );
    }

    /**
     * Derive key from password using PBKDF2
     */
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const passwordKey = await this.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return await this.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: CONFIG.ENCRYPTION.PBKDF2_ITERATIONS,
                hash: 'SHA-256',
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt private key with master password
     */
    async encryptPrivateKey(privateKey, masterPassword, salt) {
        const exportedKey = await this.exportPrivateKey(privateKey);
        const derivedKey = await this.deriveKey(masterPassword, salt);

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();

        const encrypted = await this.subtle.encrypt(
            { name: 'AES-GCM', iv },
            derivedKey,
            encoder.encode(exportedKey)
        );

        return {
            encrypted: this.arrayBufferToBase64(encrypted),
            iv: this.arrayBufferToBase64(iv),
        };
    }

    /**
     * Decrypt private key with master password
     */
    async decryptPrivateKey(encryptedData, masterPassword, salt) {
        const derivedKey = await this.deriveKey(masterPassword, salt);

        const encrypted = this.base64ToArrayBuffer(encryptedData.encrypted);
        const iv = this.base64ToArrayBuffer(encryptedData.iv);

        try {
            const decrypted = await this.subtle.decrypt(
                { name: 'AES-GCM', iv },
                derivedKey,
                encrypted
            );

            const decoder = new TextDecoder();
            const jwkKey = decoder.decode(decrypted);

            return await this.importPrivateKey(jwkKey);
        } catch (error) {
            throw new Error('Invalid master password');
        }
    }

    /**
     * Generate AES symmetric key for file encryption
     */
    async generateSymmetricKey() {
        return await this.subtle.generateKey(
            { name: 'AES-GCM', length: CONFIG.ENCRYPTION.AES_KEY_SIZE },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt file with AES-GCM
     */
    async encryptFile(file, symmetricKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const fileData = await this.readFileAsArrayBuffer(file);

        const encrypted = await this.subtle.encrypt(
            { name: 'AES-GCM', iv },
            symmetricKey,
            fileData
        );

        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);

        return combined;
    }

    /**
     * Decrypt file with AES-GCM
     */
    async decryptFile(encryptedData, symmetricKey) {
        // Extract IV and encrypted content
        const iv = encryptedData.slice(0, 12);
        const data = encryptedData.slice(12);

        const decrypted = await this.subtle.decrypt(
            { name: 'AES-GCM', iv },
            symmetricKey,
            data
        );

        return decrypted;
    }

    /**
     * Wrap (encrypt) symmetric key with RSA public key
     */
    async wrapKey(symmetricKey, publicKey) {
        const wrapped = await this.subtle.wrapKey(
            'raw',
            symmetricKey,
            publicKey,
            { name: 'RSA-OAEP' }
        );

        return this.arrayBufferToBase64(wrapped);
    }

    /**
     * Unwrap (decrypt) symmetric key with RSA private key
     */
    async unwrapKey(wrappedKey, privateKey) {
        const wrappedBuffer = this.base64ToArrayBuffer(wrappedKey);

        return await this.subtle.unwrapKey(
            'raw',
            wrappedBuffer,
            privateKey,
            { name: 'RSA-OAEP' },
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate digital signature
     */
    async generateSignature(data, privateKey) {
        const signature = await this.subtle.sign(
            { name: 'RSA-PSS', saltLength: 32 },
            privateKey,
            data
        );

        return this.arrayBufferToBase64(signature);
    }

    /**
     * Verify digital signature
     */
    async verifySignature(data, signature, publicKey) {
        const signatureBuffer = this.base64ToArrayBuffer(signature);

        return await this.subtle.verify(
            { name: 'RSA-PSS', saltLength: 32 },
            publicKey,
            signatureBuffer,
            data
        );
    }

    /**
     * Hash password for authentication
     */
    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hash = await this.subtle.digest('SHA-256', data);
        return this.arrayBufferToHex(hash);
    }

    /**
     * Calculate file hash (SHA-256)
     */
    async calculateFileHash(file) {
        const fileData = await this.readFileAsArrayBuffer(file);
        const hash = await this.subtle.digest('SHA-256', fileData);
        return this.arrayBufferToHex(hash);
    }

    /**
     * Encrypt file name
     */
    async encryptFileName(fileName, symmetricKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();

        const encrypted = await this.subtle.encrypt(
            { name: 'AES-GCM', iv },
            symmetricKey,
            encoder.encode(fileName)
        );

        return {
            encrypted: this.arrayBufferToBase64(encrypted),
            iv: this.arrayBufferToBase64(iv),
        };
    }

    /**
     * Decrypt file name
     */
    async decryptFileName(encryptedData, symmetricKey) {
        const encrypted = this.base64ToArrayBuffer(encryptedData.encrypted);
        const iv = this.base64ToArrayBuffer(encryptedData.iv);

        const decrypted = await this.subtle.decrypt(
            { name: 'AES-GCM', iv },
            symmetricKey,
            encrypted
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    // ============================================
    // UTILITY METHODS
    // ============================================

    /**
     * Read file as ArrayBuffer
     */
    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    /**
     * Convert ArrayBuffer to Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Convert Base64 to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Convert ArrayBuffer to Hex string
     */
    arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Generate random salt
     */
    generateSalt() {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        return this.arrayBufferToBase64(salt);
    }

    /**
     * Download decrypted file
     */
    downloadFile(data, fileName, mimeType) {
        const blob = new Blob([data], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;
        link.click();
        URL.revokeObjectURL(url);
    }
}

// Create global crypto manager instance
const cryptoManager = new CryptoManager();
