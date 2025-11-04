/**
 * File Sharing Module
 * Handles secure file sharing between users
 */

class ShareManager {
    constructor() {
        this.currentShares = [];
        this.currentFileId = null;
        this.currentFileName = null;
    }

    /**
     * Open share modal
     */
    async openShareModal(fileId, fileName) {
        this.currentFileId = fileId;
        this.currentFileName = fileName;

        const modal = document.getElementById('share-modal');
        document.getElementById('share-file-id').value = fileId;

        // Load existing shares
        await this.loadFileShares(fileId);

        modal.classList.add('active');
    }

    /**
     * Close share modal
     */
    closeShareModal() {
        const modal = document.getElementById('share-modal');
        modal.classList.remove('active');
        document.getElementById('shareForm').reset();
    }

    /**
     * Share file with user
     */
    async shareFile(fileId, recipientUsername, permissions) {
        try {
            showLoading('Preparing secure share...');

            // Get recipient's public key
            // Note: In a real implementation, you'd fetch this from the server
            // For now, we'll ask the server to handle the key wrapping

            // Get file's symmetric key (we need to download file metadata)
            const fileResponse = await api.downloadFile(fileId);

            // Unwrap our symmetric key
            const keyPair = authManager.getKeyPair();
            const symmetricKey = await cryptoManager.unwrapKey(
                fileResponse.file.encryptedSymmetricKey,
                keyPair.privateKey
            );

            // For sharing, we need the recipient's public key
            // In this implementation, the server will handle the re-wrapping
            // So we'll send our unwrapped key, and server will wrap it with recipient's key

            // Export symmetric key for sharing (no wrapping for school project)
            const exportedKey = await crypto.subtle.exportKey("raw", symmetricKey);
            const keyBase64 = cryptoManager.arrayBufferToBase64(exportedKey);

            // Store raw key directly (backend won't re-wrap for now)
            await api.shareFile({
                fileId,
                recipientUsername,
                wrappedKey: keyBase64,
                permissions
            });


            hideLoading();
            showToast(`File shared with ${recipientUsername}`, 'success');

            // Reload shares
            await this.loadFileShares(fileId);

        } catch (error) {
            hideLoading();
            console.error('Share error:', error);
            showToast(`Failed to share file: ${error.message}`, 'error');
        }
    }

    /**
     * Load shares for a file
     */
    async loadFileShares(fileId) {
        try {
            const response = await api.getFileShares(fileId);
            this.currentShares = response.shares;
            this.renderCurrentShares();

        } catch (error) {
            console.error('Load shares error:', error);
            showToast('Failed to load shares', 'error');
        }
    }

    /**
     * Render current shares list
     */
    renderCurrentShares() {
        const container = document.getElementById('current-shares');

        if (this.currentShares.length === 0) {
            container.innerHTML = '<p class="text-muted">No shares yet</p>';
            return;
        }

        container.innerHTML = this.currentShares.map(share => `
            <div class="share-item">
                <div>
                    <strong>${share.recipient_username}</strong>
                    <small class="text-muted">${share.recipient_email}</small>
                    <br>
                    <small>
                        ${share.permissions} • 
                        ${share.is_active ? 'Active' : 'Revoked'}
                    </small>
                </div>
                <div>
                    ${share.is_active ? `
                        <button class="btn btn-small btn-danger" 
                                onclick="shareManager.revokeShare('${share.share_id}')">
                            Revoke
                        </button>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    /**
     * Revoke share
     */
    async revokeShare(shareId) {
        if (!confirm('Revoke this share?')) {
            return;
        }

        try {
            showLoading('Revoking share...');
            await api.revokeShare(shareId);
            hideLoading();

            showToast('Share revoked', 'success');
            await this.loadFileShares(this.currentFileId);

        } catch (error) {
            hideLoading();
            console.error('Revoke error:', error);
            showToast('Failed to revoke share', 'error');
        }
    }

    /**
     * Load files shared with current user
     */
    async loadSharedFiles() {
        try {
            const response = await api.getSharedFiles('received');
            this.renderSharedFiles(response.shares);

        } catch (error) {
            console.error('Load shared files error:', error);
            showToast('Failed to load shared files', 'error');
        }
    }

    /**
     * Render shared files list
     */
    renderSharedFiles(shares) {
        const container = document.getElementById('shared-files-list');

        if (shares.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">👥</div>
                    <p>No files shared with you</p>
                </div>
            `;
            return;
        }

        container.innerHTML = shares.map(share => `
            <div class="file-item">
                <div class="file-icon">
                    ${fileManager.getFileIcon(share.mime_type)}
                </div>
                <div class="file-info">
                    <div class="file-name">${fileManager.escapeHtml(share.file_name)}</div>
                    <div class="file-meta">
                        <span>${fileManager.formatFileSize(share.file_size)}</span>
                        <span>Shared by ${share.owner_username}</span>
                        <span>${share.permissions} access</span>
                    </div>
                </div>
                <div class="file-actions">
                    <button class="btn btn-small btn-success" 
                            onclick="shareManager.downloadSharedFile('${share.file_id}', '${fileManager.escapeHtml(share.file_name)}', '${share.wrapped_key}')">
                        ⬇️ Download
                    </button>
                </div>
            </div>
        `).join('');
    }

    /**
     * Download shared file
     */
    async downloadSharedFile(fileId, fileName, wrappedKey) {
        try {
            showLoading(`Downloading ${fileName}...`);

            // Get encrypted file from server
            const response = await api.downloadFile(fileId);

            // Unwrap symmetric key using our private key
            const keyPair = authManager.getKeyPair();
            showLoading(`Decrypting ${fileName}...`);

            // shared "wrappedKey" is actually the raw base64 symmetric key (school project mode)
            const rawKey = cryptoManager.base64ToArrayBuffer(wrappedKey);
            const symmetricKey = await crypto.subtle.importKey(
                "raw",
                rawKey,
                { name: "AES-GCM" },
                false,
                ["encrypt", "decrypt"]
            );


            // Decrypt file data
            const encryptedData = cryptoManager.base64ToArrayBuffer(response.encryptedData);
            const decryptedData = await cryptoManager.decryptFile(encryptedData, symmetricKey);

            // Download file
            hideLoading();
            cryptoManager.downloadFile(
                decryptedData,
                fileName,
                response.file.mimeType
            );

            showToast(`${fileName} downloaded successfully`, 'success');

        } catch (error) {
            hideLoading();
            console.error('Download shared file error:', error);
            showToast(`Failed to download ${fileName}: ${error.message}`, 'error');
        }
    }
}

// Create global share manager instance
const shareManager = new ShareManager();
