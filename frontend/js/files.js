/**
 * File Management Module
 * Handles file upload, download, and management operations
 */

class FileManager {
    constructor() {
        this.currentFiles = [];
        this.currentPage = 1;
        this.totalPages = 1;
        this.sortBy = 'created_at';
        this.sortOrder = 'DESC';
        this.searchQuery = '';
    }

    /**
     * Upload file(s)
     */
    async uploadFiles(files) {
        if (!authManager.isAuthenticated()) {
            showToast('Please login first', 'error');
            return;
        }

        for (const file of files) {
            await this.uploadSingleFile(file);
        }
    }

    /**
     * Upload single file
     */
    async uploadSingleFile(file) {
        if (file.size > CONFIG.UPLOAD.MAX_FILE_SIZE) {
            showToast(`File ${file.name} exceeds maximum size (100MB)`, 'error');
            return;
        }

        try {
            showLoading(`Encrypting ${file.name}...`);

            const startTime = Date.now();

            // Generate symmetric key for file encryption
            const symmetricKey = await cryptoManager.generateSymmetricKey();

            // Encrypt file
            const encryptedFile = await cryptoManager.encryptFile(file, symmetricKey);

            // Encrypt file name
            const encryptedFileName = await cryptoManager.encryptFileName(file.name, symmetricKey);

            // Wrap symmetric key with user's public key
            const keyPair = authManager.getKeyPair();
            const wrappedKey = await cryptoManager.wrapKey(symmetricKey, keyPair.publicKey);

            // Generate HMAC signature for integrity
            const signatureData = await cryptoManager.generateSignature(encryptedFile);

            // Prepare form data
            const formData = new FormData();
            formData.append('file', new Blob([encryptedFile]), 'encrypted');
            formData.append('fileName', file.name);
            formData.append('encryptedFileName', JSON.stringify(encryptedFileName));
            formData.append('encryptedSymmetricKey', wrappedKey);
            formData.append('signature', JSON.stringify(signatureData)); // Send both signature and key
            formData.append('mimeType', file.type || 'application/octet-stream');
            formData.append('originalSize', file.size);

            // Upload to server
            showLoading(`Uploading ${file.name}...`);
            const response = await api.uploadFile(formData);

            const duration = Date.now() - startTime;

            hideLoading();
            showToast(
                `${file.name} uploaded successfully (${duration}ms)`,
                'success'
            );

            // Refresh file list
            await this.loadFiles();

        } catch (error) {
            hideLoading();
            console.error('Upload error:', error);
            showToast(`Failed to upload ${file.name}: ${error.message}`, 'error');
        }
    }

    /**
     * Download and decrypt file
     */
    async downloadFile(fileId, fileName) {
        try {
            showLoading(`Downloading ${fileName}...`);

            // Get encrypted file from server
            const response = await api.downloadFile(fileId);

            // Get private key
            const keyPair = authManager.getKeyPair();

            // Unwrap symmetric key
            showLoading(`Decrypting ${fileName}...`);
            const symmetricKey = await cryptoManager.unwrapKey(
                response.file.encryptedSymmetricKey,
                keyPair.privateKey
            );

            // Decrypt file data
            const encryptedData = cryptoManager.base64ToArrayBuffer(response.encryptedData);
            const decryptedData = await cryptoManager.decryptFile(encryptedData, symmetricKey);

            // Verify signature (if available)
            try {
                if (response.file.signature) {
                    const signatureData = typeof response.file.signature === 'string'
                        ? JSON.parse(response.file.signature)
                        : response.file.signature;

                    const isValid = await cryptoManager.verifySignature(
                        encryptedData,
                        signatureData
                    );

                    if (!isValid) {
                        console.warn('File integrity check failed - file may be corrupted');
                        if (!confirm('File integrity check failed. Download anyway?')) {
                            hideLoading();
                            return;
                        }
                    }
                }
            } catch (sigError) {
                console.warn('Signature verification skipped:', sigError.message);
            }

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
            console.error('Download error:', error);
            showToast(`Failed to download ${fileName}: ${error.message}`, 'error');
        }
    }


    /**
     * Delete file
     */
    async deleteFile(fileId, fileName, permanent = false) {
        const confirmMsg = permanent
            ? `Permanently delete ${fileName}? This cannot be undone.`
            : `Delete ${fileName}?`;

        if (!confirm(confirmMsg)) {
            return;
        }

        try {
            showLoading(`Deleting ${fileName}...`);
            await api.deleteFile(fileId, permanent);
            hideLoading();

            showToast(`${fileName} deleted`, 'success');
            await this.loadFiles();

        } catch (error) {
            hideLoading();
            console.error('Delete error:', error);
            showToast(`Failed to delete ${fileName}: ${error.message}`, 'error');
        }
    }

    /**
     * Load files from server
     */
    async loadFiles(page = 1) {
        try {
            const params = {
                page,
                limit: CONFIG.PAGINATION.FILES_PER_PAGE,
                sortBy: this.sortBy,
                sortOrder: this.sortOrder,
            };

            if (this.searchQuery) {
                params.search = this.searchQuery;
            }

            const response = await api.listFiles(params);

            this.currentFiles = response.files;
            this.currentPage = response.pagination.page;
            this.totalPages = response.pagination.totalPages;

            this.renderFilesList();
            this.renderPagination();

        } catch (error) {
            console.error('Load files error:', error);
            showToast('Failed to load files', 'error');
        }
    }

    /**
     * Render files list
     */
    renderFilesList() {
        const container = document.getElementById('files-list');

        if (this.currentFiles.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">📁</div>
                    <p>No files found</p>
                    <small>Upload your first file to get started</small>
                </div>
            `;
            return;
        }

        container.innerHTML = this.currentFiles.map(file => `
            <div class="file-item" data-file-id="${file.file_id}">
                <div class="file-icon">
                    ${this.getFileIcon(file.mime_type)}
                </div>
                <div class="file-info">
                    <div class="file-name">${this.escapeHtml(file.file_name)}</div>
                    <div class="file-meta">
                        <span>${this.formatFileSize(file.file_size)}</span>
                        <span>${this.formatDate(file.created_at)}</span>
                        <span>v${file.version}</span>
                    </div>
                </div>
                <div class="file-actions">
                    <button class="btn btn-small btn-success" onclick="fileManager.downloadFile('${file.file_id}', '${this.escapeHtml(file.file_name)}')">
                        ⬇️ Download
                    </button>
                    <button class="btn btn-small btn-secondary" onclick="shareManager.openShareModal('${file.file_id}', '${this.escapeHtml(file.file_name)}')">
                        🔗 Share
                    </button>
                    <button class="btn btn-small btn-secondary" onclick="fileManager.showVersions('${file.file_id}')">
                        📋 Versions
                    </button>
                    <button class="btn btn-small btn-danger" onclick="fileManager.deleteFile('${file.file_id}', '${this.escapeHtml(file.file_name)}')">
                        🗑️ Delete
                    </button>
                </div>
            </div>
        `).join('');
    }

    /**
     * Render pagination
     */
    renderPagination() {
        const container = document.getElementById('files-pagination');

        if (this.totalPages <= 1) {
            container.innerHTML = '';
            return;
        }

        let pages = [];
        for (let i = 1; i <= this.totalPages; i++) {
            if (
                i === 1 ||
                i === this.totalPages ||
                (i >= this.currentPage - 2 && i <= this.currentPage + 2)
            ) {
                pages.push(i);
            } else if (pages[pages.length - 1] !== '...') {
                pages.push('...');
            }
        }

        container.innerHTML = `
            <button ${this.currentPage === 1 ? 'disabled' : ''} 
                    onclick="fileManager.loadFiles(${this.currentPage - 1})">
                Previous
            </button>
            ${pages.map(page =>
            page === '...'
                ? '<span>...</span>'
                : `<button class="${page === this.currentPage ? 'active' : ''}" 
                               onclick="fileManager.loadFiles(${page})">${page}</button>`
        ).join('')}
            <button ${this.currentPage === this.totalPages ? 'disabled' : ''} 
                    onclick="fileManager.loadFiles(${this.currentPage + 1})">
                Next
            </button>
        `;
    }

    /**
     * Show file versions
     */
    async showVersions(fileId) {
        try {
            showLoading('Loading versions...');
            const response = await api.getFileVersions(fileId);
            hideLoading();

            const modal = document.getElementById('versions-modal');
            const versionsList = document.getElementById('versions-list');

            versionsList.innerHTML = response.versions.map(version => `
                <div class="file-item">
                    <div class="file-info">
                        <div class="file-name">Version ${version.version_number}</div>
                        <div class="file-meta">
                            <span>${this.formatFileSize(version.file_size)}</span>
                            <span>${this.formatDate(version.created_at)}</span>
                            <span>by ${version.created_by_username || 'Unknown'}</span>
                        </div>
                    </div>
                </div>
            `).join('');

            modal.classList.add('active');

        } catch (error) {
            hideLoading();
            console.error('Load versions error:', error);
            showToast('Failed to load versions', 'error');
        }
    }

    /**
     * Set sort options
     */
    setSort(sortBy, sortOrder) {
        this.sortBy = sortBy;
        this.sortOrder = sortOrder;
        this.loadFiles(1);
    }

    /**
     * Set search query
     */
    setSearch(query) {
        this.searchQuery = query;
        this.loadFiles(1);
    }

    // ============================================
    // UTILITY METHODS
    // ============================================

    getFileIcon(mimeType) {
        if (!mimeType) return '📄';
        if (mimeType.startsWith('image/')) return '🖼️';
        if (mimeType.startsWith('video/')) return '🎥';
        if (mimeType.startsWith('audio/')) return '🎵';
        if (mimeType.includes('pdf')) return '📕';
        if (mimeType.includes('zip') || mimeType.includes('rar')) return '📦';
        if (mimeType.includes('text')) return '📝';
        return '📄';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diff = now - date;
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));

        if (days === 0) return 'Today';
        if (days === 1) return 'Yesterday';
        if (days < 7) return `${days} days ago`;
        if (days < 30) return `${Math.floor(days / 7)} weeks ago`;
        return date.toLocaleDateString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Create global file manager instance
const fileManager = new FileManager();
