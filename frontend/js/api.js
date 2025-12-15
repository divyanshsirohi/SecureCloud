/**
 * API Communication Module
 */

class API {
    constructor(baseURL) {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('authToken');
    }

    /**
     * Set authentication token
     */
    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('authToken', token);
        } else {
            localStorage.removeItem('authToken');
        }
    }

    /**
     * Build headers
     */
    getHeaders(includeAuth = true, contentType = 'application/json') {
        const headers = {};

        if (contentType) headers['Content-Type'] = contentType;

        if (includeAuth && this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        return headers;
    }

    /**
     * Generic request handler
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;

        try {
            const response = await fetch(url, {
                ...options,
                credentials: "include", // ✅ important for Render
                headers: {
                    ...this.getHeaders(options.auth !== false, options.contentType),
                    ...options.headers,
                },
            });

            const contentType = response.headers.get('content-type');
            let data;

            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                data = await response.text();
            }

            if (!response.ok) {
                throw {
                    status: response.status,
                    message: data.error || data.message || 'Request failed',
                    code: data.code,
                };
            }

            return data;
        } catch (error) {
            console.error('API Request Error:', error);
            throw error;
        }
    }

    // ========== AUTH ==========

    register(userData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData),
            auth: false,
        });
    }

    login(credentials) {
        return this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials),
            auth: false,
        });
    }

    logout() {
        return this.request('/auth/logout', { method: 'POST' });
    }

    getCurrentUser() {
        return this.request('/auth/me');
    }

    refreshToken() {
        return this.request('/auth/refresh', { method: 'POST' });
    }

    // ========== FILES ==========

    uploadFile(formData) {
        return this.request('/files/upload', {
            method: 'POST',
            body: formData,
            contentType: null,
        });
    }

    listFiles(params = {}) {
        const query = new URLSearchParams(params).toString();
        return this.request(`/files${query ? '?' + query : ''}`);
    }

    downloadFile(fileId) {
        return this.request(`/files/${fileId}`);
    }

    deleteFile(fileId, permanent = false) {
        return this.request(`/files/${fileId}?permanent=${permanent}`, { method: 'DELETE' });
    }

    getFileVersions(fileId) {
        return this.request(`/files/${fileId}/versions`);
    }

    createFileVersion(fileId, formData) {
        return this.request(`/files/${fileId}/versions`, {
            method: 'POST',
            body: formData,
            contentType: null,
        });
    }

    // ========== SHARES ==========

    shareFile(shareData) {
        return this.request('/shares', {
            method: 'POST',
            body: JSON.stringify(shareData),
        });
    }

    getSharedFiles(type = 'received', params = {}) {
        const query = new URLSearchParams(params).toString();
        return this.request(`/shares/${type}${query ? '?' + query : ''}`);
    }

    getFileShares(fileId) {
        return this.request(`/shares/file/${fileId}`);
    }

    updateShare(shareId, permissions) {
        return this.request(`/shares/${shareId}`, {
            method: 'PATCH',
            body: JSON.stringify({ permissions }),
        });
    }

    revokeShare(shareId) {
        return this.request(`/shares/${shareId}`, { method: 'DELETE' });
    }

    getShareStats() {
        return this.request('/shares/stats');
    }

    // ========== AUDIT ==========

    getAuditLogs(params = {}) {
        const query = new URLSearchParams(params).toString();
        return this.request(`/audit${query ? '?' + query : ''}`);
    }

    exportAuditLogs(params = {}) {
        const query = new URLSearchParams(params).toString();
        const url = `${this.baseURL}/audit/export${query ? '?' + query : ''}`;

        const link = document.createElement('a');
        link.href = url;
        link.download = `audit-logs-${Date.now()}.csv`;
        link.click();
    }

    // ========== STATS ==========

    getStats() {
        return this.request('/stats');
    }

    // ========== HEALTH ==========

    healthCheck() {
        return this.request('/health', { auth: false });
    }
}

// Global API instance
const api = new API(CONFIG.API_BASE_URL);
