/**
 * API Communication Module
 * Handles all HTTP requests to the backend
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
     * Get authorization headers
     */
    getHeaders(includeAuth = true, contentType = 'application/json') {
        const headers = {};

        if (contentType) {
            headers['Content-Type'] = contentType;
        }

        if (includeAuth && this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        return headers;
    }

    /**
     * Generic request method
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;

        try {
            const response = await fetch(url, {
                ...options,
                headers: {
                    ...this.getHeaders(options.auth !== false, options.contentType),
                    ...options.headers,
                },
            });

            // Handle non-JSON responses
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

    // ============================================
    // AUTHENTICATION ENDPOINTS
    // ============================================

    async register(userData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData),
            auth: false,
        });
    }

    async login(credentials) {
        return this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials),
            auth: false,
        });
    }

    async logout() {
        return this.request('/auth/logout', {
            method: 'POST',
        });
    }

    async getCurrentUser() {
        return this.request('/auth/me');
    }

    async refreshToken() {
        return this.request('/auth/refresh', {
            method: 'POST',
        });
    }

    // ============================================
    // FILE ENDPOINTS
    // ============================================

    async uploadFile(formData) {
        return this.request('/files/upload', {
            method: 'POST',
            body: formData,
            contentType: null, // Let browser set multipart/form-data
        });
    }

    async listFiles(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return this.request(`/files${queryString ? '?' + queryString : ''}`);
    }

    async downloadFile(fileId) {
        return this.request(`/files/${fileId}`);
    }

    async deleteFile(fileId, permanent = false) {
        return this.request(`/files/${fileId}?permanent=${permanent}`, {
            method: 'DELETE',
        });
    }

    async getFileVersions(fileId) {
        return this.request(`/files/${fileId}/versions`);
    }

    async createFileVersion(fileId, formData) {
        return this.request(`/files/${fileId}/versions`, {
            method: 'POST',
            body: formData,
            contentType: null,
        });
    }

    // ============================================
    // SHARE ENDPOINTS
    // ============================================

    async shareFile(shareData) {
        return this.request('/shares', {
            method: 'POST',
            body: JSON.stringify(shareData),
        });
    }

    async getSharedFiles(type = 'received', params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return this.request(`/shares/${type}${queryString ? '?' + queryString : ''}`);
    }

    async getFileShares(fileId) {
        return this.request(`/shares/file/${fileId}`);
    }

    async updateShare(shareId, permissions) {
        return this.request(`/shares/${shareId}`, {
            method: 'PATCH',
            body: JSON.stringify({ permissions }),
        });
    }

    async revokeShare(shareId) {
        return this.request(`/shares/${shareId}`, {
            method: 'DELETE',
        });
    }

    async getShareStats() {
        return this.request('/shares/stats');
    }

    // ============================================
    // AUDIT ENDPOINTS
    // ============================================

    async getAuditLogs(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return this.request(`/audit${queryString ? '?' + queryString : ''}`);
    }

    async exportAuditLogs(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = `${this.baseURL}/audit/export${queryString ? '?' + queryString : ''}`;

        // Download file
        const link = document.createElement('a');
        link.href = url;
        link.download = `audit-logs-${Date.now()}.csv`;
        link.click();
    }

    // ============================================
    // STATISTICS ENDPOINTS
    // ============================================

    async getStats() {
        return this.request('/stats');
    }

    // ============================================
    // HEALTH CHECK
    // ============================================

    async healthCheck() {
        return this.request('/health', { auth: false });
    }
}

// Create global API instance
const api = new API(CONFIG.API_BASE_URL);
