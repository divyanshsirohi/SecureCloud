/**
 * Audit Logs Module
 * Displays and exports security audit logs
 */

class AuditManager {
    constructor() {
        this.currentLogs = [];
        this.currentPage = 1;
        this.totalPages = 1;
        this.filters = {
            action: '',
            startDate: '',
            endDate: ''
        };
    }

    /**
     * Load audit logs
     */
    async loadAuditLogs(page = 1) {
        try {
            const params = {
                page,
                limit: CONFIG.PAGINATION.AUDIT_PER_PAGE,
                ...this.filters
            };

            const response = await api.getAuditLogs(params);

            this.currentLogs = response.logs;
            this.currentPage = response.pagination.page;
            this.totalPages = response.pagination.totalPages;

            this.renderAuditLogs();

        } catch (error) {
            console.error('Load audit logs error:', error);
            showToast('Failed to load audit logs', 'error');
        }
    }

    /**
     * Render audit logs
     */
    /**
     * Render audit logs
     */
    renderAuditLogs() {
        const container = document.getElementById('audit-logs-list');

        if (this.currentLogs.length === 0) {
            container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📊</div>
                <p>No audit logs found</p>
            </div>
        `;
            return;
        }

        container.innerHTML = this.currentLogs.map(log => {
            const parts = [];

            if (log.encryption_time_ms) parts.push(`Enc: ${log.encryption_time_ms}ms`);
            if (log.decryption_time_ms) parts.push(`Dec: ${log.decryption_time_ms}ms`);
            if (log.key_generation_time_ms) parts.push(`KeyGen: ${log.key_generation_time_ms}ms`);
            if (log.signature_verification_time_ms) parts.push(`Sig: ${log.signature_verification_time_ms}ms`);
            if (log.file_size_bytes) parts.push(this.formatBytes(log.file_size_bytes));
            if (log.encryption_algorithm) parts.push(log.encryption_algorithm);
            if (log.key_size) parts.push(`${log.key_size}-bit`);
            if (log.avalanche_effect_percentage) parts.push(`Aval: ${log.avalanche_effect_percentage}%`);
            if (log.collision_resistance_score) parts.push(`ColRes: ${log.collision_resistance_score}`);

            const metricsLine = parts.join(' • ');

            // ==========================
            // SECURITY METRICS & BADGES
            // ==========================
            const sec = log.metadata?.securityReport;
            const securityBadges = [];

            if (sec?.quality?.grade) {
                const g = sec.quality.grade.toUpperCase();
                const color = g === 'EXCELLENT' ? '#27ae60'
                    : g === 'GOOD' ? '#2d8fdd'
                        : g === 'ACCEPTABLE' ? '#f39c12'
                            : '#e74c3c';
                securityBadges.push(`<span style="color:${color};font-weight:600;">SEC: ${g}</span>`);
            }

            if (sec?.metrics?.cipherMode) {
                securityBadges.push(sec.metrics.cipherMode);
            }

            if (sec?.metrics?.integrityProtected === false) {
                securityBadges.push(`<span style="color:var(--error);">No Integrity!</span>`);
            }

            if (sec?.metrics?.nonceReuse?.reuseCount > 0) {
                securityBadges.push(`<span style="color:var(--error);">Nonce Reuse</span>`);
            }

            const securityLine = securityBadges.length
                ? `<div class="audit-security">${securityBadges.join(' • ')}</div>`
                : '';

            return `
            <div class="audit-item">
                <div class="audit-icon">
                    ${this.getActionIcon(log.action)}
                </div>
                <div class="audit-info">
                    <h4>${this.formatAction(log.action)}</h4>
                    <div class="audit-meta">
                        ${this.formatDate(log.timestamp)} • ${log.ip_address || 'Unknown IP'}
                    </div>
                    <div class="audit-metrics">
                        ${metricsLine}
                    </div>
                    ${securityLine}
                    ${log.error_message ? `<small style="color: var(--error);">${log.error_message}</small>` : ''}
                </div>
                <div class="audit-status ${log.success ? 'success' : 'error'}">
                    ${log.success ? '✓ Success' : '✗ Failed'}
                </div>
            </div>
        `;
        }).join('');
    }


    formatBytes(bytes) {
        if (bytes === 0) return '0B';
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(2)}${sizes[i]}`;
    }


    /**
     * Export audit logs as CSV
     */
    async exportLogs() {
        try {
            showLoading('Exporting audit logs...');
            await api.exportAuditLogs(this.filters);
            hideLoading();
            showToast('Audit logs exported', 'success');

        } catch (error) {
            hideLoading();
            console.error('Export error:', error);
            showToast('Failed to export logs', 'error');
        }
    }

    /**
     * Set filters
     */
    setFilters(action, startDate, endDate) {
        this.filters = { action, startDate, endDate };
        this.loadAuditLogs(1);
    }

    // ============================================
    // UTILITY METHODS
    // ============================================

    getActionIcon(action) {
        const icons = {
            'FILE_UPLOAD': '📤',
            'FILE_DOWNLOAD': '📥',
            'FILE_DELETE': '🗑️',
            'FILE_SHARE': '🔗',
            'SHARE_REVOKE': '🚫',
            'LOGIN_SUCCESS': '🔓',
            'LOGOUT_SUCCESS': '🔒',
            'REGISTER_SUCCESS': '✨'
        };
        return icons[action] || '📋';
    }

    formatAction(action) {
        return action
            .split('_')
            .map(word => word.charAt(0) + word.slice(1).toLowerCase())
            .join(' ');
    }

    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    }
}

// Create global audit manager instance
const auditManager = new AuditManager();
