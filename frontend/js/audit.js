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

        container.innerHTML = this.currentLogs.map(log => `
            <div class="audit-item">
                <div class="audit-icon">
                    ${this.getActionIcon(log.action)}
                </div>
                <div class="audit-info">
                    <h4>${this.formatAction(log.action)}</h4>
                    <div class="audit-meta">
                        ${this.formatDate(log.timestamp)} • 
                        ${log.encryption_time_ms ? `${log.encryption_time_ms}ms` : ''} •
                        ${log.ip_address || 'Unknown IP'}
                        ${log.avalanche_effect_percentage ? ` • Avalanche: ${log.avalanche_effect_percentage}%` : ''}
                    </div>
                    ${log.error_message ? `<small style="color: var(--error);">${log.error_message}</small>` : ''}
                </div>
                <div class="audit-status ${log.success ? 'success' : 'error'}">
                    ${log.success ? '✓ Success' : '✗ Failed'}
                </div>
            </div>
        `).join('');
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
