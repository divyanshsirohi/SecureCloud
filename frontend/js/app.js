/**
 * Main Application Module
 * Handles UI initialization and event listeners
 */

class App {
    constructor() {
        this.currentView = 'files';
        this.initialized = false;
    }

    /**
     * Initialize application
     */
    async init() {
        console.log('🚀 Initializing SecureCloud...');

        // Check for existing session
        const hasSession = await authManager.autoLogin();

        if (hasSession) {
            this.showAppScreen();
            await this.loadInitialData();
        } else {
            this.showAuthScreen();
        }

        this.setupEventListeners();
        this.initialized = true;

        console.log('✓ SecureCloud initialized');
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Auth form switching
        document.getElementById('show-register').addEventListener('click', (e) => {
            e.preventDefault();
            this.switchAuthForm('register');
        });

        document.getElementById('show-login').addEventListener('click', (e) => {
            e.preventDefault();
            this.switchAuthForm('login');
        });

        // Auth form submissions
        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.getElementById('registerForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });

        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.handleLogout();
        });

        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const view = item.dataset.view;
                this.switchView(view);
            });
        });

        // File upload
        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file-input');

        document.getElementById('select-files-btn').addEventListener('click', () => {
            fileInput.click();
        });

        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                fileManager.uploadFiles(Array.from(e.target.files));
                e.target.value = '';
            }
        });

        // Drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');

            if (e.dataTransfer.files.length > 0) {
                fileManager.uploadFiles(Array.from(e.dataTransfer.files));
            }
        });

        // File controls
        document.getElementById('refresh-files-btn').addEventListener('click', () => {
            fileManager.loadFiles();
        });

        document.getElementById('file-search').addEventListener('input', (e) => {
            fileManager.setSearch(e.target.value);
        });

        document.getElementById('file-sort').addEventListener('change', (e) => {
            const [sortBy, sortOrder] = e.target.value.split('-');
            fileManager.setSort(sortBy, sortOrder);
        });

        // Share form
        document.getElementById('shareForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleShare();
        });

        // Modal close buttons
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => {
                btn.closest('.modal').classList.remove('active');
            });
        });

        // Close modals on background click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });

        // Shared files refresh
        document.getElementById('refresh-shared-btn').addEventListener('click', () => {
            shareManager.loadSharedFiles();
        });

        // Audit logs controls
        document.getElementById('refresh-audit-btn').addEventListener('click', () => {
            auditManager.loadAuditLogs();
        });

        document.getElementById('export-audit-btn').addEventListener('click', () => {
            auditManager.exportLogs();
        });

        document.getElementById('audit-action-filter').addEventListener('change', () => {
            this.updateAuditFilters();
        });

        document.getElementById('audit-start-date').addEventListener('change', () => {
            this.updateAuditFilters();
        });

        document.getElementById('audit-end-date').addEventListener('change', () => {
            this.updateAuditFilters();
        });

        // Statistics refresh
        document.getElementById('refresh-stats-btn').addEventListener('click', () => {
            this.loadStatistics();
        });
    }

    /**
     * Handle login
     */
    async handleLogin() {
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        const success = await authManager.login(username, password);

        if (success) {
            this.showAppScreen();
            await this.loadInitialData();
        }
    }

    /**
     * Handle registration
     */
    async handleRegister() {
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirm = document.getElementById('register-confirm').value;

        if (password !== confirm) {
            showToast('Passwords do not match', 'error');
            return;
        }

        if (password.length < 8) {
            showToast('Password must be at least 8 characters', 'error');
            return;
        }

        const success = await authManager.register(username, email, password);

        if (success) {
            this.showAppScreen();
            await this.loadInitialData();
        }
    }

    /**
     * Handle logout
     */
    async handleLogout() {
        await authManager.logout();
        this.showAuthScreen();
    }

    /**
     * Handle file sharing
     */
    async handleShare() {
        const fileId = document.getElementById('share-file-id').value;
        const username = document.getElementById('share-username').value;
        const permissions = document.getElementById('share-permissions').value;

        await shareManager.shareFile(fileId, username, permissions);

        document.getElementById('share-username').value = '';
    }

    /**
     * Update audit filters
     */
    updateAuditFilters() {
        const action = document.getElementById('audit-action-filter').value;
        const startDate = document.getElementById('audit-start-date').value;
        const endDate = document.getElementById('audit-end-date').value;

        auditManager.setFilters(action, startDate, endDate);
    }

    /**
     * Switch authentication form
     */
    switchAuthForm(form) {
        document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));

        if (form === 'login') {
            document.getElementById('login-form').classList.add('active');
        } else {
            document.getElementById('register-form').classList.add('active');
        }
    }

    /**
     * Show authentication screen
     */
    showAuthScreen() {
        document.getElementById('auth-screen').classList.add('active');
        document.getElementById('app-screen').classList.remove('active');
    }

    /**
     * Show application screen
     */
    showAppScreen() {
        document.getElementById('auth-screen').classList.remove('active');
        document.getElementById('app-screen').classList.add('active');

        // Update user info
        const user = authManager.getCurrentUser();
        document.getElementById('user-info').textContent = user.username;
    }

    /**
     * Switch view
     */
    switchView(view) {
        this.currentView = view;

        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.view === view) {
                item.classList.add('active');
            }
        });

        // Update views
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.getElementById(`${view}-view`).classList.add('active');

        // Load view data
        this.loadViewData(view);
    }

    /**
     * Load view data
     */
    async loadViewData(view) {
        switch (view) {
            case 'files':
                await fileManager.loadFiles();
                break;
            case 'shared':
                await shareManager.loadSharedFiles();
                break;
            case 'audit':
                await auditManager.loadAuditLogs();
                break;
            case 'stats':
                await this.loadStatistics();
                break;
        }
    }

    /**
     * Load initial data
     */
    async loadInitialData() {
        await this.loadViewData(this.currentView);
        await this.updateStorageInfo();
    }

    /**
     * Load statistics
     */
    async loadStatistics() {
        try {
            const stats = await api.getStats();

            // Update stat cards
            document.getElementById('stat-files').textContent = stats.files.total;
            document.getElementById('stat-storage').textContent =
                fileManager.formatFileSize(stats.files.totalSize);
            document.getElementById('stat-shares').textContent =
                stats.shares.sent + stats.shares.received;
            document.getElementById('stat-avalanche').textContent =
                stats.encryption.averageAvalancheEffect + '%';

            // Render action breakdown
            const actionContainer = document.getElementById('action-breakdown');
            actionContainer.innerHTML = stats.actions.map(action => `
                <div class="action-item">
                    <div>
                        <strong>${auditManager.formatAction(action.action)}</strong>
                        <br>
                        <small>${action.count} times • ${action.success_count} successful</small>
                    </div>
                    <div>
                        <strong>${action.count}</strong>
                    </div>
                </div>
            `).join('');

            // Render encryption metrics
            const metricsContainer = document.getElementById('encryption-metrics');
            metricsContainer.innerHTML = `
                <div class="stat-card">
                    <h4>Avg Encryption Time</h4>
                    <div class="stat-value">${stats.encryption.averageEncryptionTime}ms</div>
                </div>
                <div class="stat-card">
                    <h4>Collision Resistance</h4>
                    <div class="stat-value">${stats.encryption.averageCollisionResistance}</div>
                </div>
                <div class="stat-card">
                    <h4>Avg File Size</h4>
                    <div class="stat-value">${fileManager.formatFileSize(stats.encryption.averageFileSize)}</div>
                </div>
            `;

        } catch (error) {
            console.error('Load statistics error:', error);
            showToast('Failed to load statistics', 'error');
        }
    }

    /**
     * Update storage info
     */
    async updateStorageInfo() {
        try {
            const stats = await api.getStats();
            const totalSize = stats.files.totalSize;
            const maxSize = 10 * 1024 * 1024 * 1024; // 10GB
            const percentage = (totalSize / maxSize) * 100;

            document.querySelector('.storage-fill').style.width = percentage + '%';
            document.getElementById('storage-text').textContent =
                fileManager.formatFileSize(totalSize);

        } catch (error) {
            console.error('Update storage info error:', error);
        }
    }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Show loading overlay
 */
function showLoading(text = 'Processing...') {
    document.getElementById('loading-text').textContent = text;
    document.getElementById('loading-overlay').classList.remove('hidden');
}

/**
 * Hide loading overlay
 */
function hideLoading() {
    document.getElementById('loading-overlay').classList.add('hidden');
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-icon">
            ${type === 'success' ? '✓' : type === 'error' ? '✗' : type === 'warning' ? '⚠' : 'ℹ'}
        </div>
        <div class="toast-message">${message}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, CONFIG.TOAST_DURATION);
}

// ============================================
// APPLICATION STARTUP
// ============================================

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const app = new App();
    app.init();
});
