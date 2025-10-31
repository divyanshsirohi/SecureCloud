/**
 * Authentication Module
 * Handles user registration, login, and session management
 */

class AuthManager {
    constructor() {
        this.currentUser = null;
        this.keyPair = null;
    }

    /**
     * Register new user
     */
    async register(username, email, password) {
        showLoading('Generating encryption keys...');

        try {
            // Generate RSA key pair
            const keyPair = await cryptoManager.generateRSAKeyPair();

            // Export public key
            const publicKey = await cryptoManager.exportPublicKey(keyPair.publicKey);

            // Generate salt for private key encryption
            const salt = cryptoManager.generateSalt();

            // Encrypt private key with master password
            showLoading('Encrypting private key...');
            const encryptedPrivateKey = await cryptoManager.encryptPrivateKey(
                keyPair.privateKey,
                password,
                cryptoManager.base64ToArrayBuffer(salt)
            );

            // Hash password for server authentication
            showLoading('Creating account...');
            const passwordHash = await cryptoManager.hashPassword(password);

            // Register with server
            const response = await api.register({
                username,
                email,
                passwordHash,
                publicKey,
                encryptedPrivateKey: JSON.stringify(encryptedPrivateKey),
                salt,
            });

            // Store auth token
            api.setToken(response.token);

            // Store user data
            this.currentUser = response.user;
            this.keyPair = keyPair;

            // Store master password temporarily (for this session only)
            sessionStorage.setItem('masterPassword', password);

            hideLoading();
            showToast('Account created successfully!', 'success');

            return true;

        } catch (error) {
            hideLoading();
            console.error('Registration error:', error);
            showToast(error.message || 'Registration failed', 'error');
            return false;
        }
    }

    /**
     * Login user
     */
    async login(username, password) {
        showLoading('Logging in...');

        try {
            // Hash password
            const passwordHash = await cryptoManager.hashPassword(password);

            // Login to server
            const response = await api.login({ username, passwordHash });

            // Store auth token
            api.setToken(response.token);

            // Decrypt private key
            showLoading('Decrypting your keys...');
            const encryptedPrivateKey = JSON.parse(response.user.encryptedPrivateKey);
            const salt = cryptoManager.base64ToArrayBuffer(response.user.salt);

            try {
                const privateKey = await cryptoManager.decryptPrivateKey(
                    encryptedPrivateKey,
                    password,
                    salt
                );

                // Import public key
                const publicKey = await cryptoManager.importPublicKey(response.user.publicKey);

                // Store keys
                this.keyPair = { publicKey, privateKey };
                this.currentUser = response.user;

                // Store master password temporarily
                sessionStorage.setItem('masterPassword', password);

                hideLoading();
                showToast('Login successful!', 'success');

                return true;

            } catch (error) {
                hideLoading();
                showToast('Invalid master password', 'error');
                return false;
            }

        } catch (error) {
            hideLoading();
            console.error('Login error:', error);
            showToast(error.message || 'Login failed', 'error');
            return false;
        }
    }

    /**
     * Logout user
     */
    async logout() {
        try {
            await api.logout();
        } catch (error) {
            console.error('Logout error:', error);
        }

        // Clear session data
        api.setToken(null);
        this.currentUser = null;
        this.keyPair = null;
        sessionStorage.clear();

        showToast('Logged out successfully', 'info');
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!api.token && !!this.currentUser && !!this.keyPair;
    }

    /**
     * Get current user
     */
    getCurrentUser() {
        return this.currentUser;
    }

    /**
     * Get key pair
     */
    getKeyPair() {
        return this.keyPair;
    }

    /**
     * Auto-login if token exists
     */
    async autoLogin() {
        const token = localStorage.getItem('authToken');

        if (!token) {
            return false;
        }

        try {
            showLoading('Restoring session...');

            // Get current user from server
            const response = await api.getCurrentUser();
            this.currentUser = response.user;

            // Check if master password is stored (in session)
            const masterPassword = sessionStorage.getItem('masterPassword');

            if (masterPassword) {
                // Decrypt private key
                const encryptedPrivateKey = JSON.parse(this.currentUser.encryptedPrivateKey);
                const salt = cryptoManager.base64ToArrayBuffer(this.currentUser.salt);

                const privateKey = await cryptoManager.decryptPrivateKey(
                    encryptedPrivateKey,
                    masterPassword,
                    salt
                );

                const publicKey = await cryptoManager.importPublicKey(this.currentUser.publicKey);
                this.keyPair = { publicKey, privateKey };

                hideLoading();
                return true;
            } else {
                // Need to re-enter master password
                hideLoading();
                return false;
            }

        } catch (error) {
            console.error('Auto-login error:', error);
            api.setToken(null);
            hideLoading();
            return false;
        }
    }
}

// Create global auth manager instance
const authManager = new AuthManager();
