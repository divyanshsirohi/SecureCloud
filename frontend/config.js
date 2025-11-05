const CONFIG = {
    // Use relative path for API (same domain)
    API_BASE_URL: window.location.origin + '/api',

    ENCRYPTION: {
        RSA_KEY_SIZE: 2048,
        AES_KEY_SIZE: 256,
        PBKDF2_ITERATIONS: 500000,
    },

    UPLOAD: {
        MAX_FILE_SIZE: 100 * 1024 * 1024,
        ALLOWED_TYPES: '*',
    },

    PAGINATION: {
        FILES_PER_PAGE: 20,
        AUDIT_PER_PAGE: 50,
    },

    TOAST_DURATION: 4000,
};
