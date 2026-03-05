/**
 * CPUNK.IO Storage Manager Library
 * Handles session, local storage, and cross-domain storage for SSO
 * 
 * Features:
 * - Session storage management
 * - Local storage management  
 * - Cross-domain storage bridge
 * - Encrypted storage options
 * - Storage event handling
 * - Automatic cleanup
 * 
 * @version 1.0.0
 */

class CpunkStorageManager {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        this.storagePrefix = core?.config?.storage?.sessionPrefix || 'cpunk_io_';
        this.localPrefix = core?.config?.storage?.localPrefix || 'cpunk_io_local_';
        this.encryptionKey = null;
        this.listeners = new Map();
        this.crossDomainBridge = null;
    }

    /**
     * Initialize storage manager
     * @param {Object} options - Configuration options
     */
    async init(options = {}) {
        if (this.initialized) return;

        this.options = {
            enableEncryption: false,
            enableCrossDomain: true,
            autoCleanup: true,
            cleanupInterval: 24 * 60 * 60 * 1000, // 24 hours
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            ...options
        };

        // Setup encryption if enabled
        if (this.options.enableEncryption) {
            await this.setupEncryption();
        }

        // Setup cross-domain bridge if enabled
        if (this.options.enableCrossDomain) {
            this.setupCrossDomainBridge();
        }

        // Setup storage event listeners
        this.setupStorageListeners();

        // Setup automatic cleanup
        if (this.options.autoCleanup) {
            this.setupAutoCleanup();
        }

        this.initialized = true;
        this.core?.log('Storage Manager initialized', this.options);
    }

    /**
     * Session Storage Methods
     */

    /**
     * Set session storage item
     * @param {string} key - Storage key
     * @param {*} value - Value to store
     * @param {Object} options - Storage options
     */
    setSession(key, value, options = {}) {
        const fullKey = this.storagePrefix + key;
        const data = {
            value,
            timestamp: Date.now(),
            expires: options.expires || null,
            encrypted: options.encrypt || false,
            domain: 'cpunk.io'
        };

        try {
            let serializedData = JSON.stringify(data);
            
            if (data.encrypted && this.encryptionKey) {
                serializedData = this.encrypt(serializedData);
            }

            sessionStorage.setItem(fullKey, serializedData);
            
            // Emit storage event
            this.core?.emit('storage:session:set', { key, value, options });
            
            return true;
        } catch (error) {
            this.core?.error('Failed to set session storage:', error);
            return false;
        }
    }

    /**
     * Get session storage item
     * @param {string} key - Storage key
     * @param {*} defaultValue - Default value if not found
     * @returns {*} Stored value or default
     */
    getSession(key, defaultValue = null) {
        const fullKey = this.storagePrefix + key;
        
        try {
            let item = sessionStorage.getItem(fullKey);
            if (!item) return defaultValue;

            // Try to decrypt if needed
            if (this.encryptionKey && !item.startsWith('{')) {
                item = this.decrypt(item);
            }

            const data = JSON.parse(item);
            
            // Check expiration
            if (data.expires && Date.now() > data.expires) {
                this.removeSession(key);
                return defaultValue;
            }

            return data.value;
        } catch (error) {
            this.core?.warn('Failed to get session storage:', error);
            return defaultValue;
        }
    }

    /**
     * Remove session storage item
     * @param {string} key - Storage key
     */
    removeSession(key) {
        const fullKey = this.storagePrefix + key;
        sessionStorage.removeItem(fullKey);
        this.core?.emit('storage:session:remove', { key });
    }

    /**
     * Clear all session storage items
     */
    clearSession() {
        const keysToRemove = [];
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key && key.startsWith(this.storagePrefix)) {
                keysToRemove.push(key);
            }
        }
        
        keysToRemove.forEach(key => {
            sessionStorage.removeItem(key);
        });
        
        this.core?.emit('storage:session:clear', { count: keysToRemove.length });
    }

    /**
     * Local Storage Methods
     */

    /**
     * Set local storage item
     * @param {string} key - Storage key
     * @param {*} value - Value to store
     * @param {Object} options - Storage options
     */
    setLocal(key, value, options = {}) {
        const fullKey = this.localPrefix + key;
        const data = {
            value,
            timestamp: Date.now(),
            expires: options.expires || null,
            encrypted: options.encrypt || false,
            domain: 'cpunk.io'
        };

        try {
            let serializedData = JSON.stringify(data);
            
            if (data.encrypted && this.encryptionKey) {
                serializedData = this.encrypt(serializedData);
            }

            localStorage.setItem(fullKey, serializedData);
            
            this.core?.emit('storage:local:set', { key, value, options });
            return true;
        } catch (error) {
            this.core?.error('Failed to set local storage:', error);
            return false;
        }
    }

    /**
     * Get local storage item
     * @param {string} key - Storage key
     * @param {*} defaultValue - Default value if not found
     * @returns {*} Stored value or default
     */
    getLocal(key, defaultValue = null) {
        const fullKey = this.localPrefix + key;
        
        try {
            let item = localStorage.getItem(fullKey);
            if (!item) return defaultValue;

            if (this.encryptionKey && !item.startsWith('{')) {
                item = this.decrypt(item);
            }

            const data = JSON.parse(item);
            
            if (data.expires && Date.now() > data.expires) {
                this.removeLocal(key);
                return defaultValue;
            }

            return data.value;
        } catch (error) {
            this.core?.warn('Failed to get local storage:', error);
            return defaultValue;
        }
    }

    /**
     * Remove local storage item
     * @param {string} key - Storage key
     */
    removeLocal(key) {
        const fullKey = this.localPrefix + key;
        localStorage.removeItem(fullKey);
        this.core?.emit('storage:local:remove', { key });
    }

    /**
     * Clear all local storage items
     */
    clearLocal() {
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.localPrefix)) {
                keysToRemove.push(key);
            }
        }
        
        keysToRemove.forEach(key => {
            localStorage.removeItem(key);
        });
        
        this.core?.emit('storage:local:clear', { count: keysToRemove.length });
    }

    /**
     * Cross-Domain Storage Methods
     */

    /**
     * Setup cross-domain storage bridge
     */
    setupCrossDomainBridge() {
        // Listen for messages from other domains
        window.addEventListener('message', (event) => {
            // Validate origin
            if (!this.isValidOrigin(event.origin)) {
                return;
            }

            const { type, key, value, requestId } = event.data;

            switch (type) {
                case 'cpunk_storage_get':
                    this.handleCrossDomainGet(event, key, requestId);
                    break;
                case 'cpunk_storage_set':
                    this.handleCrossDomainSet(event, key, value, requestId);
                    break;
                case 'cpunk_storage_remove':
                    this.handleCrossDomainRemove(event, key, requestId);
                    break;
            }
        });

        this.core?.log('Cross-domain storage bridge initialized');
    }

    /**
     * Get value from another domain
     * @param {string} domain - Target domain
     * @param {string} key - Storage key
     * @returns {Promise} Promise resolving to stored value
     */
    async getCrossDomain(domain, key) {
        return new Promise((resolve, reject) => {
            const requestId = this.core?.generateUUID() || Math.random().toString(36);
            const timeout = setTimeout(() => {
                reject(new Error('Cross-domain storage request timeout'));
            }, 5000);

            const handleResponse = (event) => {
                if (event.data.requestId === requestId && event.data.type === 'cpunk_storage_response') {
                    clearTimeout(timeout);
                    window.removeEventListener('message', handleResponse);
                    resolve(event.data.value);
                }
            };

            window.addEventListener('message', handleResponse);

            // Send request to target domain
            const iframe = this.getOrCreateIframe(domain);
            iframe.contentWindow.postMessage({
                type: 'cpunk_storage_get',
                key,
                requestId
            }, domain);
        });
    }

    /**
     * Set value in another domain
     * @param {string} domain - Target domain
     * @param {string} key - Storage key
     * @param {*} value - Value to store
     * @returns {Promise} Promise resolving to success status
     */
    async setCrossDomain(domain, key, value) {
        return new Promise((resolve, reject) => {
            const requestId = this.core?.generateUUID() || Math.random().toString(36);
            const timeout = setTimeout(() => {
                reject(new Error('Cross-domain storage request timeout'));
            }, 5000);

            const handleResponse = (event) => {
                if (event.data.requestId === requestId && event.data.type === 'cpunk_storage_response') {
                    clearTimeout(timeout);
                    window.removeEventListener('message', handleResponse);
                    resolve(event.data.success);
                }
            };

            window.addEventListener('message', handleResponse);

            const iframe = this.getOrCreateIframe(domain);
            iframe.contentWindow.postMessage({
                type: 'cpunk_storage_set',
                key,
                value,
                requestId
            }, domain);
        });
    }

    /**
     * Handle cross-domain get request
     */
    handleCrossDomainGet(event, key, requestId) {
        const value = this.getSession(key);
        event.source.postMessage({
            type: 'cpunk_storage_response',
            value,
            requestId
        }, event.origin);
    }

    /**
     * Handle cross-domain set request
     */
    handleCrossDomainSet(event, key, value, requestId) {
        const success = this.setSession(key, value);
        event.source.postMessage({
            type: 'cpunk_storage_response',
            success,
            requestId
        }, event.origin);
    }

    /**
     * Handle cross-domain remove request
     */
    handleCrossDomainRemove(event, key, requestId) {
        this.removeSession(key);
        event.source.postMessage({
            type: 'cpunk_storage_response',
            success: true,
            requestId
        }, event.origin);
    }

    /**
     * Get or create iframe for cross-domain communication
     */
    getOrCreateIframe(domain) {
        let iframe = document.querySelector(`iframe[data-domain="${domain}"]`);
        if (!iframe) {
            iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.setAttribute('data-domain', domain);
            iframe.src = `${domain}/storage-bridge.html`;
            document.body.appendChild(iframe);
        }
        return iframe;
    }

    /**
     * Validate origin for cross-domain requests
     */
    isValidOrigin(origin) {
        const validOrigins = [
            'https://cpunk.club',
            'https://cpunk.io',
            'http://localhost:3000',
            'http://127.0.0.1:3000'
        ];
        return validOrigins.includes(origin);
    }

    /**
     * Encryption Methods
     */

    /**
     * Setup encryption
     */
    async setupEncryption() {
        // Simple base64 encoding for now
        // In production, use proper encryption
        this.encryptionKey = 'cpunk_io_key_2025';
        this.core?.log('Encryption setup completed');
    }

    /**
     * Encrypt data
     */
    encrypt(data) {
        try {
            return btoa(data);
        } catch (error) {
            this.core?.warn('Encryption failed, storing as plain text');
            return data;
        }
    }

    /**
     * Decrypt data
     */
    decrypt(data) {
        try {
            return atob(data);
        } catch (error) {
            this.core?.warn('Decryption failed, returning as-is');
            return data;
        }
    }

    /**
     * Utility Methods
     */

    /**
     * Setup storage event listeners
     */
    setupStorageListeners() {
        window.addEventListener('storage', (event) => {
            if (event.key && event.key.startsWith(this.localPrefix)) {
                this.core?.emit('storage:external:change', {
                    key: event.key.replace(this.localPrefix, ''),
                    oldValue: event.oldValue,
                    newValue: event.newValue,
                    url: event.url
                });
            }
        });
    }

    /**
     * Setup automatic cleanup
     */
    setupAutoCleanup() {
        setInterval(() => {
            this.cleanupExpired();
        }, this.options.cleanupInterval);

        // Initial cleanup
        setTimeout(() => {
            this.cleanupExpired();
        }, 1000);
    }

    /**
     * Cleanup expired items
     */
    cleanupExpired() {
        const now = Date.now();
        let sessionCleaned = 0;
        let localCleaned = 0;

        // Clean session storage
        for (let i = sessionStorage.length - 1; i >= 0; i--) {
            const key = sessionStorage.key(i);
            if (key && key.startsWith(this.storagePrefix)) {
                try {
                    const item = sessionStorage.getItem(key);
                    const data = JSON.parse(item);
                    
                    if (data.expires && now > data.expires) {
                        sessionStorage.removeItem(key);
                        sessionCleaned++;
                    } else if (data.timestamp && (now - data.timestamp) > this.options.maxAge) {
                        sessionStorage.removeItem(key);
                        sessionCleaned++;
                    }
                } catch (error) {
                    // Remove corrupted items
                    sessionStorage.removeItem(key);
                    sessionCleaned++;
                }
            }
        }

        // Clean local storage
        for (let i = localStorage.length - 1; i >= 0; i--) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.localPrefix)) {
                try {
                    const item = localStorage.getItem(key);
                    const data = JSON.parse(item);
                    
                    if (data.expires && now > data.expires) {
                        localStorage.removeItem(key);
                        localCleaned++;
                    } else if (data.timestamp && (now - data.timestamp) > this.options.maxAge) {
                        localStorage.removeItem(key);
                        localCleaned++;
                    }
                } catch (error) {
                    localStorage.removeItem(key);
                    localCleaned++;
                }
            }
        }

        if (sessionCleaned > 0 || localCleaned > 0) {
            this.core?.log(`Storage cleanup: ${sessionCleaned} session, ${localCleaned} local items removed`);
        }
    }

    /**
     * Get storage statistics
     */
    getStats() {
        const stats = {
            session: { count: 0, size: 0 },
            local: { count: 0, size: 0 },
            total: { count: 0, size: 0 }
        };

        // Count session storage
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key && key.startsWith(this.storagePrefix)) {
                stats.session.count++;
                stats.session.size += sessionStorage.getItem(key).length;
            }
        }

        // Count local storage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.localPrefix)) {
                stats.local.count++;
                stats.local.size += localStorage.getItem(key).length;
            }
        }

        stats.total.count = stats.session.count + stats.local.count;
        stats.total.size = stats.session.size + stats.local.size;

        return stats;
    }

    /**
     * Export storage data
     */
    exportData() {
        const data = {
            session: {},
            local: {},
            timestamp: Date.now(),
            version: '1.0.0'
        };

        // Export session storage
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key && key.startsWith(this.storagePrefix)) {
                const shortKey = key.replace(this.storagePrefix, '');
                data.session[shortKey] = this.getSession(shortKey);
            }
        }

        // Export local storage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.localPrefix)) {
                const shortKey = key.replace(this.localPrefix, '');
                data.local[shortKey] = this.getLocal(shortKey);
            }
        }

        return data;
    }

    /**
     * Import storage data
     */
    importData(data) {
        if (!data || typeof data !== 'object') {
            throw new Error('Invalid data format');
        }

        let imported = { session: 0, local: 0 };

        // Import session data
        if (data.session) {
            Object.entries(data.session).forEach(([key, value]) => {
                if (this.setSession(key, value)) {
                    imported.session++;
                }
            });
        }

        // Import local data
        if (data.local) {
            Object.entries(data.local).forEach(([key, value]) => {
                if (this.setLocal(key, value)) {
                    imported.local++;
                }
            });
        }

        this.core?.log('Storage data imported:', imported);
        return imported;
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('storage', new CpunkStorageManager(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkStorageManager;
}