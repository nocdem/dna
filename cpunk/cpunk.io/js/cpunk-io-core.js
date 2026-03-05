/**
 * CPUNK.IO Core Library
 * Foundation library for CPUNK identity protocol
 * Provides core utilities, configuration, and event system
 * 
 * @version 1.0.0
 * @author CPUNK Protocol Team
 */

class CpunkIOCore {
    constructor() {
        this.version = '1.0.0';
        this.domain = 'cpunk.io';
        this.config = {
            api: {
                dashboard: 'http://localhost:8045/',
                dnaProxy: '/dna-proxy.php',
                rpcEndpoint: 'http://rpc.cellframe.net/connect'
            },
            blockchain: {
                network: 'Backbone',
                treasuryAddress: 'Rj7J7MiX2bWy8sNyZcoLqkZuNznvU4KbK6RHgqrGj9iqwKPhoVKE1xNrEMmgtVsnyTZtFhftMPAJbaswuSLp7UeBS7jiRmE5uvuUJaKA',
                tokenDecimals: 18
            },
            ui: {
                animationDuration: 300,
                debounceDelay: 500,
                maxRetries: 10
            },
            storage: {
                sessionPrefix: 'cpunk_io_',
                localPrefix: 'cpunk_io_local_'
            },
            domains: {
                club: 'https://cpunk.club',
                io: 'https://cpunk.io',
                api: 'https://api.dna.cpunk.club'
            }
        };
        
        this.events = new EventTarget();
        this.modules = new Map();
        this.initialized = false;
        this.debug = true;
    }

    /**
     * Initialize CPUNK.IO Core
     * @param {Object} options - Configuration options
     */
    async init(options = {}) {
        if (this.initialized) {
            this.log('Core already initialized');
            return;
        }

        // Merge custom configuration
        this.config = this.deepMerge(this.config, options);
        
        // Set up global error handling
        this.setupErrorHandling();
        
        // Initialize core features
        await this.detectEnvironment();
        this.setupEventSystem();
        
        this.initialized = true;
        this.log('CPUNK.IO Core initialized', this.config);
        
        // Emit initialization event
        this.emit('core:initialized', { version: this.version });
    }

    /**
     * Register a module
     * @param {string} name - Module name
     * @param {Object} module - Module instance
     */
    registerModule(name, module) {
        if (this.modules.has(name)) {
            this.warn(`Module ${name} already registered, replacing`);
        }
        
        this.modules.set(name, module);
        this.log(`Module registered: ${name}`);
        
        // Set up module communication
        if (module.init && typeof module.init === 'function') {
            module.init(this);
        }
        
        this.emit('module:registered', { name, module });
    }

    /**
     * Get a registered module
     * @param {string} name - Module name
     * @returns {Object|null} Module instance
     */
    getModule(name) {
        return this.modules.get(name) || null;
    }

    /**
     * Emit an event
     * @param {string} eventName - Event name
     * @param {Object} data - Event data
     */
    emit(eventName, data = {}) {
        this.events.dispatchEvent(new CustomEvent(eventName, { detail: data }));
    }

    /**
     * Listen to an event
     * @param {string} eventName - Event name
     * @param {Function} callback - Event handler
     */
    on(eventName, callback) {
        this.events.addEventListener(eventName, (event) => {
            callback(event.detail, event);
        });
    }

    /**
     * Remove event listener
     * @param {string} eventName - Event name
     * @param {Function} callback - Event handler
     */
    off(eventName, callback) {
        this.events.removeEventListener(eventName, callback);
    }

    /**
     * Format balance for display
     * @param {string|number} balance - Balance value
     * @param {number} decimals - Decimal places
     * @returns {string} Formatted balance
     */
    formatBalance(balance, decimals = 3) {
        const num = parseFloat(balance);
        if (num === 0) return '0';
        if (num < Math.pow(10, -decimals)) return `< ${Math.pow(10, -decimals)}`;
        return num.toLocaleString(undefined, { 
            minimumFractionDigits: 0, 
            maximumFractionDigits: decimals 
        });
    }

    /**
     * Format address for display
     * @param {string} address - Wallet address
     * @param {number} startChars - Characters to show at start
     * @param {number} endChars - Characters to show at end
     * @returns {string} Formatted address
     */
    formatAddress(address, startChars = 6, endChars = 6) {
        if (!address || address.length <= startChars + endChars) {
            return address;
        }
        return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
    }

    /**
     * Generate UUID v4
     * @returns {string} UUID
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    /**
     * Debounce function calls
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in ms
     * @returns {Function} Debounced function
     */
    debounce(func, wait = this.config.ui.debounceDelay) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * Deep merge objects
     * @param {Object} target - Target object
     * @param {Object} source - Source object
     * @returns {Object} Merged object
     */
    deepMerge(target, source) {
        const output = Object.assign({}, target);
        if (this.isObject(target) && this.isObject(source)) {
            Object.keys(source).forEach(key => {
                if (this.isObject(source[key])) {
                    if (!(key in target)) {
                        Object.assign(output, { [key]: source[key] });
                    } else {
                        output[key] = this.deepMerge(target[key], source[key]);
                    }
                } else {
                    Object.assign(output, { [key]: source[key] });
                }
            });
        }
        return output;
    }

    /**
     * Check if value is object
     * @param {*} item - Value to check
     * @returns {boolean} Is object
     */
    isObject(item) {
        return item && typeof item === 'object' && !Array.isArray(item);
    }

    /**
     * Sleep/delay utility
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise} Promise that resolves after delay
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Retry function with exponential backoff
     * @param {Function} func - Function to retry
     * @param {number} maxRetries - Maximum retry attempts
     * @param {number} baseDelay - Base delay in ms
     * @returns {Promise} Promise that resolves with function result
     */
    async retry(func, maxRetries = this.config.ui.maxRetries, baseDelay = 1000) {
        let lastError;
        
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                return await func();
            } catch (error) {
                lastError = error;
                
                if (attempt === maxRetries) {
                    throw error;
                }
                
                const delay = baseDelay * Math.pow(2, attempt);
                this.log(`Retry attempt ${attempt + 1}/${maxRetries + 1} after ${delay}ms`);
                await this.sleep(delay);
            }
        }
        
        throw lastError;
    }

    /**
     * Setup global error handling
     */
    setupErrorHandling() {
        window.addEventListener('unhandledrejection', (event) => {
            this.error('Unhandled promise rejection:', event.reason);
            this.emit('error:unhandled', { error: event.reason, type: 'promise' });
        });

        window.addEventListener('error', (event) => {
            this.error('Global error:', event.error || event.message);
            this.emit('error:unhandled', { error: event.error || event.message, type: 'javascript' });
        });
    }

    /**
     * Setup event system
     */
    setupEventSystem() {
        // Global event bus for cross-module communication
        if (!window.cpunkEventBus) {
            window.cpunkEventBus = new EventTarget();
        }
    }

    /**
     * Detect environment and capabilities
     */
    async detectEnvironment() {
        this.environment = {
            browser: this.detectBrowser(),
            mobile: this.isMobile(),
            features: {
                localStorage: this.hasLocalStorage(),
                sessionStorage: this.hasSessionStorage(),
                webgl: this.hasWebGL(),
                webassembly: this.hasWebAssembly()
            }
        };
        
        this.log('Environment detected:', this.environment);
    }

    /**
     * Detect browser type
     * @returns {string} Browser name
     */
    detectBrowser() {
        const ua = navigator.userAgent;
        if (ua.includes('Chrome')) return 'chrome';
        if (ua.includes('Firefox')) return 'firefox';
        if (ua.includes('Safari')) return 'safari';
        if (ua.includes('Edge')) return 'edge';
        return 'unknown';
    }

    /**
     * Check if mobile device
     * @returns {boolean} Is mobile
     */
    isMobile() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    }

    /**
     * Check localStorage support
     * @returns {boolean} Has localStorage
     */
    hasLocalStorage() {
        try {
            const test = 'test';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Check sessionStorage support
     * @returns {boolean} Has sessionStorage
     */
    hasSessionStorage() {
        try {
            const test = 'test';
            sessionStorage.setItem(test, test);
            sessionStorage.removeItem(test);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Check WebGL support
     * @returns {boolean} Has WebGL
     */
    hasWebGL() {
        try {
            const canvas = document.createElement('canvas');
            return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
        } catch (e) {
            return false;
        }
    }

    /**
     * Check WebAssembly support
     * @returns {boolean} Has WebAssembly
     */
    hasWebAssembly() {
        return typeof WebAssembly === 'object';
    }

    /**
     * Logging methods
     */
    log(...args) {
        if (this.debug) {
            console.log(`[CPUNK.IO Core]`, ...args);
        }
    }

    warn(...args) {
        console.warn(`[CPUNK.IO Core]`, ...args);
    }

    error(...args) {
        console.error(`[CPUNK.IO Core]`, ...args);
    }
}

// Create global instance
window.CpunkIO = new CpunkIOCore();

// Auto-initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.CpunkIO.init();
    });
} else {
    // DOM already loaded
    window.CpunkIO.init();
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkIOCore;
}