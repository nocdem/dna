/**
 * CPUNK.IO SSO Client Library
 * Cross-domain Single Sign-On authentication
 * 
 * Features:
 * - Cross-domain authentication bridge
 * - Token-based session management
 * - Automatic session synchronization
 * - Secure message passing
 * - Session restoration
 * - Multi-domain support
 * - Event-driven architecture
 * 
 * @version 1.0.0
 */

class CpunkSSOClient {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        
        // Configuration
        this.config = {
            domains: {
                club: 'https://cpunk.club',
                io: 'https://cpunk.io',
                local: ['http://localhost:3000', 'http://127.0.0.1:3000']
            },
            sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
            syncInterval: 5 * 60 * 1000, // 5 minutes
            enableAutoSync: true,
            enableSecureMessages: true,
            cookieDomain: '.cpunk.io', // For shared cookies if possible
            bridgeTimeout: 10000 // 10 seconds
        };
        
        // Authentication state
        this.isAuthenticated = false;
        this.currentUser = null;
        this.sessionToken = null;
        this.sessionData = null;
        this.lastSync = null;
        
        // Cross-domain communication
        this.messageHandlers = new Map();
        this.pendingRequests = new Map();
        this.bridgeFrames = new Map();
        this.requestId = 0;
        
        // Event handlers
        this.eventHandlers = {
            authenticated: [],
            unauthenticated: [],
            sessionChanged: [],
            error: [],
            syncComplete: []
        };
        
        // Sync timer
        this.syncTimer = null;
    }

    /**
     * Initialize SSO client
     * @param {Object} options - Configuration options
     */
    async init(options = {}) {
        if (this.initialized) return;

        // Merge configuration
        this.config = this.core?.deepMerge(this.config, options) || { ...this.config, ...options };

        // Get required modules
        this.storage = this.core?.getModule('storage');
        this.wallet = this.core?.getModule('wallet');

        // Setup cross-domain communication
        this.setupMessageHandlers();
        
        // Setup authentication bridges
        await this.setupAuthBridges();
        
        // Restore session if exists
        await this.restoreSession();
        
        // Setup automatic sync
        if (this.config.enableAutoSync) {
            this.setupAutoSync();
        }

        this.initialized = true;
        this.core?.log('SSO Client initialized', {
            domains: this.config.domains,
            authenticated: this.isAuthenticated
        });

        // Emit initial authentication state
        if (this.isAuthenticated) {
            this.emit('authenticated', { user: this.currentUser, restored: true });
        } else {
            this.emit('unauthenticated', { restored: true });
        }
    }

    /**
     * Authentication Methods
     */

    /**
     * Authenticate user with session data
     * @param {Object} sessionData - Session data from login
     * @returns {Promise<Object>} Authentication result
     */
    async authenticate(sessionData) {
        try {
            const {
                sessionId,
                dna,
                walletName,
                walletAddress,
                network,
                balances
            } = sessionData;

            // Validate session data
            if (!sessionId || !dna || !walletAddress) {
                throw new Error('Invalid session data provided');
            }

            // Generate session token
            this.sessionToken = this.generateSessionToken();
            
            // Store authentication state
            this.isAuthenticated = true;
            this.currentUser = {
                dna,
                walletName,
                walletAddress,
                network,
                balances,
                authenticatedAt: Date.now()
            };
            
            this.sessionData = {
                sessionId,
                sessionToken: this.sessionToken,
                ...this.currentUser
            };

            // Store in local storage
            await this.storeSession();
            
            // Sync across domains
            await this.syncSessionAcrossDomains();

            this.core?.log('User authenticated successfully', { dna, walletAddress });
            this.emit('authenticated', { user: this.currentUser });

            return {
                success: true,
                user: this.currentUser,
                sessionToken: this.sessionToken
            };

        } catch (error) {
            this.core?.error('Authentication failed:', error);
            this.emit('error', { type: 'authentication', error: error.message });
            throw error;
        }
    }

    /**
     * Logout user
     * @returns {Promise<void>}
     */
    async logout() {
        try {
            // Clear authentication state
            this.isAuthenticated = false;
            this.currentUser = null;
            this.sessionToken = null;
            this.sessionData = null;

            // Clear local storage
            this.clearStoredSession();
            
            // Sync logout across domains
            await this.syncLogoutAcrossDomains();

            this.core?.log('User logged out successfully');
            this.emit('unauthenticated', { logout: true });

        } catch (error) {
            this.core?.error('Logout failed:', error);
            this.emit('error', { type: 'logout', error: error.message });
        }
    }

    /**
     * Check if user is authenticated
     * @returns {boolean} Is authenticated
     */
    isUserAuthenticated() {
        return this.isAuthenticated && this.currentUser && this.sessionToken;
    }

    /**
     * Get current user
     * @returns {Object|null} Current user data
     */
    getCurrentUser() {
        return this.currentUser;
    }

    /**
     * Get session data
     * @returns {Object|null} Session data
     */
    getSessionData() {
        return this.sessionData;
    }

    /**
     * Cross-Domain Communication
     */

    /**
     * Setup authentication bridges to other domains
     */
    async setupAuthBridges() {
        const currentDomain = window.location.origin;
        
        // Setup bridges to other domains
        for (const [key, domain] of Object.entries(this.config.domains)) {
            if (typeof domain === 'string' && domain !== currentDomain) {
                await this.createBridge(domain);
            } else if (Array.isArray(domain)) {
                for (const d of domain) {
                    if (d !== currentDomain) {
                        await this.createBridge(d);
                    }
                }
            }
        }
    }

    /**
     * Create authentication bridge iframe
     * @param {string} domain - Target domain
     */
    async createBridge(domain) {
        try {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.style.position = 'absolute';
            iframe.style.width = '1px';
            iframe.style.height = '1px';
            iframe.style.left = '-9999px';
            
            // Create bridge page URL
            const bridgeUrl = `${domain}/sso-bridge.html`;
            iframe.src = bridgeUrl;
            
            // Add to DOM
            document.body.appendChild(iframe);
            
            // Wait for iframe to load
            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new Error(`Bridge timeout for ${domain}`));
                }, this.config.bridgeTimeout);
                
                iframe.onload = () => {
                    clearTimeout(timeout);
                    resolve();
                };
                
                iframe.onerror = () => {
                    clearTimeout(timeout);
                    reject(new Error(`Bridge load failed for ${domain}`));
                };
            });
            
            this.bridgeFrames.set(domain, iframe);
            this.core?.log(`SSO bridge created for ${domain}`);

        } catch (error) {
            this.core?.warn(`Failed to create SSO bridge for ${domain}:`, error.message);
        }
    }

    /**
     * Setup cross-domain message handlers
     */
    setupMessageHandlers() {
        window.addEventListener('message', (event) => {
            // Validate origin
            if (!this.isValidOrigin(event.origin)) {
                return;
            }

            const { type, data, requestId } = event.data;

            switch (type) {
                case 'sso_session_request':
                    this.handleSessionRequest(event, requestId);
                    break;
                case 'sso_session_data':
                    this.handleSessionData(event, data, requestId);
                    break;
                case 'sso_session_sync':
                    this.handleSessionSync(event, data);
                    break;
                case 'sso_logout_sync':
                    this.handleLogoutSync(event);
                    break;
                case 'sso_response':
                    this.handleResponse(event, data, requestId);
                    break;
                default:
                    // Unknown message type
                    break;
            }
        });
    }

    /**
     * Send cross-domain message
     * @param {string} domain - Target domain
     * @param {string} type - Message type
     * @param {Object} data - Message data
     * @param {boolean} expectResponse - Whether to expect a response
     * @returns {Promise<Object>} Response data
     */
    async sendCrossDomainMessage(domain, type, data = {}, expectResponse = false) {
        const iframe = this.bridgeFrames.get(domain);
        if (!iframe) {
            throw new Error(`No bridge available for domain: ${domain}`);
        }

        const requestId = this.generateRequestId();
        
        const message = {
            type,
            data,
            requestId,
            origin: window.location.origin,
            timestamp: Date.now()
        };

        if (expectResponse) {
            return new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    this.pendingRequests.delete(requestId);
                    reject(new Error('Cross-domain message timeout'));
                }, this.config.bridgeTimeout);

                this.pendingRequests.set(requestId, { resolve, reject, timeout });
                iframe.contentWindow.postMessage(message, domain);
            });
        } else {
            iframe.contentWindow.postMessage(message, domain);
        }
    }

    /**
     * Handle session request from other domain
     */
    handleSessionRequest(event, requestId) {
        const sessionData = this.isAuthenticated ? {
            authenticated: true,
            user: this.currentUser,
            sessionToken: this.sessionToken,
            sessionData: this.sessionData
        } : {
            authenticated: false
        };

        event.source.postMessage({
            type: 'sso_response',
            data: sessionData,
            requestId
        }, event.origin);
    }

    /**
     * Handle session data from other domain
     */
    handleSessionData(event, data, requestId) {
        if (data.authenticated && !this.isAuthenticated) {
            // Restore authentication from other domain
            this.restoreFromCrossDomainData(data);
        }
        
        // Send acknowledgment
        event.source.postMessage({
            type: 'sso_response',
            data: { received: true },
            requestId
        }, event.origin);
    }

    /**
     * Handle session sync from other domain
     */
    handleSessionSync(event, data) {
        if (data.authenticated && data.sessionToken !== this.sessionToken) {
            this.restoreFromCrossDomainData(data);
            this.emit('sessionChanged', { source: event.origin, data });
        }
    }

    /**
     * Handle logout sync from other domain
     */
    handleLogoutSync(event) {
        if (this.isAuthenticated) {
            this.logout();
            this.emit('sessionChanged', { source: event.origin, logout: true });
        }
    }

    /**
     * Handle response from cross-domain request
     */
    handleResponse(event, data, requestId) {
        const pendingRequest = this.pendingRequests.get(requestId);
        if (pendingRequest) {
            clearTimeout(pendingRequest.timeout);
            this.pendingRequests.delete(requestId);
            pendingRequest.resolve(data);
        }
    }

    /**
     * Session Synchronization
     */

    /**
     * Sync session across all domains
     */
    async syncSessionAcrossDomains() {
        if (!this.isAuthenticated) return;

        const syncData = {
            authenticated: true,
            user: this.currentUser,
            sessionToken: this.sessionToken,
            sessionData: this.sessionData,
            syncedAt: Date.now()
        };

        const syncPromises = [];
        
        for (const domain of this.bridgeFrames.keys()) {
            syncPromises.push(
                this.sendCrossDomainMessage(domain, 'sso_session_sync', syncData).catch(error => {
                    this.core?.warn(`Failed to sync session to ${domain}:`, error.message);
                })
            );
        }

        await Promise.allSettled(syncPromises);
        this.lastSync = Date.now();
        this.emit('syncComplete', { syncedDomains: this.bridgeFrames.size });
    }

    /**
     * Sync logout across all domains
     */
    async syncLogoutAcrossDomains() {
        const logoutPromises = [];
        
        for (const domain of this.bridgeFrames.keys()) {
            logoutPromises.push(
                this.sendCrossDomainMessage(domain, 'sso_logout_sync', {}).catch(error => {
                    this.core?.warn(`Failed to sync logout to ${domain}:`, error.message);
                })
            );
        }

        await Promise.allSettled(logoutPromises);
    }

    /**
     * Request session from other domain
     * @param {string} domain - Target domain
     * @returns {Promise<Object>} Session data
     */
    async requestSessionFromDomain(domain) {
        try {
            const response = await this.sendCrossDomainMessage(domain, 'sso_session_request', {}, true);
            return response;
        } catch (error) {
            this.core?.warn(`Failed to request session from ${domain}:`, error.message);
            return { authenticated: false };
        }
    }

    /**
     * Setup automatic session sync
     */
    setupAutoSync() {
        this.syncTimer = setInterval(async () => {
            if (this.isAuthenticated) {
                await this.syncSessionAcrossDomains();
            }
        }, this.config.syncInterval);
    }

    /**
     * Session Storage
     */

    /**
     * Store session in local storage
     */
    async storeSession() {
        if (!this.storage || !this.sessionData) return;

        try {
            const sessionToStore = {
                ...this.sessionData,
                storedAt: Date.now()
            };

            this.storage.setLocal('sso_session', sessionToStore, {
                expires: Date.now() + this.config.sessionTimeout
            });

            // Also store in session storage for immediate access
            this.storage.setSession('sso_current_session', sessionToStore);

        } catch (error) {
            this.core?.error('Failed to store session:', error);
        }
    }

    /**
     * Restore session from storage
     */
    async restoreSession() {
        if (!this.storage) return false;

        try {
            // Try session storage first
            let storedSession = this.storage.getSession('sso_current_session');
            
            // Fallback to local storage
            if (!storedSession) {
                storedSession = this.storage.getLocal('sso_session');
            }

            if (storedSession && this.isValidSession(storedSession)) {
                await this.restoreFromStoredSession(storedSession);
                return true;
            }

            // Try to get session from other domains
            const domains = Object.values(this.config.domains).flat().filter(d => 
                typeof d === 'string' && d !== window.location.origin
            );

            for (const domain of domains) {
                try {
                    const crossDomainSession = await this.requestSessionFromDomain(domain);
                    if (crossDomainSession && crossDomainSession.authenticated) {
                        await this.restoreFromCrossDomainData(crossDomainSession);
                        return true;
                    }
                } catch (error) {
                    // Continue to next domain
                }
            }

        } catch (error) {
            this.core?.error('Failed to restore session:', error);
        }

        return false;
    }

    /**
     * Restore authentication from stored session
     * @param {Object} storedSession - Stored session data
     */
    async restoreFromStoredSession(storedSession) {
        this.isAuthenticated = true;
        this.sessionToken = storedSession.sessionToken;
        this.sessionData = storedSession;
        this.currentUser = {
            dna: storedSession.dna,
            walletName: storedSession.walletName,
            walletAddress: storedSession.walletAddress,
            network: storedSession.network,
            balances: storedSession.balances,
            authenticatedAt: storedSession.authenticatedAt
        };

        this.core?.log('Session restored from storage', { dna: this.currentUser.dna });
    }

    /**
     * Restore authentication from cross-domain data
     * @param {Object} crossDomainData - Cross-domain session data
     */
    async restoreFromCrossDomainData(crossDomainData) {
        if (!crossDomainData.authenticated) return;

        this.isAuthenticated = true;
        this.sessionToken = crossDomainData.sessionToken;
        this.sessionData = crossDomainData.sessionData;
        this.currentUser = crossDomainData.user;

        // Store the restored session
        await this.storeSession();

        this.core?.log('Session restored from cross-domain', { 
            dna: this.currentUser.dna,
            source: 'cross-domain'
        });
    }

    /**
     * Clear stored session
     */
    clearStoredSession() {
        if (this.storage) {
            this.storage.removeLocal('sso_session');
            this.storage.removeSession('sso_current_session');
        }
    }

    /**
     * Validation and Utility Methods
     */

    /**
     * Check if origin is valid for cross-domain communication
     * @param {string} origin - Origin to validate
     * @returns {boolean} Is valid origin
     */
    isValidOrigin(origin) {
        const validOrigins = [
            ...Object.values(this.config.domains).flat()
        ];
        
        return validOrigins.includes(origin);
    }

    /**
     * Check if stored session is valid
     * @param {Object} session - Session to validate
     * @returns {boolean} Is valid session
     */
    isValidSession(session) {
        if (!session || !session.sessionToken) return false;
        
        // Check expiration
        const maxAge = this.config.sessionTimeout;
        const age = Date.now() - (session.storedAt || session.authenticatedAt || 0);
        
        return age < maxAge;
    }

    /**
     * Generate session token
     * @returns {string} Session token
     */
    generateSessionToken() {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substr(2, 15);
        const origin = window.location.origin.replace(/[^a-zA-Z0-9]/g, '');
        return `sso_${timestamp}_${random}_${origin}`;
    }

    /**
     * Generate request ID
     * @returns {string} Request ID
     */
    generateRequestId() {
        return `req_${++this.requestId}_${Date.now()}`;
    }

    /**
     * Event System
     */

    /**
     * Add event listener
     * @param {string} event - Event name
     * @param {Function} handler - Event handler
     */
    on(event, handler) {
        if (this.eventHandlers[event]) {
            this.eventHandlers[event].push(handler);
        }
    }

    /**
     * Remove event listener
     * @param {string} event - Event name
     * @param {Function} handler - Event handler
     */
    off(event, handler) {
        if (this.eventHandlers[event]) {
            const index = this.eventHandlers[event].indexOf(handler);
            if (index > -1) {
                this.eventHandlers[event].splice(index, 1);
            }
        }
    }

    /**
     * Emit event
     * @param {string} event - Event name
     * @param {Object} data - Event data
     */
    emit(event, data) {
        if (this.eventHandlers[event]) {
            this.eventHandlers[event].forEach(handler => {
                try {
                    handler(data);
                } catch (error) {
                    this.core?.error('SSO event handler error:', error);
                }
            });
        }

        // Also emit through core event system
        this.core?.emit(`sso:${event}`, data);
    }

    /**
     * Public API
     */

    /**
     * Get SSO status
     * @returns {Object} SSO status
     */
    getStatus() {
        return {
            initialized: this.initialized,
            authenticated: this.isAuthenticated,
            user: this.currentUser,
            sessionToken: this.sessionToken ? this.sessionToken.substring(0, 20) + '...' : null,
            lastSync: this.lastSync,
            bridgeCount: this.bridgeFrames.size,
            activeRequests: this.pendingRequests.size
        };
    }

    /**
     * Force session sync
     */
    async forceSync() {
        if (this.isAuthenticated) {
            await this.syncSessionAcrossDomains();
        }
    }

    /**
     * Clean up resources
     */
    destroy() {
        // Clear sync timer
        if (this.syncTimer) {
            clearInterval(this.syncTimer);
            this.syncTimer = null;
        }

        // Clear pending requests
        for (const request of this.pendingRequests.values()) {
            clearTimeout(request.timeout);
            request.reject(new Error('SSO client destroyed'));
        }
        this.pendingRequests.clear();

        // Remove bridge iframes
        for (const iframe of this.bridgeFrames.values()) {
            if (iframe.parentNode) {
                iframe.parentNode.removeChild(iframe);
            }
        }
        this.bridgeFrames.clear();

        // Clear state
        this.isAuthenticated = false;
        this.currentUser = null;
        this.sessionToken = null;
        this.sessionData = null;
        this.eventHandlers = {};

        this.initialized = false;
        this.core?.log('SSO Client destroyed');
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('sso', new CpunkSSOClient(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkSSOClient;
}