/**
 * CPUNK.IO API Client Library
 * Comprehensive API communication layer with RPC integration
 * 
 * Features:
 * - Dashboard API communication
 * - DNA backend API communication
 * - Cellframe RPC integration
 * - Automatic retry with exponential backoff
 * - Request/response caching
 * - Error handling and logging
 * - Request queuing
 * - Mock/test mode support
 * 
 * @version 1.0.0
 */

class CpunkAPIClient {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        
        // API endpoints
        this.endpoints = {
            dashboard: core?.config?.api?.dashboard || 'http://localhost:8045/',
            dnaProxy: core?.config?.api?.dnaProxy || '/dna-proxy.php',
            rpc: core?.config?.api?.rpcEndpoint || 'http://rpc.cellframe.net/connect'
        };

        // Request options
        this.options = {
            timeout: 30000,
            retries: 3,
            retryDelay: 1000,
            enableCaching: true,
            cacheTimeout: 5 * 60 * 1000, // 5 minutes
            enableLogging: true,
            enableMocking: false
        };

        // Internal state
        this.requestCache = new Map();
        this.requestQueue = [];
        this.activeRequests = new Set();
        this.mockResponses = new Map();
        this.rateLimits = new Map();
        this.requestId = 0;
    }

    /**
     * Initialize API client
     * @param {Object} options - Configuration options
     */
    async init(options = {}) {
        if (this.initialized) return;

        // Merge options
        this.options = { ...this.options, ...options };
        
        if (options.endpoints) {
            this.endpoints = { ...this.endpoints, ...options.endpoints };
        }

        // Setup request interceptors
        this.setupInterceptors();
        
        // Setup periodic cleanup
        this.setupCleanup();

        this.initialized = true;
        this.core?.log('API Client initialized', { endpoints: this.endpoints, options: this.options });
    }

    /**
     * Dashboard API Methods
     */

    /**
     * Connect to dashboard
     * @returns {Promise<Object>} Connection result
     */
    async connectToDashboard() {
        return this.dashboardRequest('connect_to_dashboard');
    }

    /**
     * Get wallets from dashboard
     * @param {string} sessionId - Session ID
     * @returns {Promise<Object>} Wallets data
     */
    async getWallets(sessionId) {
        return this.dashboardRequest('get_wallets', { sessionId });
    }

    /**
     * Get wallet details
     * @param {string} sessionId - Session ID
     * @param {string} walletName - Wallet name
     * @returns {Promise<Object>} Wallet details
     */
    async getWalletDetails(sessionId, walletName) {
        return this.dashboardRequest('get_wallet_details', { sessionId, walletName });
    }

    /**
     * Send transaction
     * @param {Object} params - Transaction parameters
     * @returns {Promise<Object>} Transaction result
     */
    async sendTransaction(params) {
        const {
            sessionId,
            walletName,
            network,
            toAddress,
            tokenName,
            value
        } = params;

        return this.dashboardRequest('send_transaction', {
            sessionId,
            walletName,
            network,
            toAddress,
            tokenName,
            value
        });
    }

    /**
     * Get transaction history
     * @param {string} sessionId - Session ID
     * @param {string} walletName - Wallet name
     * @returns {Promise<Object>} Transaction history
     */
    async getTransactionHistory(sessionId, walletName) {
        return this.dashboardRequest('get_transaction_history', { sessionId, walletName });
    }

    /**
     * Generic dashboard request
     * @param {string} method - API method
     * @param {Object} params - Request parameters
     * @returns {Promise<Object>} API response
     */
    async dashboardRequest(method, params = {}) {
        const url = new URL(this.endpoints.dashboard);
        url.searchParams.append('method', method);

        // Add parameters to URL
        Object.entries(params).forEach(([key, value]) => {
            url.searchParams.append(key, value);
        });

        const requestOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        };

        return this.makeRequest(url.toString(), requestOptions, {
            type: 'dashboard',
            method,
            cacheable: ['get_wallets', 'get_wallet_details'].includes(method)
        });
    }

    /**
     * DNA Backend API Methods
     */

    /**
     * Check DNA nickname availability
     * @param {string} nickname - DNA nickname to check
     * @returns {Promise<Object>} Availability result
     */
    async checkDNAAvailability(nickname) {
        const url = `${this.endpoints.dnaProxy}?lookup=${encodeURIComponent(nickname)}`;
        
        return this.makeRequest(url, { method: 'GET' }, {
            type: 'dna',
            method: 'lookup',
            cacheable: true,
            cacheTimeout: 2 * 60 * 1000 // 2 minutes for availability checks
        });
    }

    /**
     * Register DNA nickname
     * @param {Object} data - Registration data
     * @returns {Promise<Object>} Registration result
     */
    async registerDNA(data) {
        const { nickname, walletAddress, txHash } = data;
        
        const formData = new FormData();
        formData.append('action', 'add');
        formData.append('name', nickname);
        formData.append('wallet', walletAddress);
        formData.append('tx_hash', txHash);

        return this.makeRequest(this.endpoints.dnaProxy, {
            method: 'POST',
            body: formData
        }, {
            type: 'dna',
            method: 'register',
            cacheable: false
        });
    }

    /**
     * Validate transaction
     * @param {string} txHash - Transaction hash
     * @param {string} network - Network name
     * @returns {Promise<Object>} Validation result
     */
    async validateTransaction(txHash, network = 'Backbone') {
        const url = `${this.endpoints.dnaProxy}?tx_validate=${encodeURIComponent(txHash)}&network=${encodeURIComponent(network)}`;
        
        return this.makeRequest(url, { method: 'GET' }, {
            type: 'dna',
            method: 'validate_transaction',
            cacheable: true,
            cacheTimeout: 30 * 1000 // 30 seconds for transaction validation
        });
    }

    /**
     * Lookup DNA by name or address
     * @param {string} query - Name or address to lookup
     * @returns {Promise<Object>} Lookup result
     */
    async lookupDNA(query) {
        const url = `${this.endpoints.dnaProxy}?lookup=${encodeURIComponent(query)}`;
        
        return this.makeRequest(url, { method: 'GET' }, {
            type: 'dna',
            method: 'lookup',
            cacheable: true,
            cacheTimeout: 5 * 60 * 1000 // 5 minutes
        });
    }

    /**
     * RPC Methods
     */

    /**
     * Make RPC request to Cellframe
     * @param {Object} request - RPC request object
     * @returns {Promise<Object>} RPC response
     */
    async makeRPCRequest(request) {
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        };

        return this.makeRequest(this.endpoints.rpc, requestOptions, {
            type: 'rpc',
            method: request.method || 'unknown',
            cacheable: ['get_balance', 'get_transaction'].includes(request.method)
        });
    }

    /**
     * Get transaction history via RPC
     * @param {string} address - Wallet address
     * @param {number} limit - Number of transactions to fetch
     * @returns {Promise<Object>} Transaction history
     */
    async getRPCTransactionHistory(address, limit = 100) {
        return this.makeRPCRequest({
            jsonrpc: '2.0',
            method: 'tx_history',
            params: {
                addr: address,
                limit: limit
            },
            id: this.generateRequestId()
        });
    }

    /**
     * Validate transaction via RPC
     * @param {string} txHash - Transaction hash
     * @param {string} treasuryAddress - Treasury address to check
     * @param {number} expectedAmount - Expected amount
     * @returns {Promise<Object>} Validation result
     */
    async validateTransactionViaRPC(txHash, treasuryAddress, expectedAmount) {
        try {
            // Get transaction history for treasury address
            const historyResponse = await this.getRPCTransactionHistory(treasuryAddress);
            
            if (!historyResponse.result || !historyResponse.result.transactions) {
                return {
                    verified: false,
                    error: 'Unable to fetch transaction history'
                };
            }

            // Search for the transaction hash
            const transaction = historyResponse.result.transactions.find(tx => 
                tx.hash === txHash || tx.hash === `0x${txHash.replace('0x', '')}`
            );

            if (!transaction) {
                return {
                    verified: false,
                    error: 'Transaction not found'
                };
            }

            // Validate transaction details
            const validation = this.validateTransactionDetails(transaction, expectedAmount);
            
            return {
                verified: validation.valid,
                transaction: transaction,
                validation: validation,
                method: 'rpc'
            };

        } catch (error) {
            this.core?.error('RPC validation failed:', error);
            return {
                verified: false,
                error: error.message || 'RPC validation failed',
                method: 'rpc'
            };
        }
    }

    /**
     * Core Request Methods
     */

    /**
     * Make HTTP request with retry logic
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @param {Object} metadata - Request metadata
     * @returns {Promise<Object>} Response data
     */
    async makeRequest(url, options = {}, metadata = {}) {
        const requestId = this.generateRequestId();
        const cacheKey = this.generateCacheKey(url, options);
        
        // Check cache first
        if (metadata.cacheable && this.requestCache.has(cacheKey)) {
            const cached = this.requestCache.get(cacheKey);
            if (Date.now() - cached.timestamp < (metadata.cacheTimeout || this.options.cacheTimeout)) {
                this.log('Cache hit', { requestId, url, type: metadata.type });
                return cached.data;
            }
        }

        // Check rate limits
        if (this.isRateLimited(url)) {
            throw new Error('Rate limit exceeded for this endpoint');
        }

        // Add request to active set
        this.activeRequests.add(requestId);

        try {
            const response = await this.executeRequestWithRetry(url, options, metadata, requestId);
            
            // Cache successful responses
            if (metadata.cacheable && response) {
                this.requestCache.set(cacheKey, {
                    data: response,
                    timestamp: Date.now()
                });
            }

            return response;

        } finally {
            this.activeRequests.delete(requestId);
        }
    }

    /**
     * Execute request with retry logic
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @param {Object} metadata - Request metadata
     * @param {string} requestId - Request ID
     * @returns {Promise<Object>} Response data
     */
    async executeRequestWithRetry(url, options, metadata, requestId) {
        let lastError = null;
        const maxRetries = this.options.retries;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                this.log(`Request attempt ${attempt + 1}/${maxRetries + 1}`, { 
                    requestId, url, type: metadata.type 
                });

                const response = await this.executeRequest(url, options, metadata, requestId);
                
                if (attempt > 0) {
                    this.log('Request succeeded after retry', { requestId, attempt });
                }

                return response;

            } catch (error) {
                lastError = error;
                
                this.log(`Request attempt ${attempt + 1} failed`, { 
                    requestId, error: error.message 
                });

                // Don't retry on certain errors
                if (this.shouldNotRetry(error)) {
                    break;
                }

                // Don't retry on last attempt
                if (attempt === maxRetries) {
                    break;
                }

                // Wait before retry
                const delay = this.options.retryDelay * Math.pow(2, attempt);
                await this.core?.sleep(delay) || new Promise(resolve => setTimeout(resolve, delay));
            }
        }

        // All attempts failed
        this.updateRateLimit(url);
        throw lastError || new Error('Request failed after all retry attempts');
    }

    /**
     * Execute single HTTP request
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @param {Object} metadata - Request metadata
     * @param {string} requestId - Request ID
     * @returns {Promise<Object>} Response data
     */
    async executeRequest(url, options, metadata, requestId) {
        // Check for mock responses
        if (this.options.enableMocking && this.mockResponses.has(url)) {
            this.log('Mock response', { requestId, url });
            await this.core?.sleep(100); // Simulate network delay
            return this.mockResponses.get(url);
        }

        // Set up timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, this.options.timeout);

        const requestOptions = {
            ...options,
            signal: controller.signal,
            headers: {
                'User-Agent': 'CPUNK.IO/1.0.0',
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, requestOptions);
            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            // Try to parse as JSON, fallback to text
            let data;
            try {
                data = await response.json();
            } catch (parseError) {
                data = await response.text();
                
                // Try to convert text responses to structured format
                if (typeof data === 'string') {
                    data = this.parseTextResponse(data, metadata);
                }
            }

            this.log('Request completed', { requestId, url, status: response.status });
            
            // Emit success event
            this.core?.emit('api:request:success', {
                requestId,
                url,
                type: metadata.type,
                method: metadata.method,
                data
            });

            return data;

        } catch (error) {
            clearTimeout(timeoutId);
            
            // Emit error event
            this.core?.emit('api:request:error', {
                requestId,
                url,
                type: metadata.type,
                method: metadata.method,
                error: error.message
            });

            throw error;
        }
    }

    /**
     * Utility Methods
     */

    /**
     * Parse text response to structured format
     * @param {string} text - Response text
     * @param {Object} metadata - Request metadata
     * @returns {Object} Parsed response
     */
    parseTextResponse(text, metadata) {
        // Handle DNA lookup responses
        if (metadata.type === 'dna' && metadata.method === 'lookup') {
            if (text.includes('not found') || text.trim() === '') {
                return { error: 'not found', available: true };
            } else {
                try {
                    return JSON.parse(text);
                } catch (e) {
                    return { data: text, available: false };
                }
            }
        }

        // Handle validation responses
        if (metadata.method === 'validate_transaction') {
            if (text.includes('verified') || text.includes('success')) {
                return { verified: true, status: 'success' };
            } else {
                return { verified: false, status: 'pending', message: text };
            }
        }

        // Default: wrap in object
        return { data: text };
    }

    /**
     * Validate transaction details
     * @param {Object} transaction - Transaction object
     * @param {number} expectedAmount - Expected amount
     * @returns {Object} Validation result
     */
    validateTransactionDetails(transaction, expectedAmount) {
        const result = {
            valid: false,
            checks: {
                amountMatch: false,
                tokenType: false,
                status: false
            },
            details: {}
        };

        // Check transaction status
        if (transaction.status === 'ACCEPTED' || transaction.status === 'confirmed') {
            result.checks.status = true;
        }

        // Check amount (convert from wei if needed)
        const txAmount = parseFloat(transaction.value || transaction.amount || 0);
        const expectedAmountFloat = parseFloat(expectedAmount);
        
        if (Math.abs(txAmount - expectedAmountFloat) < 0.001) {
            result.checks.amountMatch = true;
        }

        // Check token type
        if (transaction.token === 'CPUNK' || transaction.tokenName === 'CPUNK') {
            result.checks.tokenType = true;
        }

        // Overall validation
        result.valid = Object.values(result.checks).every(check => check);
        result.details = {
            txAmount,
            expectedAmount: expectedAmountFloat,
            status: transaction.status,
            token: transaction.token || transaction.tokenName
        };

        return result;
    }

    /**
     * Generate unique request ID
     * @returns {string} Request ID
     */
    generateRequestId() {
        return `req_${++this.requestId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Generate cache key
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @returns {string} Cache key
     */
    generateCacheKey(url, options) {
        const method = options.method || 'GET';
        const body = options.body ? JSON.stringify(options.body) : '';
        return `${method}:${url}:${body}`;
    }

    /**
     * Check if endpoint is rate limited
     * @param {string} url - Request URL
     * @returns {boolean} Is rate limited
     */
    isRateLimited(url) {
        const limit = this.rateLimits.get(url);
        if (!limit) return false;
        
        return Date.now() - limit.timestamp < limit.cooldown;
    }

    /**
     * Update rate limit for URL
     * @param {string} url - Request URL
     */
    updateRateLimit(url) {
        this.rateLimits.set(url, {
            timestamp: Date.now(),
            cooldown: 60000 // 1 minute cooldown
        });
    }

    /**
     * Check if error should not trigger retry
     * @param {Error} error - Error object
     * @returns {boolean} Should not retry
     */
    shouldNotRetry(error) {
        const noRetryErrors = [
            'AbortError', // Request was aborted
            'TypeError' // Network error (no internet)
        ];
        
        if (noRetryErrors.includes(error.name)) {
            return true;
        }

        // Don't retry 4xx errors (client errors)
        if (error.message.includes('HTTP 4')) {
            return true;
        }

        return false;
    }

    /**
     * Setup request interceptors
     */
    setupInterceptors() {
        // Request interceptor
        this.core?.on('api:request:before', (data) => {
            this.log('Request starting', data);
        });

        // Response interceptor
        this.core?.on('api:request:after', (data) => {
            this.log('Request completed', data);
        });
    }

    /**
     * Setup periodic cleanup
     */
    setupCleanup() {
        setInterval(() => {
            this.cleanupCache();
            this.cleanupRateLimits();
        }, 5 * 60 * 1000); // Every 5 minutes
    }

    /**
     * Cleanup expired cache entries
     */
    cleanupCache() {
        const now = Date.now();
        let cleaned = 0;

        for (const [key, value] of this.requestCache.entries()) {
            if (now - value.timestamp > this.options.cacheTimeout) {
                this.requestCache.delete(key);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            this.log(`Cache cleanup: ${cleaned} entries removed`);
        }
    }

    /**
     * Cleanup expired rate limits
     */
    cleanupRateLimits() {
        const now = Date.now();
        let cleaned = 0;

        for (const [url, limit] of this.rateLimits.entries()) {
            if (now - limit.timestamp > limit.cooldown) {
                this.rateLimits.delete(url);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            this.log(`Rate limits cleanup: ${cleaned} entries removed`);
        }
    }

    /**
     * Mock/Testing Methods
     */

    /**
     * Add mock response for testing
     * @param {string} url - URL to mock
     * @param {Object} response - Mock response
     */
    addMockResponse(url, response) {
        this.mockResponses.set(url, response);
    }

    /**
     * Remove mock response
     * @param {string} url - URL to remove mock for
     */
    removeMockResponse(url) {
        this.mockResponses.delete(url);
    }

    /**
     * Clear all mock responses
     */
    clearMockResponses() {
        this.mockResponses.clear();
    }

    /**
     * Get API statistics
     * @returns {Object} Statistics
     */
    getStats() {
        return {
            cache: {
                size: this.requestCache.size,
                entries: Array.from(this.requestCache.keys())
            },
            rateLimits: {
                size: this.rateLimits.size,
                entries: Array.from(this.rateLimits.keys())
            },
            activeRequests: this.activeRequests.size,
            queueSize: this.requestQueue.length,
            totalRequests: this.requestId
        };
    }

    /**
     * Clear all caches and reset state
     */
    reset() {
        this.requestCache.clear();
        this.rateLimits.clear();
        this.requestQueue.length = 0;
        this.activeRequests.clear();
        this.requestId = 0;
        this.log('API client reset');
    }

    /**
     * Logging helper
     */
    log(message, data = {}) {
        if (this.options.enableLogging) {
            this.core?.log(`[API Client] ${message}`, data);
        }
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('api', new CpunkAPIClient(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkAPIClient;
}