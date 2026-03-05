/**
 * CPUNK.IO Wallet Connector Library
 * Cellframe wallet integration and management
 * 
 * Features:
 * - Dashboard connection management
 * - Wallet discovery and selection
 * - Balance monitoring
 * - Transaction capabilities
 * - Session persistence
 * - Multi-wallet support
 * - Real-time updates
 * 
 * @version 1.0.0
 */

class CpunkWalletConnector {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        
        // Connection state
        this.isConnected = false;
        this.sessionId = null;
        this.selectedWallet = null;
        this.availableWallets = [];
        this.walletDetails = new Map();
        
        // Configuration
        this.config = {
            network: 'Backbone',
            reconnectInterval: 30000, // 30 seconds
            balanceUpdateInterval: 60000, // 1 minute
            maxReconnectAttempts: 5,
            sessionTimeout: 24 * 60 * 60 * 1000 // 24 hours
        };
        
        // Internal state
        this.reconnectAttempts = 0;
        this.reconnectTimer = null;
        this.balanceUpdateTimer = null;
        this.connectionPromise = null;
        
        // Event handlers
        this.eventHandlers = {
            connected: [],
            disconnected: [],
            walletSelected: [],
            walletUpdated: [],
            balanceUpdated: [],
            error: []
        };
    }

    /**
     * Initialize wallet connector
     * @param {Object} options - Configuration options
     */
    async init(options = {}) {
        if (this.initialized) return;

        // Merge configuration
        this.config = { ...this.config, ...options };

        // Get required modules
        this.api = this.core?.getModule('api');
        this.storage = this.core?.getModule('storage');
        this.validation = this.core?.getModule('validation');

        if (!this.api) {
            throw new Error('API client module required but not found');
        }

        // Attempt to restore previous session
        await this.restoreSession();

        // Setup automatic reconnection
        this.setupReconnection();

        // Setup balance monitoring
        this.setupBalanceMonitoring();

        this.initialized = true;
        this.core?.log('Wallet Connector initialized', this.config);
    }

    /**
     * Connection Management
     */

    /**
     * Connect to dashboard
     * @param {Object} options - Connection options
     * @returns {Promise<Object>} Connection result
     */
    async connect(options = {}) {
        if (this.connectionPromise) {
            return this.connectionPromise;
        }

        this.connectionPromise = this._performConnection(options);
        
        try {
            const result = await this.connectionPromise;
            return result;
        } finally {
            this.connectionPromise = null;
        }
    }

    /**
     * Perform actual connection
     * @param {Object} options - Connection options
     * @returns {Promise<Object>} Connection result
     */
    async _performConnection(options = {}) {
        try {
            this.core?.log('Connecting to dashboard...');
            
            // Connect to dashboard API
            const response = await this.api.connectToDashboard();
            
            if (!response || !response.sessionId) {
                throw new Error('Failed to get session ID from dashboard');
            }

            this.sessionId = response.sessionId;
            this.isConnected = true;
            this.reconnectAttempts = 0;

            // Store session
            if (this.storage) {
                this.storage.setSession('dashboard_session', this.sessionId, {
                    expires: Date.now() + this.config.sessionTimeout
                });
            }

            // Load available wallets
            await this.loadWallets();

            // Emit connection event
            this.emit('connected', {
                sessionId: this.sessionId,
                walletCount: this.availableWallets.length
            });

            this.core?.log('Dashboard connected successfully', {
                sessionId: this.sessionId,
                wallets: this.availableWallets.length
            });

            return {
                success: true,
                sessionId: this.sessionId,
                walletCount: this.availableWallets.length
            };

        } catch (error) {
            this.isConnected = false;
            this.sessionId = null;
            
            this.core?.error('Dashboard connection failed:', error);
            this.emit('error', { type: 'connection', error: error.message });
            
            throw error;
        }
    }

    /**
     * Disconnect from dashboard
     */
    disconnect() {
        this.isConnected = false;
        this.sessionId = null;
        this.selectedWallet = null;
        this.availableWallets = [];
        this.walletDetails.clear();

        // Clear timers
        if (this.reconnectTimer) {
            clearInterval(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        
        if (this.balanceUpdateTimer) {
            clearInterval(this.balanceUpdateTimer);
            this.balanceUpdateTimer = null;
        }

        // Clear stored session
        if (this.storage) {
            this.storage.removeSession('dashboard_session');
            this.storage.removeSession('selected_wallet');
        }

        this.emit('disconnected', {});
        this.core?.log('Dashboard disconnected');
    }

    /**
     * Restore session from storage
     */
    async restoreSession() {
        if (!this.storage) return false;

        try {
            const storedSessionId = this.storage.getSession('dashboard_session');
            const storedWallet = this.storage.getSession('selected_wallet');

            if (storedSessionId) {
                this.sessionId = storedSessionId;
                
                // Try to validate session by loading wallets
                try {
                    await this.loadWallets();
                    this.isConnected = true;
                    
                    // Restore selected wallet if available
                    if (storedWallet) {
                        const wallet = this.availableWallets.find(w => w.name === storedWallet.name);
                        if (wallet) {
                            await this.selectWallet(wallet);
                        }
                    }

                    this.core?.log('Session restored successfully');
                    this.emit('connected', { sessionId: this.sessionId, restored: true });
                    return true;

                } catch (error) {
                    // Session invalid, clear it
                    this.core?.warn('Stored session invalid, clearing');
                    this.storage.removeSession('dashboard_session');
                    this.storage.removeSession('selected_wallet');
                    this.sessionId = null;
                    this.isConnected = false;
                }
            }

        } catch (error) {
            this.core?.error('Failed to restore session:', error);
        }

        return false;
    }

    /**
     * Wallet Management
     */

    /**
     * Load available wallets
     * @returns {Promise<Array>} Available wallets
     */
    async loadWallets() {
        if (!this.sessionId) {
            throw new Error('No active session');
        }

        try {
            const response = await this.api.getWallets(this.sessionId);
            
            if (!response || !response.wallets) {
                throw new Error('Failed to get wallets from dashboard');
            }

            this.availableWallets = response.wallets.map(wallet => ({
                ...wallet,
                network: this.config.network,
                cpunkBalance: parseFloat(wallet.cpunkBalance || 0),
                cellBalance: parseFloat(wallet.cellBalance || 0),
                lastUpdated: Date.now()
            }));

            this.core?.log(`Loaded ${this.availableWallets.length} wallets`);
            return this.availableWallets;

        } catch (error) {
            this.core?.error('Failed to load wallets:', error);
            throw error;
        }
    }

    /**
     * Select a wallet
     * @param {Object} wallet - Wallet to select
     * @returns {Promise<Object>} Selected wallet details
     */
    async selectWallet(wallet) {
        if (!wallet || !wallet.name) {
            throw new Error('Invalid wallet provided');
        }

        try {
            // Get detailed wallet information
            const details = await this.getWalletDetails(wallet.name);
            
            this.selectedWallet = {
                ...wallet,
                ...details,
                selectedAt: Date.now()
            };

            // Store selected wallet
            if (this.storage) {
                this.storage.setSession('selected_wallet', {
                    name: this.selectedWallet.name,
                    address: this.selectedWallet.address,
                    network: this.selectedWallet.network
                });
            }

            this.emit('walletSelected', { wallet: this.selectedWallet });
            this.core?.log('Wallet selected:', this.selectedWallet.name);

            return this.selectedWallet;

        } catch (error) {
            this.core?.error('Failed to select wallet:', error);
            throw error;
        }
    }

    /**
     * Get detailed wallet information
     * @param {string} walletName - Wallet name
     * @returns {Promise<Object>} Wallet details
     */
    async getWalletDetails(walletName) {
        if (!this.sessionId) {
            throw new Error('No active session');
        }

        // Check cache first
        if (this.walletDetails.has(walletName)) {
            const cached = this.walletDetails.get(walletName);
            if (Date.now() - cached.timestamp < 30000) { // 30 seconds cache
                return cached.data;
            }
        }

        try {
            const details = await this.api.getWalletDetails(this.sessionId, walletName);
            
            const walletData = {
                ...details,
                lastUpdated: Date.now()
            };

            // Cache the details
            this.walletDetails.set(walletName, {
                data: walletData,
                timestamp: Date.now()
            });

            return walletData;

        } catch (error) {
            this.core?.error(`Failed to get wallet details for ${walletName}:`, error);
            throw error;
        }
    }

    /**
     * Update wallet balances
     * @param {string} walletName - Wallet name (optional, updates selected wallet)
     * @returns {Promise<Object>} Updated balance information
     */
    async updateWalletBalance(walletName) {
        const targetWallet = walletName || (this.selectedWallet ? this.selectedWallet.name : null);
        
        if (!targetWallet) {
            throw new Error('No wallet specified or selected');
        }

        try {
            const details = await this.getWalletDetails(targetWallet);
            
            // Update selected wallet if it matches
            if (this.selectedWallet && this.selectedWallet.name === targetWallet) {
                const previousBalance = {
                    cpunk: this.selectedWallet.cpunkBalance,
                    cell: this.selectedWallet.cellBalance
                };

                this.selectedWallet = {
                    ...this.selectedWallet,
                    ...details,
                    lastUpdated: Date.now()
                };

                // Emit balance update event
                this.emit('balanceUpdated', {
                    wallet: this.selectedWallet,
                    previousBalance,
                    currentBalance: {
                        cpunk: this.selectedWallet.cpunkBalance,
                        cell: this.selectedWallet.cellBalance
                    }
                });
            }

            // Update in available wallets list
            const walletIndex = this.availableWallets.findIndex(w => w.name === targetWallet);
            if (walletIndex >= 0) {
                this.availableWallets[walletIndex] = {
                    ...this.availableWallets[walletIndex],
                    ...details,
                    lastUpdated: Date.now()
                };
            }

            return details;

        } catch (error) {
            this.core?.error(`Failed to update balance for ${targetWallet}:`, error);
            throw error;
        }
    }

    /**
     * Transaction Methods
     */

    /**
     * Check if wallet has sufficient balance
     * @param {number} amount - Amount to check
     * @param {string} token - Token type (CPUNK or CELL)
     * @returns {boolean} Has sufficient balance
     */
    hasSufficientBalance(amount, token = 'CPUNK') {
        if (!this.selectedWallet) return false;

        const balance = token.toUpperCase() === 'CPUNK' 
            ? this.selectedWallet.cpunkBalance 
            : this.selectedWallet.cellBalance;

        return parseFloat(balance) >= parseFloat(amount);
    }

    /**
     * Estimate transaction fee
     * @param {Object} transactionParams - Transaction parameters
     * @returns {Promise<Object>} Fee estimation
     */
    async estimateTransactionFee(transactionParams) {
        // For now, return static fee estimates
        // In the future, this could query the network for dynamic fees
        
        const baseFee = 0.01; // Base fee in CELL
        
        return {
            baseFee,
            totalFee: baseFee,
            currency: 'CELL',
            estimated: true
        };
    }

    /**
     * Validate transaction parameters
     * @param {Object} params - Transaction parameters
     * @returns {Object} Validation result
     */
    validateTransactionParams(params) {
        const { toAddress, amount, tokenName } = params;
        const errors = [];

        if (!this.selectedWallet) {
            errors.push('No wallet selected');
        }

        if (!toAddress) {
            errors.push('Recipient address required');
        } else if (this.validation) {
            const addressValidation = this.validation.validateWalletAddress(toAddress);
            if (!addressValidation.valid) {
                errors.push(...addressValidation.errors);
            }
        }

        if (!amount || parseFloat(amount) <= 0) {
            errors.push('Valid amount required');
        }

        if (!tokenName) {
            errors.push('Token name required');
        }

        // Check balance
        if (this.selectedWallet && amount && tokenName) {
            if (!this.hasSufficientBalance(amount, tokenName)) {
                errors.push(`Insufficient ${tokenName} balance`);
            }
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    /**
     * Utility Methods
     */

    /**
     * Setup automatic reconnection
     */
    setupReconnection() {
        this.reconnectTimer = setInterval(async () => {
            if (!this.isConnected && this.reconnectAttempts < this.config.maxReconnectAttempts) {
                this.core?.log(`Attempting reconnection (${this.reconnectAttempts + 1}/${this.config.maxReconnectAttempts})`);
                
                try {
                    await this.connect();
                } catch (error) {
                    this.reconnectAttempts++;
                    if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
                        this.core?.error('Max reconnection attempts reached');
                        this.emit('error', { 
                            type: 'reconnection_failed', 
                            attempts: this.reconnectAttempts 
                        });
                    }
                }
            }
        }, this.config.reconnectInterval);
    }

    /**
     * Setup balance monitoring
     */
    setupBalanceMonitoring() {
        this.balanceUpdateTimer = setInterval(async () => {
            if (this.isConnected && this.selectedWallet) {
                try {
                    await this.updateWalletBalance();
                } catch (error) {
                    this.core?.warn('Failed to update balance:', error.message);
                }
            }
        }, this.config.balanceUpdateInterval);
    }

    /**
     * Event system
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
                    this.core?.error('Event handler error:', error);
                }
            });
        }

        // Also emit through core event system
        this.core?.emit(`wallet:${event}`, data);
    }

    /**
     * Get connection status
     * @returns {Object} Connection status
     */
    getStatus() {
        return {
            connected: this.isConnected,
            sessionId: this.sessionId,
            selectedWallet: this.selectedWallet ? {
                name: this.selectedWallet.name,
                address: this.selectedWallet.address,
                network: this.selectedWallet.network
            } : null,
            walletCount: this.availableWallets.length,
            reconnectAttempts: this.reconnectAttempts,
            lastUpdated: this.selectedWallet ? this.selectedWallet.lastUpdated : null
        };
    }

    /**
     * Get wallet list
     * @returns {Array} Available wallets
     */
    getWallets() {
        return this.availableWallets.map(wallet => ({
            name: wallet.name,
            address: wallet.address,
            network: wallet.network,
            cpunkBalance: wallet.cpunkBalance,
            cellBalance: wallet.cellBalance,
            lastUpdated: wallet.lastUpdated
        }));
    }

    /**
     * Get selected wallet
     * @returns {Object|null} Selected wallet
     */
    getSelectedWallet() {
        return this.selectedWallet;
    }

    /**
     * Format balance for display
     * @param {number} balance - Balance amount
     * @param {string} token - Token name
     * @returns {string} Formatted balance
     */
    formatBalance(balance, token = '') {
        if (this.validation) {
            return this.validation.formatBalance(balance, 3, token);
        }
        
        const num = parseFloat(balance);
        if (num === 0) return `0${token ? ' ' + token : ''}`;
        if (num < 0.001) return `< 0.001${token ? ' ' + token : ''}`;
        return `${num.toLocaleString(undefined, { maximumFractionDigits: 3 })}${token ? ' ' + token : ''}`;
    }

    /**
     * Clean up resources
     */
    destroy() {
        this.disconnect();
        this.eventHandlers = {};
        this.walletDetails.clear();
        this.initialized = false;
        this.core?.log('Wallet Connector destroyed');
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('wallet', new CpunkWalletConnector(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkWalletConnector;
}