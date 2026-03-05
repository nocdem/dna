/**
 * CPUNK Wallet Connector Library v1.0
 * Handles Cellframe node communication and wallet management
 * 
 * Dependencies: None
 * Compatible with: Cellframe Node API
 */

class CPUNKWalletConnector {
    constructor(config = {}) {
        // Configuration
        this.nodeUrl = config.nodeUrl || 'http://localhost:8045';
        this.network = config.network || 'Backbone';
        this.debug = config.debug || false;
        this.console = config.console || null; // Debug console instance
        
        // State
        this.sessionId = null;
        this.selectedWallet = null;
        this.wallets = [];
        this.balances = {};
        this.connectionStatus = 'disconnected';
        
        // Treasury address for DNA registration payments
        this.treasuryAddress = 'Rj7J7MiX2bWy8sNyZcoLqkZuNznvU4KbK6RHgqrGj9iqwKPhoVKE1xNrEMmgtVsnyTZtFhftMPAJbaswuSLp7UeBS7jiRmE5uvuUJaKA';
        
        // Event handlers
        this.eventHandlers = {};
        
        // Timeouts
        this.timeouts = {
            connection: 10000,
            walletList: 15000,
            balance: 15000,
            transaction: 30000
        };
    }

    // Event System
    on(event, callback) {
        if (!this.eventHandlers[event]) {
            this.eventHandlers[event] = [];
        }
        this.eventHandlers[event].push(callback);
    }

    emit(event, data = null) {
        if (this.eventHandlers[event]) {
            this.eventHandlers[event].forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    this.log('Event handler error', { event, error: error.message }, 'error');
                }
            });
        }
    }

    // Logging
    log(message, data = null, level = 'info') {
        if (this.console) {
            this.console.log(`[WalletConnector] ${message}`, data, level);
        } else if (this.debug) {
            console.log(`[WalletConnector] ${message}`, data);
        }
    }

    // Connection Management
    async connect() {
        this.log('Attempting to connect to Cellframe node', { nodeUrl: this.nodeUrl });
        
        try {
            // First, make initial connection to get session ID (same as old system)
            const connectUrl = `${this.nodeUrl}/?method=Connect`;
            
            const response = await this.makeRequest(connectUrl, this.timeouts.connection);
            
            if (response && response.data && response.data.id && response.status === 'ok') {
                // Store session ID from response  
                this.sessionId = response.data.id;
                this.connectionStatus = 'connected';
                this.log('Connected to Cellframe node successfully', { sessionId: this.sessionId });
                
                // Load wallets
                await this.loadWallets();
                
                this.emit('connected', { sessionId: this.sessionId, wallets: this.wallets });
                return true;
            } else {
                throw new Error('Invalid response from node');
            }
            
        } catch (error) {
            this.connectionStatus = 'error';
            this.log('Connection failed', { error: error.message }, 'error');
            this.emit('error', { type: 'connection', message: error.message });
            throw new Error(`Failed to connect to Cellframe node: ${error.message}`);
        }
    }

    async disconnect() {
        this.sessionId = null;
        this.selectedWallet = null;
        this.wallets = [];
        this.balances = {};
        this.connectionStatus = 'disconnected';
        
        this.log('Disconnected from node');
        this.emit('disconnected');
    }

    // Wallet Operations
    async loadWallets() {
        this.log('Loading wallet list');
        
        const url = `${this.nodeUrl}/?method=GetWallets&id=${this.sessionId}`;
        
        try {
            const response = await this.makeRequest(url, this.timeouts.walletList);
            
            if (response && response.data && Array.isArray(response.data)) {
                // Filter active wallets (same as old system)
                const activeWallets = response.data.filter(wallet => wallet.status !== "non-Active");
                
                this.wallets = activeWallets.map(wallet => ({
                    name: wallet.name || wallet,
                    address: wallet.address || '',
                    type: wallet.type || 'unknown',
                    status: wallet.status,
                    displayName: this.formatWalletName(wallet.name || wallet)
                }));
                
                this.log('Wallets loaded', { count: this.wallets.length });
                this.emit('wallets-loaded', this.wallets);
                
                return this.wallets;
            } else {
                throw new Error('Invalid wallet list response');
            }
            
        } catch (error) {
            this.log('Failed to load wallets', { error: error.message }, 'error');
            this.emit('error', { type: 'wallets', message: error.message });
            throw error;
        }
    }

    async selectWallet(walletName) {
        this.log('Selecting wallet', { walletName });
        
        if (!this.wallets.length) {
            await this.loadWallets();
        }
        
        const wallet = this.wallets.find(w => w.name === walletName);
        if (!wallet) {
            throw new Error(`Wallet '${walletName}' not found`);
        }
        
        this.selectedWallet = wallet;
        
        // Load wallet details and balance
        try {
            await this.loadWalletDetails(walletName);
            await this.loadBalance(walletName);
            
            this.log('Wallet selected successfully', { 
                wallet: walletName, 
                address: this.selectedWallet.address 
            });
            
            this.emit('wallet-selected', this.selectedWallet);
            
            return this.selectedWallet;
            
        } catch (error) {
            this.log('Failed to select wallet', { walletName, error: error.message }, 'error');
            this.selectedWallet = null;
            throw error;
        }
    }

    async loadWalletDetails(walletName) {
        const url = `${this.nodeUrl}/?method=GetDataWallet&walletName=${walletName}&id=${this.sessionId}`;
        
        try {
            const response = await this.makeRequest(url, this.timeouts.balance);
            
            if (response && response.data && Array.isArray(response.data) && response.data.length > 0) {
                // Use first network data (typically Backbone)
                const networkData = response.data[0];
                this.selectedWallet.address = networkData.address;
                this.selectedWallet.network = networkData.network;
                this.selectedWallet.tokens = networkData.tokens || [];
                
                this.log('Wallet details loaded', { 
                    address: this.selectedWallet.address,
                    network: this.selectedWallet.network
                });
            }
            
        } catch (error) {
            this.log('Failed to load wallet details', { walletName, error: error.message }, 'warn');
            // Don't throw - this is not critical
        }
    }

    async loadBalance(walletName = null) {
        const wallet = walletName || this.selectedWallet?.name;
        if (!wallet) {
            throw new Error('No wallet selected');
        }
        
        this.log('Loading balance', { wallet });
        
        const url = `${this.nodeUrl}/?method=GetDataWallet&walletName=${wallet}&id=${this.sessionId}`;
        
        try {
            const response = await this.makeRequest(url, this.timeouts.balance);
            
            if (response && response.data && Array.isArray(response.data) && response.data.length > 0) {
                // Use first network data (typically Backbone) 
                const networkData = response.data[0];
                const tokens = networkData.tokens || [];
                
                // Extract CPUNK and CELL balances
                this.balances = {
                    CPUNK: this.extractBalance(tokens, 'CPUNK'),
                    CELL: this.extractBalance(tokens, 'CELL')
                };
                
                this.log('Balance loaded', this.balances);
                this.emit('balance-updated', this.balances);
                
                return this.balances;
            } else {
                throw new Error('Invalid balance response');
            }
            
        } catch (error) {
            this.log('Failed to load balance', { wallet, error: error.message }, 'error');
            this.emit('error', { type: 'balance', message: error.message });
            throw error;
        }
    }

    // Transaction Operations
    async sendTransaction(params) {
        const {
            toAddress = this.treasuryAddress,
            amount,
            token = 'CPUNK',
            walletName = this.selectedWallet?.name
        } = params;
        
        if (!walletName) {
            throw new Error('No wallet selected');
        }
        
        if (!amount || amount <= 0) {
            throw new Error('Invalid amount');
        }
        
        this.log('Sending transaction', { 
            walletName, 
            amount, 
            token, 
            toAddress: this.truncateAddress(toAddress) 
        });
        
        // Format amount for Cellframe (convert to wei/datoshi - multiply by 10^18)
        const formattedAmount = (BigInt(Math.floor(amount * 1000000)) * BigInt('1000000000000')).toString();
        
        const url = `${this.nodeUrl}/?method=SendTransaction&id=${this.sessionId}&net=${this.network}&walletName=${walletName}&toAddr=${toAddress}&tokenName=${token}&value=${formattedAmount}`;
        
        try {
            if (this.console) {
                this.console.startTimer('transaction');
            }
            
            const response = await this.makeRequest(url, this.timeouts.transaction);
            
            const duration = this.console ? this.console.endTimer('transaction') : null;
            
            if (response && response.status === 'ok' && response.data && (response.data.txHash || response.data.tx_hash)) {
                const txHash = response.data.txHash || response.data.tx_hash;
                
                this.log('Transaction sent successfully', { 
                    txHash, 
                    amount: formattedAmount,
                    duration: duration ? `${duration}ms` : 'unknown'
                });
                
                if (this.console) {
                    this.console.trackTransaction(txHash, amount, 'sent');
                }
                
                this.emit('transaction-sent', { 
                    txHash, 
                    amount, 
                    token, 
                    toAddress,
                    duration 
                });
                
                return {
                    success: true,
                    txHash,
                    amount: formattedAmount,
                    duration
                };
                
            } else {
                // Provide more detailed error information
                let errorMessage = 'Transaction failed';
                
                if (response) {
                    if (response.errorMsg) {
                        errorMessage = response.errorMsg;
                    } else if (response.status === 'error') {
                        errorMessage = 'Transaction rejected or failed';
                    } else if (response.status !== 'ok') {
                        errorMessage = `Transaction failed with status: ${response.status}`;
                    }
                } else {
                    errorMessage = 'No response received from wallet - transaction may have been cancelled or wallet connection lost';
                }
                
                this.log('Transaction failed with details', { 
                    response, 
                    errorMessage,
                    url: url.replace(/id=[^&]+/, 'id=[REDACTED]') 
                }, 'error');
                
                throw new Error(errorMessage);
            }
            
        } catch (error) {
            this.log('Transaction failed', { error: error.message }, 'error');
            this.emit('error', { type: 'transaction', message: error.message });
            throw error;
        }
    }

    // Utility Methods
    async makeRequest(url, timeout = 30000) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        try {
            if (this.console) {
                this.console.startTimer('api-request');
            }
            
            const response = await fetch(url, {
                method: 'GET',
                signal: controller.signal,
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            const duration = this.console ? this.console.endTimer('api-request') : null;
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (this.console) {
                this.console.trackAPICall('GET', url, duration, data);
            }
            
            return data;
            
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error(`Request timeout after ${timeout}ms`);
            }
            throw error;
        } finally {
            clearTimeout(timeoutId);
        }
    }

    extractBalance(tokens, tokenName) {
        // Find token by tokenName property (matching old system)
        const token = tokens.find(t => t.tokenName === tokenName);
        // Extract balance from balance property
        return token ? parseFloat(token.balance || '0') : 0;
    }

    formatWalletName(name) {
        // Make wallet names more user-friendly
        if (name === 'airdropper') return 'Airdropper Wallet';
        if (name === 'DEX') return 'DEX Wallet';
        return name.charAt(0).toUpperCase() + name.slice(1) + ' Wallet';
    }

    truncateAddress(address, start = 6, end = 4) {
        if (!address || address.length <= start + end) return address;
        return `${address.slice(0, start)}...${address.slice(-end)}`;
    }

    // Session ID is now obtained from Connect method response

    // Getters
    isConnected() {
        return this.connectionStatus === 'connected' && this.sessionId !== null;
    }

    getWallets() {
        return this.wallets;
    }

    getSelectedWallet() {
        return this.selectedWallet;
    }
    
    getSessionId() {
        return this.sessionId;
    }

    getBalance(token = 'CPUNK') {
        return this.balances[token] || 0;
    }

    getBalances() {
        return this.balances;
    }

    getConnectionStatus() {
        return this.connectionStatus;
    }

    // Validation
    hasMinimumBalance(amount, token = 'CPUNK') {
        const balance = this.getBalance(token);
        return balance >= amount;
    }

    validateAmount(amount) {
        return typeof amount === 'number' && amount > 0 && isFinite(amount);
    }

    // Static Methods
    static formatAmount(amount, decimals = 18) {
        return `${amount}e+${decimals}`;
    }

    static parseAmount(formattedAmount) {
        // Parse "5.0e+18" back to 5.0
        if (typeof formattedAmount === 'string' && formattedAmount.includes('e+')) {
            const [base] = formattedAmount.split('e+');
            return parseFloat(base);
        }
        return parseFloat(formattedAmount) || 0;
    }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CPUNKWalletConnector;
}