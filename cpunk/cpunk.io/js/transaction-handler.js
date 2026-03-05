/**
 * CPUNK.IO Transaction Handler Library
 * Comprehensive transaction processing and verification
 * 
 * Features:
 * - Transaction submission and monitoring
 * - Advanced verification with RPC integration
 * - Exponential backoff retry logic
 * - Transaction history tracking
 * - Real-time status updates
 * - Error recovery mechanisms
 * - Fee estimation
 * 
 * @version 1.0.0
 */

class CpunkTransactionHandler {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        
        // Configuration
        this.config = {
            network: 'Backbone',
            treasuryAddress: 'Rj7J7MiX2bWy8sNyZcoLqkZuNznvU4KbK6RHgqrGj9iqwKPhoVKE1xNrEMmgtVsnyTZtFhftMPAJbaswuSLp7UeBS7jiRmE5uvuUJaKA',
            tokenDecimals: 18,
            verification: {
                maxAttempts: 10,
                intervals: [15, 45, 60, 60, 60, 60, 60, 60, 60, 60], // seconds
                useRPC: true,
                fallbackToAPI: true
            },
            fees: {
                baseFee: 0.01, // CELL
                priorityFee: 0.001 // CELL
            }
        };
        
        // Transaction state
        this.activeTransactions = new Map();
        this.transactionHistory = [];
        this.verificationTimers = new Map();
        
        // Event handlers
        this.eventHandlers = {
            submitted: [],
            verified: [],
            failed: [],
            progress: []
        };
    }

    /**
     * Initialize transaction handler
     * @param {Object} options - Configuration options
     */
    async init(options = {}) {
        if (this.initialized) return;

        // Merge configuration
        this.config = this.core?.deepMerge(this.config, options) || { ...this.config, ...options };

        // Get required modules
        this.api = this.core?.getModule('api');
        this.wallet = this.core?.getModule('wallet');
        this.storage = this.core?.getModule('storage');
        this.validation = this.core?.getModule('validation');

        if (!this.api) {
            throw new Error('API client module required but not found');
        }

        // Restore active transactions
        await this.restoreActiveTransactions();

        this.initialized = true;
        this.core?.log('Transaction Handler initialized', this.config);
    }

    /**
     * Transaction Submission
     */

    /**
     * Send transaction
     * @param {Object} params - Transaction parameters
     * @returns {Promise<Object>} Transaction result
     */
    async sendTransaction(params) {
        const {
            toAddress,
            tokenName,
            amount,
            walletName,
            sessionId,
            metadata = {}
        } = params;

        // Validate parameters
        const validation = this.validateTransactionParams(params);
        if (!validation.valid) {
            throw new Error(`Transaction validation failed: ${validation.errors.join(', ')}`);
        }

        // Generate transaction ID
        const txId = this.generateTransactionId();
        
        // Format amount for blockchain
        const formattedAmount = this.formatAmount(amount);

        try {
            this.core?.log(`Submitting transaction ${txId}`, { toAddress, tokenName, amount });

            // Submit transaction to dashboard API
            const result = await this.api.sendTransaction({
                sessionId,
                walletName,
                network: this.config.network,
                toAddress,
                tokenName,
                value: formattedAmount
            });

            if (!result.txHash) {
                throw new Error('Transaction failed: No hash returned');
            }

            // Create transaction record
            const transaction = {
                id: txId,
                hash: result.txHash,
                toAddress,
                tokenName,
                amount: parseFloat(amount),
                formattedAmount,
                walletName,
                sessionId,
                status: 'submitted',
                submittedAt: Date.now(),
                verificationAttempts: 0,
                metadata: {
                    ...metadata,
                    submissionResult: result
                }
            };

            // Store transaction
            this.activeTransactions.set(txId, transaction);
            this.addToHistory(transaction);

            // Start verification process
            this.startVerification(transaction);

            // Emit submission event
            this.emit('submitted', { transaction });

            this.core?.log(`Transaction ${txId} submitted successfully`, { hash: result.txHash });

            return {
                success: true,
                transactionId: txId,
                hash: result.txHash,
                transaction
            };

        } catch (error) {
            this.core?.error(`Transaction ${txId} submission failed:`, error);
            
            // Create failed transaction record
            const failedTransaction = {
                id: txId,
                toAddress,
                tokenName,
                amount: parseFloat(amount),
                walletName,
                status: 'failed',
                error: error.message,
                submittedAt: Date.now(),
                metadata
            };

            this.addToHistory(failedTransaction);
            this.emit('failed', { transaction: failedTransaction, error: error.message });

            throw error;
        }
    }

    /**
     * Transaction Verification
     */

    /**
     * Start verification process
     * @param {Object} transaction - Transaction to verify
     */
    startVerification(transaction) {
        const { id, hash } = transaction;
        
        if (this.verificationTimers.has(id)) {
            clearTimeout(this.verificationTimers.get(id));
        }

        // Schedule first verification attempt
        const firstDelay = this.config.verification.intervals[0] * 1000;
        const timer = setTimeout(() => {
            this.performVerification(transaction);
        }, firstDelay);

        this.verificationTimers.set(id, timer);
        
        this.core?.log(`Verification scheduled for transaction ${id} in ${firstDelay}ms`);
        
        // Update transaction status
        this.updateTransactionStatus(id, 'verifying', {
            nextVerificationAt: Date.now() + firstDelay
        });
    }

    /**
     * Perform verification attempt
     * @param {Object} transaction - Transaction to verify
     */
    async performVerification(transaction) {
        const { id, hash, amount, tokenName } = transaction;
        const attemptNumber = transaction.verificationAttempts + 1;
        const maxAttempts = this.config.verification.maxAttempts;

        this.core?.log(`Verification attempt ${attemptNumber}/${maxAttempts} for transaction ${id}`);

        try {
            transaction.verificationAttempts = attemptNumber;
            
            // Update progress
            this.emit('progress', {
                transactionId: id,
                attempt: attemptNumber,
                maxAttempts,
                status: 'verifying'
            });

            let verificationResult = null;

            // Try RPC verification first if enabled
            if (this.config.verification.useRPC) {
                try {
                    verificationResult = await this.verifyWithRPC(hash, amount);
                    if (verificationResult.verified) {
                        this.core?.log(`Transaction ${id} verified via RPC`);
                    }
                } catch (rpcError) {
                    this.core?.warn(`RPC verification failed for ${id}:`, rpcError.message);
                }
            }

            // Fallback to API verification if RPC failed or not enabled
            if (!verificationResult || (!verificationResult.verified && this.config.verification.fallbackToAPI)) {
                try {
                    verificationResult = await this.verifyWithAPI(hash);
                    if (verificationResult.verified) {
                        this.core?.log(`Transaction ${id} verified via API`);
                    }
                } catch (apiError) {
                    this.core?.warn(`API verification failed for ${id}:`, apiError.message);
                    verificationResult = { verified: false, error: apiError.message };
                }
            }

            // Process verification result
            if (verificationResult && verificationResult.verified) {
                this.completeTransaction(transaction, verificationResult);
            } else if (attemptNumber >= maxAttempts) {
                this.timeoutTransaction(transaction, verificationResult);
            } else {
                this.scheduleNextVerification(transaction);
            }

        } catch (error) {
            this.core?.error(`Verification attempt ${attemptNumber} failed for transaction ${id}:`, error);
            
            if (attemptNumber >= maxAttempts) {
                this.failTransaction(transaction, error);
            } else {
                this.scheduleNextVerification(transaction);
            }
        }
    }

    /**
     * Verify transaction using RPC
     * @param {string} hash - Transaction hash
     * @param {number} expectedAmount - Expected amount
     * @returns {Promise<Object>} Verification result
     */
    async verifyWithRPC(hash, expectedAmount) {
        return this.api.validateTransactionViaRPC(
            hash,
            this.config.treasuryAddress,
            expectedAmount
        );
    }

    /**
     * Verify transaction using API
     * @param {string} hash - Transaction hash
     * @returns {Promise<Object>} Verification result
     */
    async verifyWithAPI(hash) {
        const result = await this.api.validateTransaction(hash, this.config.network);
        
        return {
            verified: result.verified || result.status === 'success',
            method: 'api',
            result
        };
    }

    /**
     * Schedule next verification attempt
     * @param {Object} transaction - Transaction to verify
     */
    scheduleNextVerification(transaction) {
        const { id, verificationAttempts } = transaction;
        const intervalIndex = Math.min(verificationAttempts, this.config.verification.intervals.length - 1);
        const delay = this.config.verification.intervals[intervalIndex] * 1000;

        const timer = setTimeout(() => {
            this.performVerification(transaction);
        }, delay);

        this.verificationTimers.set(id, timer);
        
        this.updateTransactionStatus(id, 'verifying', {
            nextVerificationAt: Date.now() + delay,
            lastAttempt: Date.now()
        });

        this.core?.log(`Next verification for transaction ${id} scheduled in ${delay}ms`);
    }

    /**
     * Complete successful transaction
     * @param {Object} transaction - Transaction
     * @param {Object} verificationResult - Verification result
     */
    completeTransaction(transaction, verificationResult) {
        const { id } = transaction;
        
        // Clear verification timer
        if (this.verificationTimers.has(id)) {
            clearTimeout(this.verificationTimers.get(id));
            this.verificationTimers.delete(id);
        }

        // Update transaction
        this.updateTransactionStatus(id, 'verified', {
            verifiedAt: Date.now(),
            verificationResult,
            totalVerificationTime: Date.now() - transaction.submittedAt
        });

        // Remove from active transactions
        const completedTransaction = this.activeTransactions.get(id);
        this.activeTransactions.delete(id);

        this.emit('verified', { transaction: completedTransaction });
        this.core?.log(`Transaction ${id} completed successfully`);
    }

    /**
     * Handle transaction timeout
     * @param {Object} transaction - Transaction
     * @param {Object} lastResult - Last verification result
     */
    timeoutTransaction(transaction, lastResult) {
        const { id } = transaction;
        
        // Clear verification timer
        if (this.verificationTimers.has(id)) {
            clearTimeout(this.verificationTimers.get(id));
            this.verificationTimers.delete(id);
        }

        // Update transaction
        this.updateTransactionStatus(id, 'timeout', {
            timeoutAt: Date.now(),
            lastVerificationResult: lastResult,
            totalVerificationTime: Date.now() - transaction.submittedAt
        });

        const timedOutTransaction = this.activeTransactions.get(id);
        this.activeTransactions.delete(id);

        this.emit('failed', { 
            transaction: timedOutTransaction, 
            error: 'Transaction verification timeout',
            timeout: true 
        });

        this.core?.warn(`Transaction ${id} timed out after ${this.config.verification.maxAttempts} attempts`);
    }

    /**
     * Handle transaction failure
     * @param {Object} transaction - Transaction
     * @param {Error} error - Error object
     */
    failTransaction(transaction, error) {
        const { id } = transaction;
        
        // Clear verification timer
        if (this.verificationTimers.has(id)) {
            clearTimeout(this.verificationTimers.get(id));
            this.verificationTimers.delete(id);
        }

        // Update transaction
        this.updateTransactionStatus(id, 'failed', {
            failedAt: Date.now(),
            error: error.message,
            totalVerificationTime: Date.now() - transaction.submittedAt
        });

        const failedTransaction = this.activeTransactions.get(id);
        this.activeTransactions.delete(id);

        this.emit('failed', { transaction: failedTransaction, error: error.message });
        this.core?.error(`Transaction ${id} failed:`, error.message);
    }

    /**
     * Transaction Management
     */

    /**
     * Update transaction status
     * @param {string} transactionId - Transaction ID
     * @param {string} status - New status
     * @param {Object} updates - Additional updates
     */
    updateTransactionStatus(transactionId, status, updates = {}) {
        const transaction = this.activeTransactions.get(transactionId);
        if (!transaction) return;

        // Update transaction
        Object.assign(transaction, {
            status,
            lastUpdated: Date.now(),
            ...updates
        });

        // Update in storage
        this.storeActiveTransactions();

        // Update in history
        const historyIndex = this.transactionHistory.findIndex(tx => tx.id === transactionId);
        if (historyIndex >= 0) {
            this.transactionHistory[historyIndex] = { ...transaction };
        }
    }

    /**
     * Cancel transaction verification
     * @param {string} transactionId - Transaction ID
     */
    cancelVerification(transactionId) {
        if (this.verificationTimers.has(transactionId)) {
            clearTimeout(this.verificationTimers.get(transactionId));
            this.verificationTimers.delete(transactionId);
            
            this.updateTransactionStatus(transactionId, 'cancelled', {
                cancelledAt: Date.now()
            });

            this.core?.log(`Verification cancelled for transaction ${transactionId}`);
            return true;
        }
        return false;
    }

    /**
     * Retry transaction verification
     * @param {string} transactionId - Transaction ID
     */
    retryVerification(transactionId) {
        const transaction = this.activeTransactions.get(transactionId);
        if (!transaction) {
            throw new Error('Transaction not found');
        }

        if (transaction.status === 'verified') {
            throw new Error('Transaction already verified');
        }

        // Reset verification attempts
        transaction.verificationAttempts = 0;
        
        // Cancel existing verification
        this.cancelVerification(transactionId);
        
        // Start new verification
        this.startVerification(transaction);
        
        this.core?.log(`Verification restarted for transaction ${transactionId}`);
    }

    /**
     * Utility Methods
     */

    /**
     * Validate transaction parameters
     * @param {Object} params - Transaction parameters
     * @returns {Object} Validation result
     */
    validateTransactionParams(params) {
        const { toAddress, tokenName, amount, walletName, sessionId } = params;
        const errors = [];

        if (!sessionId) errors.push('Session ID required');
        if (!walletName) errors.push('Wallet name required');
        if (!toAddress) errors.push('Recipient address required');
        if (!tokenName) errors.push('Token name required');
        if (!amount || parseFloat(amount) <= 0) errors.push('Valid amount required');

        // Use validation module if available
        if (this.validation && toAddress) {
            const addressValidation = this.validation.validateWalletAddress(toAddress);
            if (!addressValidation.valid) {
                errors.push(...addressValidation.errors);
            }
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    /**
     * Format amount for blockchain
     * @param {string|number} amount - Amount to format
     * @returns {string} Formatted amount
     */
    formatAmount(amount) {
        const num = parseFloat(amount);
        return `${num}.0e+18`;
    }

    /**
     * Generate unique transaction ID
     * @returns {string} Transaction ID
     */
    generateTransactionId() {
        return `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Add transaction to history
     * @param {Object} transaction - Transaction to add
     */
    addToHistory(transaction) {
        this.transactionHistory.unshift(transaction);
        
        // Limit history size
        if (this.transactionHistory.length > 100) {
            this.transactionHistory = this.transactionHistory.slice(0, 100);
        }

        // Store in persistent storage
        if (this.storage) {
            this.storage.setLocal('transaction_history', this.transactionHistory);
        }
    }

    /**
     * Storage Methods
     */

    /**
     * Store active transactions
     */
    storeActiveTransactions() {
        if (this.storage) {
            const transactions = Array.from(this.activeTransactions.values());
            this.storage.setSession('active_transactions', transactions);
        }
    }

    /**
     * Restore active transactions from storage
     */
    async restoreActiveTransactions() {
        if (!this.storage) return;

        try {
            const storedTransactions = this.storage.getSession('active_transactions') || [];
            const storedHistory = this.storage.getLocal('transaction_history') || [];

            // Restore history
            this.transactionHistory = storedHistory;

            // Restore active transactions
            for (const tx of storedTransactions) {
                // Only restore transactions that are still pending
                if (tx.status === 'submitted' || tx.status === 'verifying') {
                    this.activeTransactions.set(tx.id, tx);
                    
                    // Resume verification if needed
                    if (tx.status === 'verifying') {
                        this.startVerification(tx);
                    }
                }
            }

            if (storedTransactions.length > 0) {
                this.core?.log(`Restored ${storedTransactions.length} active transactions`);
            }

        } catch (error) {
            this.core?.error('Failed to restore active transactions:', error);
        }
    }

    /**
     * Public API Methods
     */

    /**
     * Get transaction by ID
     * @param {string} transactionId - Transaction ID
     * @returns {Object|null} Transaction
     */
    getTransaction(transactionId) {
        return this.activeTransactions.get(transactionId) || 
               this.transactionHistory.find(tx => tx.id === transactionId) || 
               null;
    }

    /**
     * Get active transactions
     * @returns {Array} Active transactions
     */
    getActiveTransactions() {
        return Array.from(this.activeTransactions.values());
    }

    /**
     * Get transaction history
     * @param {number} limit - Maximum number of transactions
     * @returns {Array} Transaction history
     */
    getTransactionHistory(limit = 50) {
        return this.transactionHistory.slice(0, limit);
    }

    /**
     * Get transaction statistics
     * @returns {Object} Statistics
     */
    getStats() {
        const active = this.getActiveTransactions();
        const history = this.transactionHistory;
        
        const statusCounts = {};
        history.forEach(tx => {
            statusCounts[tx.status] = (statusCounts[tx.status] || 0) + 1;
        });

        return {
            activeTransactions: active.length,
            totalTransactions: history.length,
            statusBreakdown: statusCounts,
            averageVerificationTime: this.calculateAverageVerificationTime()
        };
    }

    /**
     * Calculate average verification time
     * @returns {number} Average time in milliseconds
     */
    calculateAverageVerificationTime() {
        const verifiedTransactions = this.transactionHistory
            .filter(tx => tx.status === 'verified' && tx.submittedAt && tx.verifiedAt);

        if (verifiedTransactions.length === 0) return 0;

        const totalTime = verifiedTransactions.reduce((sum, tx) => {
            return sum + (tx.verifiedAt - tx.submittedAt);
        }, 0);

        return Math.round(totalTime / verifiedTransactions.length);
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
                    this.core?.error('Event handler error:', error);
                }
            });
        }

        // Also emit through core event system
        this.core?.emit(`transaction:${event}`, data);
    }

    /**
     * Clean up resources
     */
    destroy() {
        // Clear all verification timers
        for (const timer of this.verificationTimers.values()) {
            clearTimeout(timer);
        }
        this.verificationTimers.clear();

        // Clear state
        this.activeTransactions.clear();
        this.transactionHistory = [];
        this.eventHandlers = {};

        this.initialized = false;
        this.core?.log('Transaction Handler destroyed');
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('transaction', new CpunkTransactionHandler(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkTransactionHandler;
}