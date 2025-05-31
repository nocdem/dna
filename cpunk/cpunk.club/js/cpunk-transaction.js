/**
 * CPUNK Transaction Manager
 * Handles transaction submission, verification, and UI updates
 */

const CpunkTransaction = (function() {
    // Configuration
    const DEFAULT_CONFIG = {
        dashboardApiUrl: 'http://localhost:8045/',
        dnaProxyUrl: 'dna-proxy.php',
        maxVerificationAttempts: 10,
        verificationSchedule: [15, 45, 60, 60, 60, 60, 60, 60, 60, 60]
    };

    // State
    let config = {...DEFAULT_CONFIG};
    let verificationTimers = [];
    let sessionId = null;

    /**
     * Initialize with custom configuration
     * @param {Object} customConfig - Configuration options
     */
    function init(customConfig = {}) {
        config = {...DEFAULT_CONFIG, ...customConfig};
        
        // Use CpunkUtils for logging if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Transaction Manager initialized', 'info', { config });
        } else {
            console.log('Transaction Manager initialized with config:', config);
        }
    }

    /**
     * Set session ID for dashboard API calls
     * @param {string} id - Dashboard API session ID
     */
    function setSessionId(id) {
        sessionId = id;
    }

    /**
     * Get current session ID
     * @returns {string|null} - Current session ID
     */
    function getSessionId() {
        return sessionId;
    }

    /**
     * Send a transaction through the dashboard API
     * @param {Object} params - Transaction parameters
     * @param {string} params.walletName - Name of the wallet
     * @param {string} params.network - Network name (e.g., "Backbone")
     * @param {string} params.toAddress - Recipient address
     * @param {string} params.tokenName - Token name (e.g., "CPUNK", "CELL")
     * @param {string|number} params.value - Amount to send, formatted appropriately
     * @returns {Promise<Object>} - Transaction result with txHash
     */
    async function sendTransaction(params) {
        if (!sessionId) {
            throw new Error('Not connected to dashboard. Session ID is missing.');
        }

        const { walletName, network, toAddress, tokenName, value } = params;
        
        // Build request parameters
        const requestParams = {
            id: sessionId,
            net: network,
            walletName: walletName,
            toAddr: toAddress,
            tokenName: tokenName,
            value: value
        };

        try {
            // Use CpunkUtils for API call if available
            let response;
            if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dashboardRequest) {
                response = await CpunkUtils.dashboardRequest('SendTransaction', requestParams);
            } else {
                response = await makeRequest('SendTransaction', requestParams);
            }

            if (response.status === 'ok' && response.data && response.data.success) {
                // Get transaction hash (different API versions use different field names)
                const txHash = response.data.tx_hash || response.data.idQueue || 'Transaction Submitted';
                
                return {
                    success: true,
                    txHash: txHash,
                    raw: response
                };
            } else {
                throw new Error(response.errorMsg || 'Failed to send transaction');
            }
        } catch (error) {
            // Use CpunkUtils for logging if available
            if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
                CpunkUtils.logDebug('Transaction error', 'error', {
                    params: params,
                    error: error.message,
                    stack: error.stack
                });
            } else {
                console.error('Transaction error:', error);
            }
            
            throw error;
        }
    }

    /**
     * Create a staking order through the dashboard API
     * @param {Object} params - Staking parameters
     * @param {string} params.walletName - Name of the wallet
     * @param {string} params.network - Network name (e.g., "Backbone")
     * @param {string|number} params.value - Amount to stake, formatted appropriately
     * @param {string|number} params.tax - Tax rate for staking (e.g., "70.0")
     * @returns {Promise<Object>} - Staking result with txHash and orderHash
     */
    async function createStakingOrder(params) {
        if (!sessionId) {
            throw new Error('Not connected to dashboard. Session ID is missing.');
        }

        const { walletName, network, value, tax } = params;
        
        // Build request parameters
        const requestParams = {
            id: sessionId,
            net: network,
            walletName: walletName,
            value: value,
            tax: tax
        };

        try {
            // Use CpunkUtils for API call if available
            let response;
            if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dashboardRequest) {
                response = await CpunkUtils.dashboardRequest('CreateOrderStaker', requestParams);
            } else {
                response = await makeRequest('CreateOrderStaker', requestParams);
            }

            if (response.status === 'ok' && response.data && response.data.success) {
                // Get transaction and order hashes
                const txHash = response.data.tx_hash || response.data.idQueue || 'Transaction Submitted';
                const orderHash = response.data.order_hash || '';
                
                return {
                    success: true,
                    txHash: txHash,
                    orderHash: orderHash,
                    raw: response
                };
            } else {
                throw new Error(response.errorMsg || 'Failed to create staking order');
            }
        } catch (error) {
            // Use CpunkUtils for logging if available
            if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
                CpunkUtils.logDebug('Staking order error', 'error', {
                    params: params,
                    error: error.message,
                    stack: error.stack
                });
            } else {
                console.error('Staking order error:', error);
            }
            
            throw error;
        }
    }

    /**
     * Start verification process for a transaction
     * @param {Object} params - Verification parameters
     * @param {string} params.txHash - Transaction hash to verify
     * @param {string} params.network - Network name (optional)
     * @param {Function} params.onVerificationStart - Callback when verification starts
     * @param {Function} params.onVerificationSuccess - Callback when verification succeeds
     * @param {Function} params.onVerificationFail - Callback when verification fails
     * @param {Function} params.onVerificationAttempt - Callback on each verification attempt
     */
    function startVerification(params) {
        const { txHash, network, onVerificationStart, onVerificationSuccess, onVerificationFail, onVerificationAttempt } = params;
        
        // Clear any existing verification timers
        clearVerificationTimers();
        
        // Callback for verification start
        if (typeof onVerificationStart === 'function') {
            onVerificationStart(txHash);
        }
        
        // If CpunkUtils is available, use it for verification
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.startTransactionVerification) {
            verificationTimers = CpunkUtils.startTransactionVerification(
                txHash,
                (txHash, attempt) => {
                    if (typeof onVerificationSuccess === 'function') {
                        onVerificationSuccess(txHash, attempt);
                    }
                },
                (txHash, attempts, error) => {
                    if (typeof onVerificationFail === 'function') {
                        onVerificationFail(txHash, attempts, error);
                    }
                },
                (attempt, maxAttempts) => {
                    if (typeof onVerificationAttempt === 'function') {
                        onVerificationAttempt(attempt, maxAttempts);
                    }
                },
                network
            );
        } else {
            // Fallback implementation if CpunkUtils is not available
            verificationTimers = startFallbackVerification(params);
        }
    }

    /**
     * Clear all verification timers
     */
    function clearVerificationTimers() {
        // If CpunkUtils is available, use it
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.clearVerificationTimers) {
            CpunkUtils.clearVerificationTimers(verificationTimers);
        } else {
            // Fallback implementation
            if (Array.isArray(verificationTimers)) {
                verificationTimers.forEach(timer => clearTimeout(timer));
            }
        }
        
        verificationTimers = [];
    }

    /**
     * Fallback implementation for verification process
     * @param {Object} params - Verification parameters
     * @returns {Array} - Array of timer IDs
     */
    function startFallbackVerification(params) {
        const { txHash, onVerificationSuccess, onVerificationFail, onVerificationAttempt } = params;
        
        let verificationAttempt = 0;
        const maxAttempts = config.maxVerificationAttempts;
        const timers = [];
        
        // Calculate cumulative delays
        let cumulativeDelay = 0;
        
        // Schedule verification attempts
        config.verificationSchedule.forEach((seconds, index) => {
            cumulativeDelay += seconds;
            
            const timer = setTimeout(async () => {
                verificationAttempt = index + 1;
                
                // Call attempt callback if provided
                if (typeof onVerificationAttempt === 'function') {
                    onVerificationAttempt(verificationAttempt, maxAttempts);
                }
                
                // Try to verify the transaction
                try {
                    const verified = await verifyTransaction(txHash);
                    
                    if (verified) {
                        // Success! Clear all pending timers
                        timers.forEach(t => clearTimeout(t));
                        
                        if (typeof onVerificationSuccess === 'function') {
                            onVerificationSuccess(txHash, verificationAttempt);
                        }
                    } else if (index === config.verificationSchedule.length - 1) {
                        // Last attempt failed
                        if (typeof onVerificationFail === 'function') {
                            onVerificationFail(txHash, verificationAttempt);
                        }
                    }
                } catch (error) {
                    console.error(`Verification error on attempt ${verificationAttempt}:`, error);
                    
                    // On error in last attempt, call fail callback
                    if (index === config.verificationSchedule.length - 1 && typeof onVerificationFail === 'function') {
                        onVerificationFail(txHash, verificationAttempt, error);
                    }
                }
            }, cumulativeDelay * 1000);
            
            timers.push(timer);
        });
        
        return timers;
    }

    /**
     * Verify a transaction
     * @param {string} txHash - Transaction hash to verify
     * @param {string} network - Network name (optional)
     * @returns {Promise<boolean>} - Whether verification was successful
     */
    async function verifyTransaction(txHash, network = null) {
        try {
            // If CpunkUtils is available, use it
            if (typeof CpunkUtils !== 'undefined' && CpunkUtils.verifyTransaction) {
                return await CpunkUtils.verifyTransaction(txHash, network);
            }
            
            // Fallback implementation
            let url = `${config.dnaProxyUrl}?tx_validate=${encodeURIComponent(txHash)}`;
            if (network && network !== 'Backbone') {
                url += `&network=${encodeURIComponent(network)}`;
            }
            const response = await fetch(url);
            const data = await response.text();
            
            // Check if verification was successful
            let isVerified = false;
            
            try {
                const jsonData = JSON.parse(data);
                // Check for specific success criteria
                if (jsonData.status_code === 0 && jsonData.message === "OK") {
                    isVerified = true;
                }
            } catch (e) {
                // Not valid JSON, check text response for success indicators
                if (data.includes('"status_code": 0') && data.includes('"message": "OK"')) {
                    isVerified = true;
                }
            }
            
            return isVerified;
        } catch (error) {
            console.error('Error verifying transaction:', error);
            return false;
        }
    }

    /**
     * Make a request to the dashboard API (fallback if CpunkUtils is not available)
     * @param {string} method - API method
     * @param {Object} params - Request parameters
     * @returns {Promise<Object>} - API response
     */
    async function makeRequest(method, params = {}) {
        const url = new URL(config.dashboardApiUrl);
        url.searchParams.append('method', method);
        
        for (const [key, value] of Object.entries(params)) {
            url.searchParams.append(key, value);
        }
        
        const response = await fetch(url.toString());
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    }

    // Public API
    return {
        init,
        setSessionId,
        getSessionId,
        sendTransaction,
        createStakingOrder,
        startVerification,
        clearVerificationTimers,
        verifyTransaction
    };
})();

// Initialize with default configuration
CpunkTransaction.init();