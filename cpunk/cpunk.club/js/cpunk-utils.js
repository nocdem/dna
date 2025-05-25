/**
 * CPUNK Utilities Library
 * Common utilities for the CPUNK platform
 */

const CpunkUtils = (function() {
    // Default configuration
    const DEFAULT_CONFIG = {
        dashboardApiUrl: 'http://localhost:8045/',
        dnaProxyUrl: 'dna-proxy.php',
        debug: {
            enabled: true,
            showInConsole: true,
            showInUI: true,
            showOnlyOnError: false
        }
    };

    // Config storage
    let config = {...DEFAULT_CONFIG};
    let debugEntries = [];

    /**
     * Initialize with custom configuration
     * @param {Object} customConfig - Configuration options
     */
    function init(customConfig = {}) {
        config = {...DEFAULT_CONFIG, ...customConfig};
        
        if (config.debug.enabled) {
            console.log('CPUNK Utils initialized with config:', config);
        }
    }

    /**
     * Dashboard API Request
     * @param {string} method - API method name
     * @param {Object} params - Request parameters
     * @param {Object} options - Additional options like session ID
     * @returns {Promise<Object>} - API response
     */
    async function dashboardRequest(method, params = {}, options = {}) {
        const url = new URL(config.dashboardApiUrl);
        url.searchParams.append('method', method);

        for (const [key, value] of Object.entries(params)) {
            url.searchParams.append(key, value);
        }

        try {
            // Log request details if debug enabled
            if (config.debug.enabled) {
                logDebug(`Dashboard API Request - ${method}`, 'request', params);
            }
            
            const startTime = Date.now();
            const response = await fetch(url.toString());
            const responseTime = Date.now() - startTime;

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            // Log response if debug enabled
            if (config.debug.enabled) {
                logDebug(`Dashboard API Response - ${method} (${responseTime}ms)`, 'response', data);
            }
            
            return data;
        } catch (error) {
            if (config.debug.enabled) {
                logDebug(`Dashboard API Error - ${method}`, 'error', {
                    error: error.message,
                    stack: error.stack,
                    params: params
                });
            }
            throw error;
        }
    }

    /**
     * DNA API Request
     * @param {string} action - Action type (lookup, tx_validate, etc.)
     * @param {string} value - Value for the action
     * @returns {Promise<Object|string>} - API response
     */
    async function dnaLookup(action, value) {
        try {
            if (config.debug.enabled) {
                logDebug(`DNA ${action} Request`, 'request', { action, value });
            }
            
            const url = `${config.dnaProxyUrl}?${action}=${encodeURIComponent(value)}`;
            const startTime = Date.now();
            const response = await fetch(url);
            const responseTime = Date.now() - startTime;
            const text = await response.text();
            
            if (config.debug.enabled) {
                logDebug(`DNA ${action} Response (${responseTime}ms)`, 'response', { 
                    status: response.status,
                    responseText: text 
                });
            }
            
            // Try to parse as JSON, return as is if not valid JSON
            try {
                return JSON.parse(text);
            } catch (e) {
                return text;
            }
        } catch (error) {
            if (config.debug.enabled) {
                logDebug(`DNA ${action} Error`, 'error', {
                    action: action,
                    value: value,
                    error: error.message,
                    stack: error.stack
                });
            }
            throw error;
        }
    }

    /**
     * Send DNA API POST request
     * @param {Object} data - Data to send to the DNA API
     * @returns {Promise<Object|string>} - API response
     */
    async function dnaPost(data) {
        try {
            if (config.debug.enabled) {
                logDebug('DNA POST Request', 'request', data);
            }
            
            const startTime = Date.now();
            const response = await fetch(config.dnaProxyUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });
            
            const responseTime = Date.now() - startTime;
            const text = await response.text();
            
            if (config.debug.enabled) {
                logDebug(`DNA POST Response (${responseTime}ms)`, 'response', { 
                    status: response.status,
                    responseText: text 
                });
            }
            
            // Try to parse as JSON, return as is if not valid JSON
            try {
                return JSON.parse(text);
            } catch (e) {
                return text;
            }
        } catch (error) {
            if (config.debug.enabled) {
                logDebug('DNA POST Error', 'error', {
                    data: data,
                    error: error.message,
                    stack: error.stack
                });
            }
            throw error;
        }
    }

    /**
     * Check if nickname is valid format
     * @param {string} nickname - The DNA nickname to validate
     * @returns {boolean} - Whether the nickname has a valid format
     */
    function isValidNicknameFormat(nickname) {
        if (!nickname) return false;
        
        // Check length
        if (nickname.length < 3 || nickname.length > 36) return false;
        
        // Check for valid characters (letters, numbers, underscore, hyphen, period)
        const validPattern = /^[a-zA-Z0-9_\-\.]+$/;
        return validPattern.test(nickname);
    }

    /**
     * Calculate CPUNK price for DNA registration based on nickname length
     * @param {string} nickname - The DNA nickname
     * @returns {number} - The price in CPUNK tokens
     */
    function calculateDnaPrice(nickname) {
        const length = nickname.length;

        if (length === 0) return 0;
        if (length === 3) return 500;
        if (length === 4) return 100;
        return 5; // 5+ characters
    }

    /**
     * Calculate tax rate for delegation based on amount
     * @param {number} amount - The delegation amount
     * @returns {number} - The tax rate percentage
     */
    function calculateDelegationTax(amount) {
        if (amount < 50) {
            return 30.0;
        } else if (amount < 100) {
            return 25.0;
        } else {
            return 20.0;
        }
    }

    /**
     * Format balance for display
     * @param {number|string} balance - The balance to format
     * @param {number} decimals - Number of decimals to show
     * @returns {string} - Formatted balance string
     */
    function formatBalance(balance, decimals = 2) {
        return parseFloat(balance).toLocaleString(undefined, {
            minimumFractionDigits: 0,
            maximumFractionDigits: decimals
        });
    }

    /**
     * Check if an address is registered in DNA
     * @param {string} address - The wallet address to check
     * @returns {Promise<Object>} - Object with isRegistered flag and names array
     */
    async function checkDnaRegistration(address) {
        try {
            // Trim any whitespace to ensure clean address
            const cleanAddress = address.trim();
            
            // Use the dna-proxy endpoint for lookup
            const result = await dnaLookup('lookup', cleanAddress);
            
            let isRegistered = false;
            let names = [];
            
            if (typeof result === 'string') {
                // Check if text response indicates the name doesn't exist
                isRegistered = !result.includes('not found') && !result.includes('No matching');
            } else {
                // Handle the API response format with status_code and response_data
                if (result.status_code === 0 && result.response_data) {
                    // Check for registered names in the data
                    const registeredNames = result.response_data.registered_names || {};
                    names = Object.keys(registeredNames);
                    isRegistered = names.length > 0;
                }
            }
            
            return {
                isRegistered,
                names,
                response: result
            };
        } catch (error) {
            if (config.debug.enabled) {
                logDebug('Error checking DNA registration', 'error', {
                    address: address,
                    error: error.message,
                    stack: error.stack
                });
            }
            
            return {
                isRegistered: false,
                names: [],
                error: error.message
            };
        }
    }

    /**
     * Check nickname availability
     * @param {string} nickname - The nickname to check
     * @returns {Promise<Object>} - Object with isAvailable flag and response data
     */
    async function checkNicknameAvailability(nickname) {
        try {
            const result = await dnaLookup('lookup', nickname);
            
            let isAvailable = false;
            let isAlreadyOwned = false;
            
            if (typeof result === 'string') {
                // Check if text response indicates the name doesn't exist
                isAvailable = result.includes('not found') || result.includes('No matching');
            } else {
                // If the response contains a wallet address or success status, the nickname is taken
                if (result.wallet ||
                    (result.status_code === 0 && result.response_data) ||
                    result.success === true) {
                    isAvailable = false;
                }
                
                // Special case for "use update method" message - explicitly check for already registered
                if (result.status_code === -1 && 
                    result.description && 
                    (result.description.includes("use update method") ||
                     result.description.includes("already registered"))) {
                    isAvailable = false;
                    isAlreadyOwned = true;
                }
                
                // Check for error messages indicating the nickname was not found (which means it's available)
                if (result.error ||
                    result.message === "not found" ||
                    (result.status_code === -1 && 
                     !(result.description && result.description.includes("use update method"))) ||
                    (result.description && result.description.includes('not found')) ||
                    (typeof result === 'object' && result.error)) {
                    isAvailable = true;
                }
            }
            
            return {
                isAvailable,
                isAlreadyOwned,
                response: result
            };
        } catch (error) {
            if (config.debug.enabled) {
                logDebug('Error checking nickname availability', 'error', {
                    nickname: nickname,
                    error: error.message,
                    stack: error.stack
                });
            }
            
            return {
                isAvailable: false,
                isAlreadyOwned: false,
                error: error.message
            };
        }
    }

    /**
     * Start transaction verification process with a specific schedule
     * @param {string} txHash - Transaction hash to verify
     * @param {function} onVerify - Callback on successful verification
     * @param {function} onFail - Callback on failed verification
     * @param {function} onAttempt - Callback on each verification attempt
     * @returns {Array} - Array of timer IDs
     */
    function startTransactionVerification(txHash, onVerify, onFail, onAttempt) {
        const MAX_ATTEMPTS = 10;
        let verificationAttempts = 0;
        const verificationTimers = [];
        
        // Create a verification schedule with specific timings:
        // 1. First check at 15 seconds
        // 2. Second check at 1 minute (60 seconds)
        // 3. Then additional checks every 60 seconds until 10 minutes
        const schedule = [
            15,     // First check at 15 seconds
            45,     // Second check at 60 seconds from start (15+45)
            60,     // Third check at 120 seconds from start
            60,     // Fourth check at 180 seconds from start
            60,     // Fifth check at 240 seconds from start
            60,     // Sixth check at 300 seconds from start
            60,     // Seventh check at 360 seconds from start
            60,     // Eighth check at 420 seconds from start
            60,     // Ninth check at 480 seconds from start
            60      // Tenth check at 540 seconds from start (9 minutes)
        ];

        // Calculate cumulative delays
        let cumulativeDelay = 0;

        // Schedule verification attempts according to the schedule
        schedule.forEach((seconds, index) => {
            cumulativeDelay += seconds;

            const timer = setTimeout(async () => {
                // Update attempt count
                verificationAttempts = index + 1;
                
                // Call the attempt callback if provided
                if (typeof onAttempt === 'function') {
                    onAttempt(verificationAttempts, MAX_ATTEMPTS);
                }

                // Try to verify the transaction
                try {
                    const verified = await verifyTransaction(txHash);

                    if (verified) {
                        // Success! Clear all pending timers and call the success callback
                        verificationTimers.forEach(t => clearTimeout(t));
                        
                        if (typeof onVerify === 'function') {
                            onVerify(txHash, verificationAttempts);
                        }
                    } else if (index === schedule.length - 1) {
                        // Last attempt failed
                        if (typeof onFail === 'function') {
                            onFail(txHash, verificationAttempts);
                        }
                    }
                } catch (error) {
                    if (config.debug.enabled) {
                        logDebug(`Verification error on attempt ${verificationAttempts}`, 'error', {
                            txHash: txHash,
                            error: error.message,
                            stack: error.stack
                        });
                    }
                    
                    // On error in last attempt, call fail callback
                    if (index === schedule.length - 1 && typeof onFail === 'function') {
                        onFail(txHash, verificationAttempts, error);
                    }
                }
            }, cumulativeDelay * 1000);

            verificationTimers.push(timer);
        });
        
        return verificationTimers;
    }

    /**
     * Clear all verification timers
     * @param {Array} timers - Array of timer IDs
     */
    function clearVerificationTimers(timers) {
        if (Array.isArray(timers)) {
            timers.forEach(timer => clearTimeout(timer));
        }
    }

    /**
     * Verify transaction
     * @param {string} txHash - Transaction hash to verify
     * @returns {Promise<boolean>} - Whether the transaction is verified
     */
    async function verifyTransaction(txHash) {
        try {
            const data = await dnaLookup('tx_validate', txHash);
            
            // Check if verification was successful
            let isVerified = false;
            
            if (typeof data === 'string') {
                // Check text response for success indicators
                isVerified = data.includes('"status_code": 0') && data.includes('"message": "OK"');
            } else {
                // Check for specific success criteria
                isVerified = data.status_code === 0 && data.message === "OK";
            }

            return isVerified;
        } catch (error) {
            if (config.debug.enabled) {
                logDebug('Transaction verification error', 'error', {
                    txHash: txHash,
                    error: error.message,
                    stack: error.stack
                });
            }
            return false;
        }
    }

    /**
     * Copy text to clipboard
     * @param {string} text - Text to copy
     * @param {function} onSuccess - Callback on success
     * @param {function} onError - Callback on error
     */
    function copyToClipboard(text, onSuccess, onError) {
        navigator.clipboard.writeText(text).then(() => {
            if (typeof onSuccess === 'function') {
                onSuccess();
            }
        }).catch(err => {
            if (config.debug.enabled) {
                logDebug('Copy to clipboard error', 'error', { 
                    error: err.message,
                    text: text.length > 20 ? text.substring(0, 20) + '...' : text
                });
            }
            
            if (typeof onError === 'function') {
                onError(err);
            } else {
                alert('Failed to copy text. Please try again or copy manually.');
            }
        });
    }

    /**
     * Register DNA nickname
     * @param {Object} params - Registration parameters
     * @param {string} params.nickname - The nickname to register
     * @param {string} params.walletAddress - The wallet address
     * @param {string} params.txHash - The transaction hash
     * @returns {Promise<Object>} - Registration result
     */
    async function registerDna(params) {
        try {
            const { nickname, walletAddress, txHash } = params;
            
            // Make the API request to register the DNA
            const registrationData = {
                action: 'add',
                name: nickname,
                wallet: walletAddress,
                tx_hash: txHash
            };
            
            const result = await dnaPost(registrationData);
            
            // Check if registration was successful
            let isSuccess = false;
            let isAlreadyRegistered = false;
            
            if (typeof result === 'string') {
                // If string response, check for success string
                isSuccess = result.includes('success') && !result.includes('false');
            } else {
                // Check standard success conditions
                isSuccess = result.success || result.status === 'ok' || result.status_code === 0;
                
                // Check for "already registered" condition - also consider it a success
                if (!isSuccess && result.status_code === -1 && 
                    result.description && 
                    (result.description.includes("already registered") || 
                     result.description.includes("use update method"))) {
                    isSuccess = true;
                    isAlreadyRegistered = true;
                }
            }
            
            return {
                success: isSuccess,
                isAlreadyRegistered,
                response: result
            };
        } catch (error) {
            if (config.debug.enabled) {
                logDebug('Error registering DNA', 'error', {
                    params: params,
                    error: error.message,
                    stack: error.stack
                });
            }
            
            throw error;
        }
    }

    /**
     * Record delegation in DNA profile
     * @param {Object} params - Delegation parameters
     * @param {string} params.walletAddress - The wallet address
     * @param {string} params.txHash - The transaction hash
     * @param {string} params.orderHash - The order hash
     * @param {string} params.network - The network name
     * @param {number} params.amount - The delegation amount
     * @param {number} params.taxRate - The tax rate percentage
     * @returns {Promise<boolean>} - Whether recording was successful
     */
    async function recordDelegation(params) {
        try {
            const { walletAddress, txHash, orderHash, network, amount, taxRate } = params;
            
            // Prepare request data with array of delegations
            const delegationData = {
                action: "update",
                wallet: walletAddress,
                delegations: [
                    {
                        tx_hash: txHash,
                        order_hash: orderHash,
                        network: network,
                        amount: amount,
                        tax: taxRate
                    }
                ]
            };

            const result = await dnaPost(delegationData);
            
            // Check if recording was successful
            if (typeof result === 'string') {
                // If string response, check for success string
                return result.includes('success') && !result.includes('false');
            } else {
                // Check standard success conditions
                return result.status === 'ok' || result.success === true;
            }
        } catch (error) {
            if (config.debug.enabled) {
                logDebug('Error recording delegation', 'error', {
                    params: params,
                    error: error.message,
                    stack: error.stack
                });
            }
            
            return false;
        }
    }

    // Debugging utilities
    
    /**
     * Log debug information
     * @param {string} message - Debug message
     * @param {string} type - Message type (info, request, response, error, warning)
     * @param {*} data - Additional data
     */
    function logDebug(message, type = 'info', data = null) {
        if (!config.debug.enabled) return;

        const timestamp = new Date().toISOString();
        const entry = {
            type: type,
            message: message,
            data: data,
            timestamp: timestamp
        };

        // Add to entries array
        debugEntries.unshift(entry); // Add to beginning for newest first

        // Log to console if enabled
        if (config.debug.showInConsole) {
            switch (type) {
                case 'request':
                    console.group(`🔷 API Request: ${message}`);
                    console.log('Timestamp:', timestamp);
                    if (data) console.log('Data:', data);
                    console.groupEnd();
                    break;
                case 'response':
                    console.group(`🔶 API Response: ${message}`);
                    console.log('Timestamp:', timestamp);
                    if (data) console.log('Data:', data);
                    console.groupEnd();
                    break;
                case 'error':
                    console.group(`❌ Error: ${message}`);
                    console.log('Timestamp:', timestamp);
                    if (data) console.error('Error details:', data);
                    console.groupEnd();
                    break;
                case 'warning':
                    console.group(`⚠️ Warning: ${message}`);
                    console.log('Timestamp:', timestamp);
                    if (data) console.warn('Warning details:', data);
                    console.groupEnd();
                    break;
                default:
                    console.log(`ℹ️ ${timestamp} - ${message}`, data || '');
            }
        }
    }

    /**
     * Get debug entries
     * @param {number} limit - Maximum number of entries to return
     * @returns {Array} - Debug entries
     */
    function getDebugEntries(limit = 10) {
        return debugEntries.slice(0, limit);
    }

    /**
     * Format JSON with syntax highlighting for HTML
     * @param {Object} obj - Object to format
     * @returns {string} - HTML string with syntax highlighting
     */
    function formatJsonForHtml(obj) {
        const json = JSON.stringify(obj, null, 2);
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'key';
                    // Remove the colon at the end for the key
                    match = match.replace(/:$/, '');
                    return '<span class="' + cls + '">' + match + '</span>:';
                } else {
                    cls = 'string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'boolean';
            } else if (/null/.test(match)) {
                cls = 'null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    }

    // Public API
    return {
        init,
        dashboardRequest,
        dnaLookup,
        dnaPost,
        isValidNicknameFormat,
        calculateDnaPrice,
        calculateDelegationTax,
        formatBalance,
        checkDnaRegistration,
        checkNicknameAvailability,
        startTransactionVerification,
        clearVerificationTimers,
        verifyTransaction,
        copyToClipboard,
        registerDna,
        recordDelegation,
        logDebug,
        getDebugEntries,
        formatJsonForHtml
    };
})();

// Initialize with default configuration
CpunkUtils.init();