/**
 * CPUNK UI Library
 * Common UI utilities for the CPUNK platform
 */

const CpunkUI = (function() {
    // Configuration
    const DEFAULT_CONFIG = {
        dashboardConnectorElements: {
            statusIndicatorId: 'statusIndicator',
            connectButtonId: 'connectButton',
            connectionErrorId: 'connectionError',
            walletSectionId: 'walletSection',
            walletsListId: 'walletsList',
            walletErrorId: 'walletError',
            dnaSectionId: 'dnaSection',
            dnaListId: 'dnaList',
            dnaErrorId: 'dnaError'
        },
        errorMessageTimeout: 10000 // 10 seconds
    };

    // State
    let config = {...DEFAULT_CONFIG};
    let elements = {};

    /**
     * Initialize with custom configuration
     * @param {Object} customConfig - Configuration options
     */
    function init(customConfig = {}) {
        config = {...DEFAULT_CONFIG, ...customConfig};
        
        // Cache DOM elements if document is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', cacheElements);
        } else {
            cacheElements();
        }
        
        // Log initialization if CpunkUtils is available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('UI Library initialized', 'info', { config });
        } else {
            console.log('UI Library initialized with config:', config);
        }
    }

    /**
     * Cache DOM elements based on configuration
     */
    function cacheElements() {
        // Dashboard connector elements
        const ids = config.dashboardConnectorElements;
        for (const [key, id] of Object.entries(ids)) {
            elements[key] = document.getElementById(id);
        }
        
        // Additional common elements
        elements.errorMessage = document.getElementById('errorMessage');
        elements.loadingIndicator = document.getElementById('loadingIndicator');
    }

    /**
     * Update dashboard connection status
     * @param {string} status - Status (connected, connecting, disconnected)
     * @param {string} message - Optional status message
     */
    function updateConnectionStatus(status, message = '') {
        const statusIndicator = elements.statusIndicatorId || document.getElementById(config.dashboardConnectorElements.statusIndicatorId);
        if (!statusIndicator) return;
        
        statusIndicator.className = 'status-indicator status-' + status;
        statusIndicator.textContent = message || status.charAt(0).toUpperCase() + status.slice(1);
    }

    /**
     * Show error message
     * @param {string} message - Error message
     * @param {string} elementId - Optional element ID to display error in
     * @param {number} timeout - Optional timeout to hide message (0 for no timeout)
     */
    function showError(message, elementId = 'errorMessage', timeout = config.errorMessageTimeout) {
        const errorElement = elementId === 'errorMessage' ? elements.errorMessage : document.getElementById(elementId);
        if (!errorElement) return;
        
        errorElement.textContent = message;
        errorElement.style.display = 'block';
        
        // Log error if CpunkUtils is available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug(`Error displayed to user: ${message}`, 'error');
        }
        
        // Hide after timeout if specified
        if (timeout > 0) {
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, timeout);
        }
    }

    /**
     * Hide error message
     * @param {string} elementId - Optional element ID
     */
    function hideError(elementId = 'errorMessage') {
        const errorElement = elementId === 'errorMessage' ? elements.errorMessage : document.getElementById(elementId);
        if (!errorElement) return;
        
        errorElement.style.display = 'none';
    }

    /**
     * Show/hide loading indicator
     * @param {boolean} isLoading - Whether loading is in progress
     * @param {string} elementId - Optional element ID
     */
    function setLoading(isLoading, elementId = 'loadingIndicator') {
        const loadingElement = elementId === 'loadingIndicator' ? elements.loadingIndicator : document.getElementById(elementId);
        if (!loadingElement) return;
        
        loadingElement.style.display = isLoading ? 'block' : 'none';
    }

    /**
     * Create wallet card for display
     * @param {Object} wallet - Wallet data
     * @param {function} onSelect - Callback when wallet is selected
     * @returns {HTMLElement} - Wallet card element
     */
    function createWalletCard(wallet, onSelect) {
        const { name, network, address, tokens } = wallet;
        
        // Find CPUNK and CELL tokens
        let cpunkToken = tokens.find(t => t.tokenName === 'CPUNK') || { balance: 0 };
        let cellToken = tokens.find(t => t.tokenName === 'CELL') || { balance: 0 };
        let mcellToken = tokens.find(t => t.tokenName === 'mCELL') || { balance: 0 };
        
        // Create wallet card element
        const walletCard = document.createElement('div');
        walletCard.className = 'wallet-card';
        walletCard.dataset.wallet = name;
        walletCard.dataset.network = network;
        walletCard.dataset.address = address;
        walletCard.dataset.cpunkBalance = cpunkToken.balance || 0;
        walletCard.dataset.cellBalance = cellToken.balance || 0;
        walletCard.dataset.mcellBalance = mcellToken.balance || 0;
        
        // Create balance display HTML
        let balancesHtml = '';
        
        // Format balances using CpunkUtils if available
        const formatBalance = typeof CpunkUtils !== 'undefined' && CpunkUtils.formatBalance
            ? CpunkUtils.formatBalance
            : (balance, decimals = 2) => parseFloat(balance).toLocaleString(undefined, {
                minimumFractionDigits: 0,
                maximumFractionDigits: decimals
            });
            
        if (cpunkToken.balance) {
            balancesHtml += `<div class="balance-item">CPUNK: ${formatBalance(cpunkToken.balance)}</div>`;
        }
        
        if (cellToken.balance) {
            balancesHtml += `<div class="balance-item">CELL: ${formatBalance(cellToken.balance)}</div>`;
        }
        
        if (mcellToken.balance) {
            balancesHtml += `<div class="balance-item">mCELL: ${formatBalance(mcellToken.balance)}</div>`;
        }
        
        // Set wallet card content
        walletCard.innerHTML = `
            <div class="wallet-name">${name} (${network})</div>
            <div class="wallet-balances">
                ${balancesHtml}
            </div>
            <div class="wallet-address">${address}</div>
        `;
        
        // Add click event listener
        if (typeof onSelect === 'function') {
            walletCard.addEventListener('click', () => {
                // Deselect all wallet cards
                document.querySelectorAll('.wallet-card').forEach(card => {
                    card.classList.remove('selected');
                });
                
                // Select this wallet card
                walletCard.classList.add('selected');
                
                // Call select callback
                onSelect(wallet);
            });
        }
        
        return walletCard;
    }

    /**
     * Create DNA card for display
     * @param {string} dnaName - DNA nickname
     * @param {Object} dnaInfo - DNA information
     * @param {function} onSelect - Callback when DNA is selected
     * @returns {HTMLElement} - DNA card element
     */
    function createDnaCard(dnaName, dnaInfo, onSelect) {
        const dnaCard = document.createElement('div');
        dnaCard.className = 'dna-card';
        dnaCard.innerHTML = `<div class="dna-name">${dnaName}</div>`;
        
        // Add click event listener
        if (typeof onSelect === 'function') {
            dnaCard.addEventListener('click', () => {
                // Deselect all DNA cards
                document.querySelectorAll('.dna-card').forEach(card => {
                    card.classList.remove('selected');
                });
                
                // Select this DNA card
                dnaCard.classList.add('selected');
                
                // Call select callback
                onSelect(dnaName, dnaInfo);
            });
        }
        
        return dnaCard;
    }

    /**
     * Create transaction verification UI
     * @param {string} txHash - Transaction hash
     * @param {string} orderHash - Optional order hash (for staking)
     * @returns {HTMLElement} - Verification UI element
     */
    function createVerificationUI(txHash, orderHash = null) {
        const container = document.createElement('div');
        container.className = 'verification-container';
        
        // Warning about not closing the page
        const pageWarning = `
            <div class="verification-warning">
                <strong>⚠️ IMPORTANT:</strong> Please do not close this page while verification is in progress. 
                Closing the page may interrupt the verification process.
            </div>
        `;
        
        // Transaction hash display
        let hashDisplay = `
            <div class="tx-hash-container">
                <div class="tx-hash-label">Transaction Hash:</div>
                <div class="tx-hash-value" id="tx-hash-value">${txHash}</div>
                <button class="copy-button" onclick="CpunkUI.copyHash('${txHash}', this)">
                    <span class="copy-icon">📋</span> Copy
                </button>
            </div>
        `;
        
        // Add order hash display if provided
        if (orderHash) {
            hashDisplay += `
                <div class="tx-hash-container">
                    <div class="tx-hash-label">Order Hash:</div>
                    <div class="tx-hash-value" id="order-hash-value">${orderHash}</div>
                    <button class="copy-button" onclick="CpunkUI.copyHash('${orderHash}', this)">
                        <span class="copy-icon">📋</span> Copy
                    </button>
                </div>
            `;
        }
        
        // Verification status
        const statusDisplay = `
            <div class="verification-status" id="verification-status">
                <div class="status-heading">Verification Pending</div>
                <div class="status-description">
                    We need to verify your transaction before finalizing the process.
                    This may take a few moments.
                </div>
            </div>
        `;
        
        // Progress bar
        const progressBar = `
            <div class="verification-progress" id="verification-progress">
                <div class="progress-track">
                    <div class="progress-fill" id="progress-fill" style="width: 0%"></div>
                </div>
            </div>
        `;
        
        // Verification details
        const verificationDetails = `
            <div class="verification-details" id="verification-details">
                <ul class="verification-steps">
                    <li><span class="step-number">1</span> Transaction submitted</li>
                    <li class="current-step"><span class="step-number">2</span> Verification in progress</li>
                    <li><span class="step-number">3</span> Confirmation</li>
                </ul>
                <div class="verification-note">
                    <span class="note-icon">ℹ️</span>
                    The verification will run automatically multiple times.
                    If it fails, you can manually retest using the button below.
                </div>
            </div>
        `;
        
        // Retry button
        const retryButton = `
            <div class="verification-actions">
                <button class="retry-button" id="retry-verification-button" style="display: none;">
                    Retest Verification
                </button>
            </div>
        `;
        
        // Assemble the container
        container.innerHTML = `
            ${pageWarning}
            ${hashDisplay}
            ${statusDisplay}
            ${progressBar}
            ${verificationDetails}
            ${retryButton}
        `;
        
        return container;
    }

    /**
     * Update verification UI based on status
     * @param {string} status - Status (pending, progress, success, failed, error)
     * @param {Object} params - Parameters for the update
     */
    function updateVerificationUI(status, params = {}) {
        const { 
            attempt = 0, 
            maxAttempts = 10, 
            statusElement = document.getElementById('verification-status'),
            progressElement = document.getElementById('progress-fill'),
            detailsElement = document.getElementById('verification-details'),
            retryElement = document.getElementById('retry-verification-button')
        } = params;
        
        if (!statusElement || !progressElement) return;
        
        // Update progress
        const progressPercentage = Math.min(100, (attempt / maxAttempts) * 100);
        progressElement.style.width = `${progressPercentage}%`;
        
        // Update based on status
        switch (status) {
            case 'pending':
                statusElement.innerHTML = `
                    <div class="status-heading">Verification Pending</div>
                    <div class="status-description">
                        We need to verify your transaction before finalizing the process.
                        This process may take a few moments.
                    </div>
                `;
                break;
                
            case 'progress':
                statusElement.innerHTML = `
                    <div class="status-heading">Verification in Progress</div>
                    <div class="status-description">
                        Verifying transaction: Attempt ${attempt} of ${maxAttempts}
                    </div>
                    <div class="status-warning">
                        Please keep this page open until verification completes.
                    </div>
                `;
                
                if (detailsElement) {
                    detailsElement.innerHTML = `
                        <ul class="verification-steps">
                            <li class="completed-step"><span class="step-number">✓</span> Transaction submitted</li>
                            <li class="current-step"><span class="step-number">${attempt}</span> Verification in progress</li>
                            <li><span class="step-number">3</span> Confirmation</li>
                        </ul>
                        <div class="verification-note">
                            <span class="note-icon">ℹ️</span>
                            Attempt ${attempt} of ${maxAttempts} in progress...
                        </div>
                    `;
                }
                break;
                
            case 'success':
                statusElement.innerHTML = `
                    <div class="status-heading success-heading">Verification Successful</div>
                    <div class="status-description">
                        Your transaction has been successfully verified.
                    </div>
                `;
                
                progressElement.style.width = '100%';
                progressElement.classList.add('success-fill');
                
                if (detailsElement) {
                    detailsElement.innerHTML = `
                        <ul class="verification-steps">
                            <li class="completed-step"><span class="step-number">✓</span> Transaction submitted</li>
                            <li class="completed-step"><span class="step-number">✓</span> Verification complete</li>
                            <li class="completed-step"><span class="step-number">✓</span> Confirmation</li>
                        </ul>
                    `;
                }
                
                if (retryElement) {
                    retryElement.style.display = 'none';
                }
                break;
                
            case 'failed':
                statusElement.innerHTML = `
                    <div class="status-heading failed-heading">Verification Pending</div>
                    <div class="status-description">
                        We couldn't verify your transaction yet. This doesn't mean it failed; it may take longer to process.
                        You can manually retry verification using the button below.
                    </div>
                `;
                
                if (detailsElement) {
                    detailsElement.innerHTML = `
                        <div class="verification-alert">
                            <span class="alert-icon">⚠️</span>
                            <span>Transaction verification is taking longer than expected. This can happen due to network congestion.</span>
                        </div>
                        <ul class="verification-steps">
                            <li class="completed-step"><span class="step-number">✓</span> Transaction submitted</li>
                            <li class="pending-step"><span class="step-number">⟳</span> Verification pending</li>
                            <li><span class="step-number">3</span> Confirmation</li>
                        </ul>
                    `;
                }
                
                if (retryElement) {
                    retryElement.style.display = 'block';
                }
                break;
                
            case 'error':
                statusElement.innerHTML = `
                    <div class="status-heading error-heading">Verification Error</div>
                    <div class="status-description">
                        We encountered an error while trying to verify your transaction.
                        You can try again using the button below.
                    </div>
                `;
                
                if (retryElement) {
                    retryElement.style.display = 'block';
                }
                break;
        }
    }

    /**
     * Copy hash to clipboard
     * @param {string} hash - Hash to copy
     * @param {HTMLElement} buttonElement - Button element that was clicked
     */
    function copyHash(hash, buttonElement) {
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.copyToClipboard) {
            CpunkUtils.copyToClipboard(hash, 
                // Success callback
                () => {
                    const originalText = buttonElement.innerHTML;
                    buttonElement.innerHTML = '<span class="copy-icon">✓</span> Copied!';
                    
                    setTimeout(() => {
                        buttonElement.innerHTML = '<span class="copy-icon">📋</span> Copy';
                    }, 2000);
                },
                // Error callback
                (err) => {
                    alert('Failed to copy. Please try again or copy manually.');
                }
            );
        } else {
            // Fallback if CpunkUtils is not available
            navigator.clipboard.writeText(hash).then(() => {
                const originalText = buttonElement.innerHTML;
                buttonElement.innerHTML = '<span class="copy-icon">✓</span> Copied!';
                
                setTimeout(() => {
                    buttonElement.innerHTML = '<span class="copy-icon">📋</span> Copy';
                }, 2000);
            }).catch(err => {
                alert('Failed to copy. Please try again or copy manually.');
            });
        }
    }

    // Public API
    return {
        init,
        updateConnectionStatus,
        showError,
        hideError,
        setLoading,
        createWalletCard,
        createDnaCard,
        createVerificationUI,
        updateVerificationUI,
        copyHash
    };
})();

// Initialize with default configuration
CpunkUI.init();