// State variables
let sessionId = null;
let walletAddress = null;
let currentDna = null;
let selectedNetwork = null;
let availableBalance = 0;
let currentTxHash = null;
let currentOrderHash = null;

// Store delegation details for recording to DNA profile
let delegationRewardsAddress = null;
let delegationAmountValue = null;

// Network configuration
const NETWORK_CONFIG = {
    'Backbone': {
        delegationToken: 'mCELL',
        feeToken: 'CELL',
        minDelegation: 10,
        maxDelegation: 150,
        minFee: 0.05,
        taxRates: {
            10: 30,    // 10-50 mCELL = 30% tax
            50: 25,    // 50-100 mCELL = 25% tax
            100: 20    // 100+ mCELL = 20% tax
        }
    },
    'KelVPN': {
        delegationToken: 'mKEL',
        feeToken: 'KEL',
        minDelegation: 400,
        maxDelegation: 800,
        minFee: 1,
        taxRates: {
            400: 50,   // 400-799 mKEL = 50% tax
            800: 40    // 800 mKEL = 40% tax
        }
    }
};

// DOM Elements - wait until document is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize utilities with appropriate configurations
    // Initialize utility modules
    CpunkUtils.init({
        debug: {
            enabled: true,
            showInConsole: true,
            showInUI: false
        }
    });
    
    CpunkUI.init({
        dashboardConnectorElements: {
            statusIndicatorId: 'statusIndicator',
            connectButtonId: 'connectButton',
            connectionErrorId: 'errorMessage'
        }
    });
    
    CpunkTransaction.init();
    
    // DOM Elements
    const statusIndicator = document.getElementById('statusIndicator');
    const sessionDetails = document.getElementById('sessionDetails');
    const errorMessage = document.getElementById('errorMessage');
    const connectButton = document.getElementById('connectButton');
    const networkSection = document.getElementById('networkSection');
    const networksList = document.getElementById('networksList');
    const walletsSection = document.getElementById('walletsSection');
    const walletsList = document.getElementById('walletsList');
    const walletHelpText = document.getElementById('walletHelpText');
    const delegationForm = document.getElementById('delegationForm');
    const selectedWalletDisplay = document.getElementById('selectedWalletDisplay');
    const rewardsAddress = document.getElementById('rewardsAddress');
    const delegationAmount = document.getElementById('delegationAmount');
    const balanceWarning = document.getElementById('balanceWarning');
    const rewardsAddressError = document.getElementById('rewardsAddressError');
    const delegationAmountError = document.getElementById('delegationAmountError');
    const submitDelegation = document.getElementById('submitDelegation');
    const successMessage = document.getElementById('successMessage');
    const dnaStatus = document.getElementById('dnaStatus');
    const taxValue = document.getElementById('taxValue');

    // Verification elements
    const verificationSection = document.getElementById('verificationSection');
    const txHashDisplay = document.getElementById('txHashDisplay');
    const orderHashDisplay = document.getElementById('orderHashDisplay');
    const verificationStatus = document.getElementById('verificationStatus');
    const verificationProgress = document.getElementById('verificationProgress');
    const progressFill = document.getElementById('progressFill');
    const retestVerificationButton = document.getElementById('retestVerificationButton');
    const verificationDetails = document.getElementById('verificationDetails');

    // Store original submission handler reference for clean handling
    const originalSubmitHandler = handleDelegationSubmission;
    
    // Initialize SSO and check authentication
    if (typeof CpunkSSO !== 'undefined') {
        CpunkSSO.getInstance().init({
            requireAuth: true,
            onAuthenticated: function(userData) {
                // User is authenticated
                console.log('User authenticated:', userData);
                
                // Store wallet and DNA info
                walletAddress = userData.wallet;
                currentDna = userData.dna;
                sessionId = userData.sessionId;
                
                // Update UI to show authenticated state
                if (statusIndicator) {
                    statusIndicator.textContent = 'Connected';
                    statusIndicator.className = 'status-indicator status-connected';
                }
                
                // Hide connect button and show network selection
                if (connectButton) connectButton.style.display = 'none';
                if (networkSection) networkSection.style.display = 'block';
                
                // Show networks immediately
                showNetworkSelection();
            },
            onUnauthenticated: function() {
                // User is not authenticated - SSO will redirect to login page
                console.log('User not authenticated, redirecting to login...');
            }
        });
    } else {
        console.error('CpunkSSO not found. Make sure sso.js is loaded.');
    }
    
    // Remove connect button click handler as authentication is handled by SSO
    if (connectButton) {
        connectButton.style.display = 'none';
    }

    delegationAmount.addEventListener('input', () => {
        updateBalanceWarning();
        validateForm();

        // Update tax rate based on amount and network
        const amount = parseFloat(delegationAmount.value);
        if (!isNaN(amount) && selectedNetwork && NETWORK_CONFIG[selectedNetwork]) {
            const config = NETWORK_CONFIG[selectedNetwork];
            if (amount >= config.minDelegation) {
                const tax = calculateNetworkTax(selectedNetwork, amount);
                taxValue.textContent = `${tax.toFixed(1)}%`;
            }
        }
    });

    rewardsAddress.addEventListener('input', async (e) => {
        const address = e.target.value.trim();

        // Check DNA registration immediately for the new address
        if (address.length >= 30) {
            await checkDnaRegistration(address);
        } else {
            dnaStatus.style.display = 'none';
        }

        validateForm();
    });

    // For the submit button, we'll use onclick instead of addEventListener
    // This makes it easier to replace the handler later
    submitDelegation.onclick = originalSubmitHandler;

    // Add event listener for retest verification button
    if (retestVerificationButton) {
        retestVerificationButton.addEventListener('click', () => {
            retestVerificationButton.textContent = "Testing...";
            retestVerificationButton.disabled = true;
            retestVerificationButton.classList.add('button-testing');

            retestVerification(currentTxHash).finally(() => {
                retestVerificationButton.textContent = "Retest Verification";
                retestVerificationButton.disabled = false;
                retestVerificationButton.classList.remove('button-testing');
            });
        });
    }

    // Calculate tax rate based on network and amount
    function calculateNetworkTax(network, amount) {
        const config = NETWORK_CONFIG[network];
        if (!config) return 30; // Default tax
        
        // Find the appropriate tax rate based on amount
        let tax = 30; // Default
        const sortedThresholds = Object.keys(config.taxRates).map(Number).sort((a, b) => b - a);
        
        for (const threshold of sortedThresholds) {
            if (amount >= threshold) {
                tax = config.taxRates[threshold];
                break;
            }
        }
        
        return tax;
    }

    // Update tax rate info display
    function updateTaxRateInfo() {
        const taxRateInfo = document.getElementById('taxRateInfo');
        if (!taxRateInfo || !selectedNetwork) return;
        
        const config = NETWORK_CONFIG[selectedNetwork];
        taxRateInfo.innerHTML = '<ul style="margin: 0; padding-left: 20px;">';
        
        const thresholds = Object.keys(config.taxRates).map(Number).sort((a, b) => a - b);
        thresholds.forEach((threshold, index) => {
            const nextThreshold = thresholds[index + 1];
            const rate = config.taxRates[threshold];
            
            if (selectedNetwork === 'Backbone') {
                if (nextThreshold) {
                    taxRateInfo.innerHTML += `<li>${threshold}-${nextThreshold - 1} ${config.delegationToken} = ${rate}% tax</li>`;
                } else {
                    taxRateInfo.innerHTML += `<li>${threshold}+ ${config.delegationToken} = ${rate}% tax</li>`;
                }
            } else if (selectedNetwork === 'KelVPN') {
                if (threshold === 400) {
                    taxRateInfo.innerHTML += `<li>${threshold}-799 ${config.delegationToken} = ${rate}% tax</li>`;
                } else {
                    taxRateInfo.innerHTML += `<li>${threshold} ${config.delegationToken} = ${rate}% tax</li>`;
                }
            }
        });
        
        taxRateInfo.innerHTML += '</ul>';
    }

    // Record delegation in DNA profile - now using CpunkUtils
    async function recordDelegation(walletAddress, txHash, orderHash, network, amount, taxRate) {
        try {
            CpunkUtils.logDebug('Recording delegation to DNA profile', 'info', {
                walletAddress, txHash, orderHash, network, amount, taxRate
            });
            
            const result = await CpunkUtils.recordDelegation({
                walletAddress: walletAddress,
                txHash: txHash,
                orderHash: orderHash,
                network: network,
                amount: amount,
                taxRate: taxRate
            });
            
            CpunkUtils.logDebug('Delegation record result', 'response', { result });
            return result;
        } catch (error) {
            CpunkUtils.logDebug('Error recording delegation', 'error', {
                error: error.message,
                params: { walletAddress, txHash, orderHash, network, amount, taxRate }
            });
            return false;
        }
    }

    // Show verification section with improved UI
    function showVerificationSection(txHash, orderHash) {
        // Store current transaction hash and order hash
        currentTxHash = txHash;
        currentOrderHash = orderHash;

        // Create verification UI using CpunkUI utility if available
        const verificationUI = CpunkUI.createVerificationUI(txHash, orderHash);
        
        // Insert the verification UI into the page
        if (verificationUI && verificationSection) {
            verificationSection.innerHTML = '';
            verificationSection.appendChild(verificationUI);
            
            // Re-acquire new DOM elements after UI recreation
            if (document.getElementById('retry-verification-button')) {
                document.getElementById('retry-verification-button').addEventListener('click', () => {
                    retestVerification(txHash);
                });
            }
        } else {
            // Fallback to manual UI creation
            // Important warning about not closing the page
            const pageWarning = `
                <div class="verification-warning" style="background-color: rgba(255, 187, 51, 0.2); border: 2px solid #ffbb33; padding: 12px; margin-bottom: 15px; border-radius: 5px; text-align: center;">
                    <strong>⚠️ IMPORTANT:</strong> Please do not close this page while verification is in progress. 
                    Closing the page may interrupt the verification process.
                </div>
            `;

            // Update transaction hash display
            if (txHashDisplay) {
                txHashDisplay.innerHTML = `
                    ${pageWarning}
                    <div class="tx-hash-label">Transaction Hash:</div>
                    <div class="tx-hash-value">${txHash}</div>
                    <button class="copy-button" onclick="CpunkUI.copyHash('${txHash}', this)">
                        <span class="copy-icon">📋</span> Copy
                    </button>
                `;
            }

            // Update order hash display
            if (orderHashDisplay) {
                orderHashDisplay.innerHTML = `
                    <div class="tx-hash-label">Order Hash:</div>
                    <div class="tx-hash-value">${orderHash}</div>
                    <button class="copy-button" onclick="CpunkUI.copyHash('${orderHash}', this)">
                        <span class="copy-icon">📋</span> Copy
                    </button>
                `;
            }

            // Initialize verification status
            if (verificationStatus) {
                verificationStatus.innerHTML = `
                    <div class="status-heading">Verification Pending</div>
                    <div class="status-description">
                        We need to verify your transaction before finalizing the delegation.
                        This process may take a few moments.
                    </div>
                `;
            }

            // Reset progress bar
            if (progressFill) {
                progressFill.style.width = '0%';
            }

            // Show details about the verification process
            if (verificationDetails) {
                verificationDetails.innerHTML = `
                    <ul class="verification-steps">
                        <li><span class="step-number">1</span> Transaction submitted</li>
                        <li class="current-step"><span class="step-number">2</span> Verification in progress</li>
                        <li><span class="step-number">3</span> Delegation confirmation</li>
                    </ul>
                    <div class="verification-note">
                        <span class="note-icon">ℹ️</span>
                        The verification will automatically run multiple times.
                        If it fails, you can manually retest using the button below.
                    </div>
                `;
            }
        }

        // Hide delegation form
        delegationForm.style.display = 'none';

        // Show verification section
        verificationSection.style.display = 'block';

        // Start verification process using CpunkTransaction
        CpunkTransaction.startVerification({
            txHash: txHash,
            onVerificationStart: (txHash) => {
                // Update verification status
                CpunkUI.updateVerificationUI('pending', {
                    statusElement: verificationStatus,
                    progressElement: progressFill,
                    detailsElement: verificationDetails
                });
            },
            onVerificationAttempt: (attempt, maxAttempts) => {
                // Update verification progress
                CpunkUI.updateVerificationUI('progress', {
                    attempt: attempt,
                    maxAttempts: maxAttempts,
                    statusElement: verificationStatus,
                    progressElement: progressFill,
                    detailsElement: verificationDetails
                });
            },
            onVerificationSuccess: async (txHash, attempt) => {
                // Record delegation in DNA profile after successful verification
                const recordingSuccess = await recordDelegation(
                    delegationRewardsAddress,
                    txHash,
                    currentOrderHash,
                    selectedNetwork,
                    delegationAmountValue,
                    calculateNetworkTax(selectedNetwork, delegationAmountValue)
                );

                CpunkUtils.logDebug("Delegation record success:", 'info', { recordingSuccess });

                // Success! Update UI and finish
                CpunkUI.updateVerificationUI('success', {
                    statusElement: verificationStatus,
                    progressElement: progressFill,
                    detailsElement: verificationDetails,
                    retryElement: retestVerificationButton
                });

                // Hide verification section after successful completion
                verificationSection.style.display = 'none';

                // Show delegation success with copyable message format
                delegationForm.style.display = 'block';
                successMessage.style.display = 'block';
                successMessage.innerHTML = `
                    <h3>Delegation Successful! ✅</h3>
                    <p>Your transaction has been verified and your delegation is now active.</p>
                    <div class="hash-info">
                        <div class="hash-row">
                            <span class="hash-label">Transaction Hash:</span>
                            <code>${txHash}</code>
                        </div>
                        <div class="hash-row">
                            <span class="hash-label">Order Hash:</span>
                            <code>${currentOrderHash}</code>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 15px; background-color: var(--section-bg); border-radius: 8px; border: 1px dashed var(--primary);">
                        <h4 style="color: var(--primary); margin-top: 0;">🔹 Required Activation Step:</h4>
                        <p>Please copy the message below and post it in our <a href="https://web.telegram.org/k/#@chippunk_official" target="_blank" style="color: var(--primary);">Telegram channel</a> for delegation support to activate your rewards:</p>
                        
                        <div id="copyableMessage" style="background-color: rgba(0,0,0,0.2); padding: 15px; border-radius: 6px; margin: 10px 0; font-family: monospace; white-space: pre-wrap;">Delegation Completed ✅
Transaction Hash: ${txHash}
Order Hash: ${currentOrderHash}
Please activate my rewards.</div>
                        
                        <button onclick="copyDelegationMessage()" class="copy-button" style="display: block; margin: 10px auto; width: auto; padding: 8px 15px;">
                            <span class="copy-icon">📋</span> Copy Message for Telegram
                        </button>
                    </div>
                `;
                
                // Keep the button disabled and change text to indicate completed verification
                submitDelegation.disabled = true;
                submitDelegation.textContent = 'Delegation Complete';
            },
            onVerificationFail: (txHash, attempts, error) => {
                // Last attempt failed
                CpunkUI.updateVerificationUI('failed', {
                    statusElement: verificationStatus,
                    progressElement: progressFill,
                    detailsElement: verificationDetails,
                    retryElement: retestVerificationButton
                });
                
                // Change the submit button to retry verification instead
                submitDelegation.disabled = false;
                submitDelegation.textContent = 'Retry Verification';
                // Replace the click handler completely
                submitDelegation.onclick = function() {
                    retestVerification(txHash);
                };
            }
        });
    }

    // Manually retest transaction verification
    async function retestVerification(txHash) {
        if (!txHash) {
            return false;
        }

        try {
            // Update UI to show testing
            CpunkUI.updateVerificationUI('progress', {
                attempt: 1,
                maxAttempts: 1,
                statusElement: verificationStatus,
                progressElement: progressFill,
                detailsElement: verificationDetails
            });

            // Try to verify using CpunkTransaction
            const verified = await CpunkTransaction.verifyTransaction(txHash);

            if (verified) {
                // Record delegation in DNA profile after successful verification
                const recordingSuccess = await recordDelegation(
                    delegationRewardsAddress,
                    txHash,
                    currentOrderHash,
                    selectedNetwork,
                    delegationAmountValue,
                    calculateNetworkTax(selectedNetwork, delegationAmountValue)
                );

                CpunkUtils.logDebug("Manual verification record success:", 'info', { recordingSuccess });

                // Success!
                CpunkUI.updateVerificationUI('success', {
                    statusElement: verificationStatus,
                    progressElement: progressFill,
                    detailsElement: verificationDetails,
                    retryElement: retestVerificationButton
                });

                // Hide verification section after successful completion
                verificationSection.style.display = 'none';

                // Show delegation success with copyable message format
                delegationForm.style.display = 'block';
                successMessage.style.display = 'block';
                successMessage.innerHTML = `
                    <h3>Delegation Successful! ✅</h3>
                    <p>Your transaction has been verified and your delegation is now active.</p>
                    <div class="hash-info">
                        <div class="hash-row">
                            <span class="hash-label">Transaction Hash:</span>
                            <code>${txHash}</code>
                        </div>
                        <div class="hash-row">
                            <span class="hash-label">Order Hash:</span>
                            <code>${currentOrderHash}</code>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 15px; background-color: var(--section-bg); border-radius: 8px; border: 1px dashed var(--primary);">
                        <h4 style="color: var(--primary); margin-top: 0;">🔹 Required Activation Step:</h4>
                        <p>Please copy the message below and post it in our <a href="https://web.telegram.org/k/#@chippunk_official" target="_blank" style="color: var(--primary);">Telegram channel</a> for delegation support to activate your rewards:</p>
                        
                        <div id="copyableMessage" style="background-color: rgba(0,0,0,0.2); padding: 15px; border-radius: 6px; margin: 10px 0; font-family: monospace; white-space: pre-wrap;">Delegation Completed ✅
Transaction Hash: ${txHash}
Order Hash: ${currentOrderHash}
Please activate my rewards.</div>
                        
                        <button onclick="copyDelegationMessage()" class="copy-button" style="display: block; margin: 10px auto; width: auto; padding: 8px 15px;">
                            <span class="copy-icon">📋</span> Copy Message for Telegram
                        </button>
                    </div>
                `;
                
                // Change submit button to indicate completion
                submitDelegation.disabled = true;
                submitDelegation.textContent = 'Delegation Complete';
            } else {
                // Still not verified
                CpunkUI.updateVerificationUI('failed', {
                    statusElement: verificationStatus,
                    progressElement: progressFill,
                    detailsElement: verificationDetails,
                    retryElement: retestVerificationButton
                });
                
                // Update submit button to retry verification
                submitDelegation.disabled = false;
                submitDelegation.textContent = 'Retry Verification';
                // Replace the click handler completely
                submitDelegation.onclick = function() {
                    retestVerification(txHash);
                };
            }

            return verified;
        } catch (error) {
            CpunkUI.updateVerificationUI('error', {
                statusElement: verificationStatus,
                progressElement: progressFill,
                detailsElement: verificationDetails,
                retryElement: retestVerificationButton
            });
            
            // Update submit button to retry verification
            submitDelegation.disabled = false;
            submitDelegation.textContent = 'Retry Verification';
            submitDelegation.onclick = () => retestVerification(txHash);
            
            return false;
        }
    }

    // Check if address is registered in DNA using CpunkUtils
    async function checkDnaRegistration(address) {
        try {
            CpunkUtils.logDebug(`Checking DNA registration for address: ${address}`, 'info');
            
            // Use CpunkUtils to check DNA registration
            const result = await CpunkUtils.checkDnaRegistration(address);
            
            // Display the result to the user
            if (result.isRegistered) {
                const nicknames = result.names;
                
                // For DNA selection, always use the dedicated selection box
                const dnaSelectionContainer = document.getElementById('dnaSelectionContainer');
                const dnaSelect = document.getElementById('dnaSelect');

                if (dnaSelectionContainer && dnaSelect) {
                    // Clear existing options
                    dnaSelect.innerHTML = '';

                    // Add options for each nickname
                    nicknames.forEach(name => {
                        const option = document.createElement('option');
                        option.value = name;
                        option.textContent = name;
                        dnaSelect.appendChild(option);
                    });

                    // Show the selection container
                    dnaSelectionContainer.style.display = 'block';

                    // Set status message to show how many DNAs were found
                    dnaStatus.innerHTML = `<span style="color: #00C851;">✓ Found ${nicknames.length} registered DNA nickname${nicknames.length > 1 ? 's' : ''}</span>`;
                } else {
                    // If the selection container is not available, just show the status
                    dnaStatus.innerHTML = `<span style="color: #00C851;">✓ Registered as: <strong>${nicknames[0]}</strong></span>`;
                }

                dnaStatus.style.display = 'block';
                return true;
            } else {
                // Address is not registered
                dnaStatus.innerHTML = `<span style="color: #ff4444;">✗ Not registered in DNA. Please <a href="register.html" style="color: #f97834; text-decoration: underline;">register your DNA</a> first.</span>`;
                dnaStatus.style.display = 'block';
                return false;
            }
        } catch (error) {
            CpunkUtils.logDebug('Error checking DNA registration', 'error', {
                address: address,
                error: error.message,
                stack: error.stack
            });
            
            dnaStatus.innerHTML = `<span style="color: #ffbb33;">! Unable to verify DNA registration. Error: ${error.message}</span>`;
            dnaStatus.style.display = 'block';
            return false;
        }
    }

    async function validateForm() {
        let isValid = true;

        // Validate rewards address
        const address = rewardsAddress.value.trim();
        if (!address) {
            rewardsAddressError.textContent = 'Rewards address is required';
            rewardsAddressError.style.display = 'block';
            rewardsAddress.classList.add('invalid');
            isValid = false;
        } else if (address.length < 30) { // Simple validation for address length
            rewardsAddressError.textContent = 'Please enter a valid address';
            rewardsAddressError.style.display = 'block';
            rewardsAddress.classList.add('invalid');
            isValid = false;
        } else {
            rewardsAddressError.style.display = 'none';
            rewardsAddress.classList.remove('invalid');

            // Check DNA registration if the address appears valid
            if (address.length >= 30) {
                const isDnaRegistered = await checkDnaRegistration(address);
                if (!isDnaRegistered) {
                    isValid = false;
                }
            }
        }

        // Validate delegation amount
        const amount = parseFloat(delegationAmount.value);
        const config = selectedNetwork ? NETWORK_CONFIG[selectedNetwork] : null;
        
        if (isNaN(amount) || amount <= 0) {
            delegationAmountError.textContent = 'Please enter a valid amount';
            delegationAmountError.style.display = 'block';
            delegationAmount.classList.add('invalid');
            isValid = false;
        } else if (config && amount < config.minDelegation) {
            delegationAmountError.textContent = `Minimum delegation amount is ${config.minDelegation} ${config.delegationToken}`;
            delegationAmountError.style.display = 'block';
            delegationAmount.classList.add('invalid');
            isValid = false;
        } else if (config && amount > config.maxDelegation) {
            delegationAmountError.textContent = `Maximum delegation amount is ${config.maxDelegation} ${config.delegationToken}`;
            delegationAmountError.style.display = 'block';
            delegationAmount.classList.add('invalid');
            isValid = false;
        } else if (amount > availableBalance) {
            delegationAmountError.textContent = 'Amount exceeds available balance';
            delegationAmountError.style.display = 'block';
            delegationAmount.classList.add('invalid');
            isValid = false;
        } else {
            delegationAmountError.style.display = 'none';
            delegationAmount.classList.remove('invalid');
        }

        submitDelegation.disabled = !isValid;
        return isValid;
    }

    function updateBalanceWarning() {
        const amount = parseFloat(delegationAmount.value);
        if (!isNaN(amount) && amount > 0) {
            if (amount > availableBalance) {
                balanceWarning.textContent = `Warning: Amount exceeds available balance of ${CpunkUtils.formatBalance(availableBalance)} mCELL`;
                balanceWarning.style.display = 'block';
            } else if (availableBalance - amount < 0.0001) {
                balanceWarning.textContent = `Warning: You should have at least 0.0001 mCELL remaining for transaction fees`;
                balanceWarning.style.display = 'block';
            } else {
                balanceWarning.style.display = 'none';
            }
        } else {
            balanceWarning.style.display = 'none';
        }
    }

    // Dashboard Interaction Functions - replaced by SSO authentication
    // connectToDashboard function removed as authentication is handled by SSO

    // Show network selection
    function showNetworkSelection() {
        networkSection.style.display = 'block';
        networksList.innerHTML = '';

        // Create network cards
        Object.keys(NETWORK_CONFIG).forEach(network => {
            const config = NETWORK_CONFIG[network];
            const networkCard = document.createElement('div');
            networkCard.className = 'wallet-card';
            networkCard.style.cursor = 'pointer';
            networkCard.innerHTML = `
                <div class="wallet-card-header">
                    <h4 style="margin: 0; color: var(--primary);">${network}</h4>
                </div>
                <div style="margin-top: 10px;">
                    <div class="wallet-balance">
                        <span class="token-name">Min ${config.delegationToken}:</span>
                        <span class="token-balance">${config.minDelegation}</span>
                    </div>
                    <div class="wallet-balance">
                        <span class="token-name">Max ${config.delegationToken}:</span>
                        <span class="token-balance">${config.maxDelegation}</span>
                    </div>
                    <div class="wallet-balance">
                        <span class="token-name">Fee (${config.feeToken}):</span>
                        <span class="token-balance">${config.minFee}</span>
                    </div>
                </div>
            `;

            networkCard.addEventListener('click', () => {
                selectedNetwork = network;
                showNetworkRequirements(network);
                loadWallets();
            });

            networksList.appendChild(networkCard);
        });
    }

    // Show network-specific requirements
    function showNetworkRequirements(network) {
        const config = NETWORK_CONFIG[network];
        const requirementsDiv = document.getElementById('networkRequirements');
        const requirementsList = document.getElementById('networkRequirementsList');
        
        if (requirementsDiv && requirementsList) {
            requirementsList.innerHTML = `
                <li>Minimum ${config.minDelegation} ${config.delegationToken} required for delegation</li>
                <li>Maximum ${config.maxDelegation} ${config.delegationToken} can be delegated</li>
                <li>Minimum ${config.minFee} ${config.feeToken} required for transaction fees</li>
                <li>Tax rates: ${Object.entries(config.taxRates).map(([threshold, rate]) => 
                    `${threshold} ${config.delegationToken} = ${rate}%`).join(', ')}</li>
            `;
            requirementsDiv.style.display = 'block';
        }
    }

    async function loadWallets() {
        try {
            if (!selectedNetwork) {
                CpunkUtils.logDebug('No network selected', 'error');
                return;
            }

            // For SSO authentication, we don't need to show wallet selection
            // Use the authenticated wallet directly
            walletsSection.style.display = 'none';
            
            const config = NETWORK_CONFIG[selectedNetwork];
            
            // Check if address is registered in DNA before showing delegation form
            const isDnaRegistered = await checkDnaRegistration(walletAddress);

            if (isDnaRegistered) {
                // Show the delegation form
                delegationForm.style.display = 'block';

                // Pre-fill rewards address with wallet address
                rewardsAddress.value = walletAddress;

                // Store the rewards address for later use in delegation recording
                delegationRewardsAddress = walletAddress;

                // Update selected wallet display
                selectedWalletDisplay.textContent = `${currentDna} - Wallet: ${walletAddress.substring(0, 10)}...${walletAddress.substring(walletAddress.length - 10)}`;

                // Update balance warning based on amount
                updateBalanceWarning();

                // Validate the form
                validateForm();
                
                // Update tax rate info display
                updateTaxRateInfo();
                
                // Update delegation help text
                const delegationHelpText = document.getElementById('delegationHelpText');
                if (delegationHelpText) {
                    delegationHelpText.textContent = `Minimum: ${config.minDelegation} ${config.delegationToken}, Maximum: ${config.maxDelegation} ${config.delegationToken}`;
                }
            } else {
                // Show DNA registration message but hide the form
                delegationForm.style.display = 'none';

                // Show prominent registration message
                errorMessage.innerHTML = `
                    <strong>DNA Registration Required</strong><br>
                    Your address ${walletAddress.substring(0, 10)}...${walletAddress.substring(walletAddress.length - 10)}
                    is not registered in the DNA system.<br><br>
                    <a href="register.html" style="display: inline-block; padding: 10px 20px; background-color: #f97834; color: white; text-decoration: none; border-radius: 5px; margin-top: 10px;">
                        Register DNA Now
                    </a>
                `;
                errorMessage.style.display = 'block';
            }
            
            return;
            
            // Old wallet loading code removed - no longer needed with SSO

                    wallet.details.forEach(networkData => {
                        // Check if wallet is on selected network
                        if (networkData.network !== selectedNetwork) return;

                        // Get tokens based on network
                        const delegationToken = networkData.tokens.find(token => token.tokenName === config.delegationToken);
                        const feeToken = networkData.tokens.find(token => token.tokenName === config.feeToken);
                        
                        if (!delegationToken || !feeToken) return;

                        const delegationBalance = parseFloat(delegationToken.balance);
                        const feeBalance = parseFloat(feeToken.balance);
                        
                        // Check minimum balances
                        if (delegationBalance < config.minDelegation || feeBalance < config.minFee) return;
                        
                        validWalletsCount++;
                        
                        // Create wallet object for CpunkUI
                        const walletObj = {
                            name: wallet.name,
                            network: networkData.network,
                            address: networkData.address,
                            tokens: [
                                { tokenName: config.delegationToken, balance: delegationBalance },
                                { tokenName: config.feeToken, balance: feeBalance }
                            ]
                        };
                        
                        // Create wallet card using CpunkUI
                        const walletCard = CpunkUI.createWalletCard(walletObj, async (selectedWalletObj) => {
                            // Update selected wallet info
                            selectedWallet = selectedWalletObj.name;
                            availableBalance = delegationBalance;

                            // Update the wallet display
                            selectedWalletDisplay.textContent = `${selectedWalletObj.name} (${selectedWalletObj.network}) - Balance: ${CpunkUtils.formatBalance(delegationBalance)} ${config.delegationToken}`;

                            // Check if address is registered in DNA before showing delegation form
                            const isDnaRegistered = await checkDnaRegistration(networkData.address);

                            if (isDnaRegistered) {
                                // Show the delegation form
                                delegationForm.style.display = 'block';

                                // Pre-fill rewards address with wallet address
                                rewardsAddress.value = networkData.address;

                                // Store the rewards address for later use in delegation recording
                                delegationRewardsAddress = networkData.address;

                                // Update balance warning based on amount
                                updateBalanceWarning();

                                // Validate the form
                                validateForm();
                                
                                // Reset submit button to original state in case it was changed
                                submitDelegation.textContent = 'Submit Delegation';
                                submitDelegation.onclick = originalSubmitHandler;
                                
                                // Update tax rate info display
                                updateTaxRateInfo();
                                
                                // Update delegation help text
                                const delegationHelpText = document.getElementById('delegationHelpText');
                                if (delegationHelpText) {
                                    delegationHelpText.textContent = `Minimum: ${config.minDelegation} ${config.delegationToken}, Maximum: ${config.maxDelegation} ${config.delegationToken}`;
                                }
                            } else {
                                // Show DNA registration message but hide the form
                                delegationForm.style.display = 'none';

                                // Show prominent registration message
                                errorMessage.innerHTML = `
                                    <strong>DNA Registration Required</strong><br>
                                    Your address ${networkData.address.substring(0, 10)}...${networkData.address.substring(networkData.address.length - 10)}
                                    is not registered in the DNA system.<br><br>
                                    <a href="register.html" style="display: inline-block; padding: 10px 20px; background-color: #f97834; color: white; text-decoration: none; border-radius: 5px; margin-top: 10px;">
                                        Register DNA Now
                                    </a>
                                `;
                                errorMessage.style.display = 'block';
                            }
                        });

                        walletsList.appendChild(walletCard);
                    });
                });

                if (validWalletsCount === 0) {
                    walletsList.innerHTML = `
                        <div style="padding: 15px; background-color: #2b1816; border-radius: 5px; text-align: center;">
                            <p>No wallets with sufficient balance found on ${selectedNetwork} network.</p>
                            <p>Please ensure you have:</p>
                            <ul style="list-style: none; padding: 0; margin: 10px 0;">
                                <li>• At least ${config.minDelegation} ${config.delegationToken}</li>
                                <li>• At least ${config.minFee} ${config.feeToken} for fees</li>
                            </ul>
                        </div>
                    `;
                }
            }
        } catch (error) {
            CpunkUtils.logDebug('Error loading wallet list', 'error', {
                message: error.message,
                stack: error.stack
            });
            
            walletsList.innerHTML = `
                <div style="padding: 15px; background-color: #2b1816; border-radius: 5px; text-align: center; color: #ff4444;">
                    <p>Error loading wallets: ${error.message}</p>
                </div>
            `;
        }
    }

    async function getWalletData(walletName) {
        try {
            CpunkUtils.logDebug(`Fetching wallet data for: ${walletName}`, 'info');
            
            return await CpunkUtils.dashboardRequest('GetDataWallet', {
                id: sessionId,
                walletName: walletName
            });
        } catch (error) {
            CpunkUtils.logDebug(`Error fetching wallet data for ${walletName}`, 'error', {
                message: error.message,
                stack: error.stack
            });
            return null;
        }
    }

    async function handleDelegationSubmission() {
        if (!await validateForm()) return;

        try {
            // Reset UI
            submitDelegation.disabled = true;
            submitDelegation.innerHTML = '<span class="loading-spinner"></span>Processing...';
            errorMessage.style.display = 'none';
            successMessage.style.display = 'none';

            const amount = parseFloat(delegationAmount.value);
            const tax = calculateNetworkTax(selectedNetwork, amount);

            // Store these values for later use in recordDelegation
            delegationRewardsAddress = rewardsAddress.value.trim();
            delegationAmountValue = amount;

            // Format the value as datoshi
            // For integers (like 1), format as "1.0e+18"
            // For non-integers (like 0.01), format as "0.01e+18"
            const formattedAmount = Number.isInteger(amount)
                ? `${amount.toFixed(1)}e+18`
                : `${amount}e+18`;

            // Build the request parameters
            // The tax rate for the API needs to be (100 - taxRate)
            const apiTaxRate = (100 - tax).toFixed(1);
            
            CpunkUtils.logDebug('Creating staking order', 'info', {
                walletName: selectedWallet,
                network: selectedNetwork,
                value: formattedAmount,
                tax: apiTaxRate
            });

            // Call the CreateOrderStaker API using CpunkTransaction
            // For SSO authentication, we'll need to use a different approach
            // since we don't have a wallet name from the dashboard
            const result = await CpunkTransaction.createStakingOrder({
                walletAddress: walletAddress, // Use wallet address instead of name
                network: selectedNetwork,
                value: formattedAmount,
                tax: apiTaxRate
            });

            if (result.success) {
                CpunkUtils.logDebug("Delegation order created:", 'info', {
                    orderHash: result.orderHash,
                    txHash: result.txHash
                });

                // Show verification section with both hashes
                showVerificationSection(result.txHash, result.orderHash);
                
                // Keep the button disabled permanently
                submitDelegation.disabled = true;
            } else {
                throw new Error('Failed to create delegation order');
            }
        } catch (error) {
            CpunkUtils.logDebug('Delegation submission error', 'error', {
                error: error.message,
                stack: error.stack
            });
            
            CpunkUI.showError(`Error: ${error.message}`);
            
            // Only re-enable the button if there's an error
            submitDelegation.disabled = false;
            submitDelegation.textContent = 'Submit Delegation';
        }
        // Note: No "finally" block with button reset - we want the button to stay disabled on success
    }

    // Copy delegation message to clipboard
    window.copyDelegationMessage = function() {
        const messageDiv = document.getElementById('copyableMessage');
        if (!messageDiv) return;
        
        const text = messageDiv.textContent;
        
        CpunkUtils.copyToClipboard(text, 
            // Success callback
            () => {
                const copyButton = document.querySelector('button.copy-button');
                if (copyButton) {
                    const originalText = copyButton.innerHTML;
                    copyButton.innerHTML = '<span class="copy-icon">✓</span> Copied! Ready to paste in Telegram';
                    
                    setTimeout(() => {
                        copyButton.innerHTML = originalText;
                    }, 3000);
                }
                
                // Highlight the message div to give visual feedback
                messageDiv.style.backgroundColor = 'rgba(0, 200, 81, 0.1)';
                setTimeout(() => {
                    messageDiv.style.backgroundColor = 'rgba(0,0,0,0.2)';
                }, 1000);
                
                // Open Telegram in a new tab
                window.open('https://web.telegram.org/k/#@chippunk_official', '_blank');
            },
            // Error callback
            () => {
                alert('Failed to copy message. Please try selecting and copying it manually.');
            }
        );
    };

    // Copy text to clipboard
    window.copyToClipboard = function(text, buttonElement) {
        CpunkUtils.copyToClipboard(text,
            // Success callback
            () => {
                const originalText = buttonElement.textContent;
                buttonElement.innerHTML = '<span class="copy-icon">✓</span> Copied!';
                
                setTimeout(() => {
                    buttonElement.innerHTML = '<span class="copy-icon">📋</span> Copy';
                }, 2000);
            },
            // Error callback
            () => {
                alert('Failed to copy. Please try again.');
            }
        );
    };
});