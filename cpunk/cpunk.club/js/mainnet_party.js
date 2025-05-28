/**
 * CPUNK Mainnet Birthday Bash JavaScript
 * Handles SSO authentication, dashboard connection, DNA lookup, and reservation processing
 */

// API Configuration
const TREASURY_WALLET = 'Rj7J7MiX2bWy8sNyZcoLqkZuNznvU4KbK6RHgqrGj9iqwKPhoVKE1xNrEMmgtVsnyTZtFhftMPAJbaswuSLp7UeBS7jiRmE5uvuUJaKA';
const RESERVATION_AMOUNT = 1000000; // 1,000,000 CPUNK on Backbone network
const MIN_WALLET_BALANCE = 1000000; // Minimum 1,000,000 CPUNK required in the wallet

// State variables
let sso = null;
let sessionId = null;
let selectedWallet = null;
let walletAddress = null;
let dnaData = null;
let selectedDnaNickname = null; // Track the selected DNA nickname
let attendeesList = [];
let validatedCode = null; // Store validated invitation code

// DOM Elements - will be initialized after DOM loads
let reservationInfo = null;
let loginRequiredSection = null;
let loginBtn = null;
let statusIndicator = null;
let walletSection = null;
let walletsList = null;
let continueButton = null;
let walletError = null;
let dnaSection = null;
let dnaStatus = null;
let dnaError = null;
let dnaSelectionList = null;
let dnaDetails = null;
let profileAvatar = null;
let profileNickname = null;
let profileNicknames = null;
let reserveButton = null;
let txSection = null;
let txStatus = null;
let txError = null;
let txSuccess = null;
let confirmationSection = null;
let reservedByDna = null;
let reservationTxId = null;
let attendeesListElement = null;

// Invitation Code Elements - will be initialized after DOM loads
let toggleInvitationButton = null;
let invitationCodeSection = null;
let invitationCodeInput = null;
let validateCodeButton = null;
let codeStatus = null;
let validCodeDetails = null;
let codeType = null;
let codeDescription = null;
let redeemCodeButton = null;

// Countdown Elements - will be initialized after DOM loads
let daysElement = null;
let hoursElement = null;
let minutesElement = null;
let secondsElement = null;

/**
 * Dashboard API Connection Functions
 */
async function makeRequest(method, params = {}) {
    // Log API request if console is available
    if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
        CpunkAPIConsole.log(`Dashboard API Request: ${method}`, { 
            method: method,
            params: params,
            type: 'dashboard_api'
        });
    }
    
    // Use CpunkUtils dashboardRequest if available, otherwise make direct request
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dashboardRequest) {
        try {
            const result = await CpunkUtils.dashboardRequest(method, params);
            
            // Log API response if console is available
            if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                CpunkAPIConsole.log(`Dashboard API Response: ${method}`, { 
                    status: result.status,
                    data: result.data,
                    error: result.errorMsg
                });
            }
            
            return result;
        } catch (error) {
            // Log API error if console is available
            if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                CpunkAPIConsole.log(`Dashboard API Error: ${method}`, { 
                    error: error.message,
                    stack: error.stack
                });
            }
            throw error;
        }
    }
    
    const API_URL = 'http://localhost:8045/';
    const url = new URL(API_URL);
    url.searchParams.append('method', method);

    for (const [key, value] of Object.entries(params)) {
        url.searchParams.append(key, value);
    }

    try {
        const response = await fetch(url.toString());
        if (!response.ok) {
            throw new Error(`Dashboard API error: ${response.status}`);
        }

        const result = await response.json();
        
        // Log API response if console is available
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log(`Dashboard API Response: ${method}`, { 
                status: result.status,
                data: result.data,
                error: result.errorMsg
            });
        }
        
        return result;
    } catch (error) {
        // Log API error if console is available
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log(`Dashboard API Error: ${method}`, { 
                error: error.message,
                stack: error.stack
            });
        }
        console.error('Dashboard request error:', error);
        throw error;
    }
}

// Update dashboard status display
function updateStatus(status, message = '') {
    if (!statusIndicator) return;
    
    if (typeof CpunkUI !== 'undefined' && CpunkUI.updateConnectionStatus) {
        if (status === 'connected' && selectedWallet && selectedWallet.name) {
            CpunkUI.updateConnectionStatus(status, `${selectedWallet.name} Connected`);
        } else {
            CpunkUI.updateConnectionStatus(status, message || status);
        }
    } else {
        // Fallback to direct DOM manipulation
        if (status === 'connected' && selectedWallet && selectedWallet.name) {
            // Format as "Dashboard Status: $WalletName Connected"
            statusIndicator.className = 'status-indicator status-connected';
            statusIndicator.textContent = `${selectedWallet.name} Connected`;
        } else {
            statusIndicator.className = 'status-indicator status-' + status;
            statusIndicator.textContent = message || status;
        }
    }
}

// Get SSO session ID for dashboard operations
function getSessionId() {
    if (sso) {
        return sso.getSessionId();
    }
    return null;
}

// Removed - wallet selection handled by SSO

// Removed - no longer need wallet selection with SSO

/**
 * DNA Registration Functions
 */

// This function is no longer needed - SSO provides DNA information

// This function is no longer needed - SSO provides single selected DNA

// This function is no longer needed - SSO ensures user has DNA

// These functions are no longer needed - SSO provides DNA information

// Check if DNA is already registered for the event
async function checkExistingReservation(dnaName) {
    try {
        // Use the new check_reservation endpoint we implemented
        const DNA_API_URL = 'dna-proxy.php';
        const requestUrl = `${DNA_API_URL}?action=check_reservation&dna=${encodeURIComponent(dnaName)}&wallet=${encodeURIComponent(walletAddress)}`;
        
        // Log using API Console if available
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log('Reservation Check API Request', { 
                url: requestUrl,
                dna: dnaName,
                wallet: walletAddress,
                type: 'dna_api'
            });
        }
        // Also log using CpunkUtils if available (for backward compatibility)
        else if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug(`Checking reservation status for ${dnaName}`, 'request', { 
                url: requestUrl,
                wallet: walletAddress
            });
        } else {
            console.log(`Checking reservation status for ${dnaName} (wallet: ${walletAddress})`, requestUrl);
        }
        
        const response = await fetch(requestUrl);
        
        if (!response.ok) {
            // Log API response if not OK
            if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                CpunkAPIConsole.log('Reservation Check API Response (Error)', { 
                    status: response.status,
                    statusText: response.statusText,
                    type: 'dna_api'
                });
            }
            else if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
                CpunkUtils.logDebug('Reservation check returned non-200 status', 'warning', { 
                    status: response.status, 
                    statusText: response.statusText 
                });
            } else {
                console.log('Reservation check returned non-200 status, assuming not reserved');
            }
            return;
        }
        
        const data = await response.json();
        
        // Log API response
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log('Reservation Check API Response', { 
                status: response.status,
                data: data,
                type: 'dna_api'
            });
        }
        else if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Reservation check response', 'response', { data });
        } else {
            console.log('Reservation check response:', data);
        }

        // Check if this wallet already has a reservation
        if (data.wallet_reserved) {
            // Update reservation info to show confirmed status
            if (reservationInfo) {
                reservationInfo.innerHTML = '🎉 <span class="highlight">Reservation Confirmed!</span> You\'re all set for the Cellframe Mainnet Birthday Bash.';
            }
            
            // Wallet already has a reservation - just show profile
            dnaDetails.innerHTML = `
                <div class="profile-preview">
                    <div class="profile-header">
                        <div class="profile-avatar" id="profileAvatar">${profileAvatar.textContent}</div>
                        <div class="profile-info">
                            <div class="profile-nickname" id="profileNickname">${profileNickname.textContent}</div>
                            <div class="nickname-tags" id="profileNicknames">${profileNicknames.innerHTML}</div>
                        </div>
                    </div>
                </div>
            `;
            // Hide the reserve button
            reserveButton.style.display = 'none';
        }
        // Check if this specific DNA is already registered
        else if (data.reserved) {
            // Update reservation info to show confirmed status
            if (reservationInfo) {
                reservationInfo.innerHTML = '🎉 <span class="highlight">Reservation Confirmed!</span> You\'re all set for the Cellframe Mainnet Birthday Bash.';
            }
            
            // DNA already reserved - just show profile
            dnaDetails.innerHTML = `
                <div class="profile-preview">
                    <div class="profile-header">
                        <div class="profile-avatar" id="profileAvatar">${profileAvatar.textContent}</div>
                        <div class="profile-info">
                            <div class="profile-nickname" id="profileNickname">${profileNickname.textContent}</div>
                            <div class="nickname-tags" id="profileNicknames">${profileNicknames.innerHTML}</div>
                        </div>
                    </div>
                </div>
            `;
            // Hide the reserve button
            reserveButton.style.display = 'none';
        }
    } catch (error) {
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error checking reservation', 'error', { error });
        } else {
            console.error('Error checking reservation:', error);
        }
        // Continue without showing error, assuming not registered
    }
    
    // Load attendees list
    loadAttendees();
}

/**
 * Reservation Functions
 */

// Process reservation
async function processReservation() {
    if (!selectedWallet || !selectedDnaNickname) {
        // Show error using CpunkUI if available
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError) {
            CpunkUI.showError('Wallet or DNA data missing', 'dnaError');
        } else {
            dnaError.textContent = 'Wallet or DNA data missing';
            dnaError.style.display = 'block';
        }
        return;
    }
    
    // Check if wallet has sufficient CPUNK balance for the minimum requirement
    if (selectedWallet.cpunkBalance < MIN_WALLET_BALANCE) {
        // Show error using CpunkUI if available
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError) {
            CpunkUI.showError(`Insufficient CPUNK balance. You need at least ${MIN_WALLET_BALANCE.toLocaleString()} CPUNK in your wallet to reserve a spot.`, 'dnaError');
        } else {
            dnaError.textContent = `Insufficient CPUNK balance. You need at least ${MIN_WALLET_BALANCE.toLocaleString()} CPUNK in your wallet to reserve a spot.`;
            dnaError.style.display = 'block';
        }
        return;
    }
    
    // Also check if wallet has enough for the actual transaction amount
    if (selectedWallet.cpunkBalance < RESERVATION_AMOUNT) {
        // Show error using CpunkUI if available
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError) {
            CpunkUI.showError(`Insufficient CPUNK balance for the transaction. You need at least ${RESERVATION_AMOUNT} CPUNK.`, 'dnaError');
        } else {
            dnaError.textContent = `Insufficient CPUNK balance for the transaction. You need at least ${RESERVATION_AMOUNT} CPUNK.`;
            dnaError.style.display = 'block';
        }
        return;
    }

    try {
        reserveButton.disabled = true;
        reserveButton.textContent = 'Processing...';
        
        // Hide DNA section
        dnaSection.style.display = 'none';
        
        // Show transaction section
        txSection.style.display = 'block';
        txStatus.style.display = 'block';
        txError.style.display = 'none';
        txSuccess.style.display = 'none';
        
        // 1. Get transaction data for reservation
        // Use selectedDnaNickname from SSO
        const primaryNickname = selectedDnaNickname;
        
        // Log which DNA is being used
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Using DNA for reservation', 'info', { 
                nickname: primaryNickname,
                isSelectedDna: !!selectedDnaNickname,
                availableDnas: nicknames
            });
        }
        
        if (!primaryNickname) {
            throw new Error('No DNA nickname found for reservation');
        }
        
        txStatus.innerHTML = '<span class="tx-status-highlight">Sending transaction...</span>';
        
        // Format the payment amount correctly (with Cellframe format)
        // Match the format used in DNA registration for consistency
        const paymentAmount = `${RESERVATION_AMOUNT}.0e+18`;
        
        // Log transaction parameters
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Sending transaction request', 'request', {
                wallet: selectedWallet.name,
                network: 'Backbone',
                toAddress: TREASURY_WALLET,
                tokenName: 'CPUNK',
                value: paymentAmount
            });
        } else {
            console.log('Sending transaction request', {
                wallet: selectedWallet.name,
                network: 'Backbone',
                toAddress: TREASURY_WALLET,
                tokenName: 'CPUNK',
                value: paymentAmount
            });
        }
        
        // Use CpunkTransaction if available
        let txHash;
        if (typeof CpunkTransaction !== 'undefined' && CpunkTransaction.sendTransaction) {
            const result = await CpunkTransaction.sendTransaction({
                walletName: selectedWallet.name,
                network: 'Backbone',
                toAddress: TREASURY_WALLET,
                tokenName: 'CPUNK',
                value: paymentAmount
            });
            
            if (result.success) {
                txHash = result.txHash;
            } else {
                throw new Error('Failed to send transaction');
            }
        } else {
            // Fallback to direct API call with SSO session
            sessionId = getSessionId();
            if (!sessionId) {
                throw new Error('No session available');
            }
            
            const response = await makeRequest('SendTransaction', {
                id: sessionId,
                net: 'Backbone',
                walletName: selectedWallet.name,
                toAddr: TREASURY_WALLET,
                tokenName: 'CPUNK',
                value: paymentAmount
            });
            
            // Check response
            if (response.status === 'ok' && response.data && response.data.success) {
                // Get transaction hash
                txHash = response.data.tx_hash || response.data.idQueue || 'Transaction Submitted';
            } else {
                throw new Error(response.errorMsg || 'Failed to send transaction');
            }
        }
        
        // Log success
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Transaction submitted successfully', 'info', {
                txHash: txHash,
                nickname: primaryNickname
            });
        } else {
            console.log('Transaction submitted successfully', {
                txHash: txHash,
                nickname: primaryNickname
            });
        }
        
        // Update status
        txStatus.textContent = 'Transaction submitted. Verifying...';
        
        // Start verification process using the transaction manager (like in register.js)
        if (typeof CpunkTransaction !== 'undefined' && CpunkTransaction.startVerification) {
            CpunkTransaction.startVerification({
                txHash: txHash,
                // When verification starts
                onVerificationStart: () => {
                    txStatus.innerHTML = '<span class="tx-status-highlight">Verifying transaction...</span>';
                },
                // On each verification attempt
                onVerificationAttempt: (attempt, maxAttempts) => {
                    txStatus.innerHTML = `Verifying transaction...<br><span style="font-size: 0.9em; opacity: 0.8;">Attempt ${attempt}/${maxAttempts}</span>`;
                },
                // On successful verification
                onVerificationSuccess: async (verifiedTxHash, attempt) => {
                    await completeReservation(primaryNickname, verifiedTxHash);
                },
                // On verification failure
                onVerificationFail: (failedTxHash, attempts, error) => {
                    showReservationFailed(failedTxHash, primaryNickname);
                }
            });
        } else {
            // Fall back to custom verification process if CpunkTransaction isn't available
            startVerificationProcess(txHash, primaryNickname);
        }
    } catch (error) {
        // Enhanced error logging with more context
        const errorDetails = {
            error: error,
            walletName: selectedWallet ? selectedWallet.name : 'Unknown',
            walletAddress: walletAddress,
            cpunkBalance: selectedWallet ? selectedWallet.cpunkBalance : 'Unknown',
            reservationAmount: RESERVATION_AMOUNT,
            timestamp: new Date().toISOString(),
            message: error.message,
            stack: error.stack
        };
        
        // Log detailed error information
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error processing reservation', 'error', errorDetails);
        } else {
            console.error('Error processing reservation:', errorDetails);
        }
        
        txStatus.style.display = 'none';
        
        // Show error using CpunkUI if available
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError) {
            CpunkUI.showError(`Error: ${error.message}`, 'txError');
        } else {
            txError.textContent = `Error: ${error.message}`;
            txError.style.display = 'block';
        }
        
        // Re-enable button
        reserveButton.disabled = false;
        reserveButton.textContent = 'Reserve Your Spot - 1,000,000 CPUNK';

        // Show DNA section again
        dnaSection.style.display = 'block';
    }
}

// Verification timers
let verificationTimers = [];
let verificationAttempt = 0;
let maxVerificationAttempts = 10;

// Start verification process with scheduling
function startVerificationProcess(txHash, dnaName) {
    // Reset verification state
    verificationAttempt = 0;
    clearVerificationTimers();
    
    // Log start of verification
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
        CpunkUtils.logDebug('Starting transaction verification process', 'info', {
            txHash: txHash,
            dnaName: dnaName,
            maxAttempts: maxVerificationAttempts
        });
    } else {
        console.log('Starting transaction verification process', {
            txHash: txHash,
            dnaName: dnaName,
            maxAttempts: maxVerificationAttempts
        });
    }
    
    // Use CpunkUtils or CpunkTransaction for verification if available
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.startTransactionVerification) {
        verificationTimers = CpunkUtils.startTransactionVerification(
            txHash,
            // Success callback
            async (verifiedTxHash, attempt) => {
                await completeReservation(dnaName, verifiedTxHash);
            },
            // Failure callback
            (failedTxHash, attempts, error) => {
                showReservationFailed(failedTxHash, dnaName);
            },
            // Attempt callback
            (attempt, maxAttempts) => {
                verificationAttempt = attempt;
                // Update transaction status
                txStatus.textContent = `Verifying transaction... Attempt ${attempt}/${maxAttempts}`;
            }
        );
    } else if (typeof CpunkTransaction !== 'undefined' && CpunkTransaction.startVerification) {
        CpunkTransaction.startVerification({
            txHash: txHash,
            onVerificationStart: () => {
                txStatus.textContent = 'Starting verification process...';
            },
            onVerificationSuccess: async (verifiedTxHash, attempt) => {
                await completeReservation(dnaName, verifiedTxHash);
            },
            onVerificationFail: (failedTxHash, attempts, error) => {
                showReservationFailed(failedTxHash, dnaName);
            },
            onVerificationAttempt: (attempt, maxAttempts) => {
                verificationAttempt = attempt;
                // Update transaction status
                txStatus.textContent = `Verifying transaction... Attempt ${attempt}/${maxAttempts}`;
            }
        });
    } else {
        // Fallback to manual implementation
        // Schedule verifications
        const schedule = [
            15,    // First verification after 15 seconds
            45,    // Second after 1 minute from start
            60,    // Then every minute
            60,
            60,
            60,
            60,
            60,
            60,
            60
        ];

        // Create a cumulative delay for each verification attempt
        let cumulativeDelay = 0;

        // Schedule verification attempts
        schedule.forEach((seconds, index) => {
            cumulativeDelay += seconds;

            const timer = setTimeout(async () => {
                verificationAttempt = index + 1;
                
                // Update transaction status
                txStatus.textContent = `Verifying transaction... Attempt ${verificationAttempt}/${maxVerificationAttempts}`;
                
                const verified = await verifyTransaction(txHash);

                // If verified or last attempt, proceed with reservation confirmation
                if (verified || index === schedule.length - 1) {
                    if (verified) {
                        await completeReservation(dnaName, txHash);
                    } else {
                        // Failed to verify after all attempts
                        showReservationFailed(txHash, dnaName);
                    }
                }
            }, cumulativeDelay * 1000);

            verificationTimers.push(timer);
        });
    }
}

// Clear all verification timers
function clearVerificationTimers() {
    // Use CpunkUtils if available
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.clearVerificationTimers) {
        CpunkUtils.clearVerificationTimers(verificationTimers);
    } else if (typeof CpunkTransaction !== 'undefined' && CpunkTransaction.clearVerificationTimers) {
        CpunkTransaction.clearVerificationTimers();
    } else {
        // Fallback implementation
        // Clear all scheduled verifications
        verificationTimers.forEach(timer => clearTimeout(timer));
    }
    
    verificationTimers = [];
}

// Verify transaction with DNA API
async function verifyTransaction(txHash) {
    try {
        // Log verification attempt
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug(`Transaction verification attempt ${verificationAttempt}/${maxVerificationAttempts}`, 'info', {
                txHash: txHash,
                attempt: verificationAttempt
            });
        } else {
            console.log(`Transaction verification attempt ${verificationAttempt}/${maxVerificationAttempts}`, {
                txHash: txHash,
                attempt: verificationAttempt
            });
        }

        // Use CpunkUtils for verification if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.verifyTransaction) {
            return await CpunkUtils.verifyTransaction(txHash);
        } else if (typeof CpunkTransaction !== 'undefined' && CpunkTransaction.verifyTransaction) {
            return await CpunkTransaction.verifyTransaction(txHash);
        }
        
        // Fallback implementation
        const DNA_API_URL = 'dna-proxy.php';
        // Make API request to dna-proxy
        const url = `${DNA_API_URL}?tx_validate=${txHash}`;
        
        // Log request
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Transaction verification request', 'request', { url: url });
        } else {
            console.log('Transaction verification request', { url: url });
        }
        
        const response = await fetch(url);
        const data = await response.text();
        
        // Log response
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Transaction verification response', 'response', { 
                status: response.status,
                responseText: data 
            });
        } else {
            console.log('Transaction verification response', { 
                status: response.status,
                responseText: data 
            });
        }

        let isVerified = false;

        // Try to parse as JSON, if possible
        try {
            const jsonData = JSON.parse(data);

            // Check for specific success criteria
            if (jsonData.status_code === 0 && jsonData.message === "OK") {
                isVerified = true;
                
                if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
                    CpunkUtils.logDebug(`Transaction verified successfully on attempt ${verificationAttempt}`, 'info');
                } else {
                    console.log(`Transaction verified successfully on attempt ${verificationAttempt}`);
                }
            }
        } catch (e) {
            // Not valid JSON, check text response
            if (data.includes('"status_code": 0') && data.includes('"message": "OK"')) {
                isVerified = true;
                
                if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
                    CpunkUtils.logDebug(`Transaction verified successfully (text match) on attempt ${verificationAttempt}`, 'info');
                } else {
                    console.log(`Transaction verified successfully (text match) on attempt ${verificationAttempt}`);
                }
            }
        }

        return isVerified;
    } catch (error) {
        // Log error
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug(`Verification error on attempt ${verificationAttempt}`, 'error', { error });
        } else {
            console.error(`Verification error on attempt ${verificationAttempt}`, error);
        }
        return false;
    }
}

// Complete reservation after transaction verification
async function completeReservation(dnaName, txHash) {
    try {
        // Update loading message
        txStatus.textContent = `Transaction verified! Finalizing reservation...`;
        
        // Enhanced debug logging with more context
        const debugInfo = {
            dnaName: dnaName,
            txHash: txHash,
            walletAddress: walletAddress,
            walletName: selectedWallet ? selectedWallet.name : 'Unknown',
            timestamp: new Date().toISOString()
        };
        
        // Log finalization with enhanced debug info
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Transaction verified, finalizing reservation', 'info', debugInfo);
        } else {
            console.log('Transaction verified, finalizing reservation', debugInfo);
        }

        // Make the API request to update reservation status using the new endpoint
        const reservationData = {
            action: 'update_reservation',
            dna_nickname: dnaName,
            wallet: walletAddress,
            tx_hash: txHash
        };
        
        // Log using API Console if available
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log('Reservation Update API Request', { 
                data: reservationData,
                type: 'dna_api'
            });
        }
        // Also log using CpunkUtils if available (for backward compatibility)
        else if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Sending reservation update request', 'request', { reservationData });
        } else {
            console.log('Sending reservation update request', reservationData);
        }
        
        // Use CpunkUtils for dnaPost if available
        let response, result;
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dnaPost) {
            result = await CpunkUtils.dnaPost(reservationData);
        } else {
            // Fallback to direct API call
            const DNA_API_URL = 'dna-proxy.php';
            response = await fetch(DNA_API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(reservationData)
            });
            
            if (!response.ok) {
                // Log API error if response is not OK
                if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                    CpunkAPIConsole.log('Reservation Update API Error', { 
                        status: response.status,
                        statusText: response.statusText,
                        type: 'dna_api'
                    });
                }
                throw new Error(`Reservation update failed with status: ${response.status}`);
            }
            
            result = await response.text();
        }
        
        // Log API response
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log('Reservation Update API Response', { 
                result: result,
                type: 'dna_api'
            });
        }
        // Also log using CpunkUtils if available (for backward compatibility)
        else if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Reservation update response', 'response', { 
                result
            });
        } else {
            console.log('Reservation update response', {
                status: response ? response.status : 'N/A',
                responseText: result
            });
        }
        
        // Try to parse the response if it's a string
        let responseData;
        if (typeof result === 'string') {
            try {
                responseData = JSON.parse(result);
            } catch (e) {
                if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
                    CpunkUtils.logDebug('Response is not valid JSON, but continuing', 'warning');
                } else {
                    console.log('Response is not valid JSON, but continuing');
                }
            }
        } else {
            responseData = result;
        }
        
        // Hide transaction section and show confirmation section
        txSection.style.display = 'none';
        confirmationSection.style.display = 'block';
        
        // Update confirmation details
        reservedByDna.textContent = dnaName;
        reservationTxId.textContent = txHash;
        
        // Update attendees list
        await loadAttendees(true);
        
    } catch (error) {
        // Log error
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error completing reservation', 'error', { error });
        } else {
            console.error('Error completing reservation', error);
        }
        
        // Show transaction failed
        txStatus.style.display = 'none';
        
        // Show error using CpunkUI if available
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError) {
            CpunkUI.showError(`Error: ${error.message}`, 'txError');
        } else {
            txError.textContent = `Error: ${error.message}`;
            txError.style.display = 'block';
        }
    }
}

// Show reservation failed UI
function showReservationFailed(txHash, dnaName) {
    // Log error
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
        CpunkUtils.logDebug('Reservation failed - transaction not verified after all attempts', 'error', {
            txHash: txHash,
            dnaName: dnaName,
            attempts: verificationAttempt
        });
    } else {
        console.error('Reservation failed - transaction not verified after all attempts', {
            txHash: txHash,
            dnaName: dnaName,
            attempts: verificationAttempt
        });
    }
    
    // Update transaction status
    txStatus.style.display = 'none';
    txError.innerHTML = `
        <h3>Transaction Not Verified</h3>
        <p>We were unable to verify your payment transaction after multiple attempts.</p>
        <p>Transaction Hash: <code>${txHash}</code></p>
        <p>If your transaction completes later, your reservation will still be processed.</p>
        <button onclick="window.location.reload()" class="action-button" style="margin-top: 20px;">Try Again</button>
    `;
    txError.style.display = 'block';
}

/**
 * Attendees List Functions
 */

// Load list of confirmed attendees
async function loadAttendees(forceRefresh = false) {
    try {
        if (attendeesList.length === 0 || forceRefresh) {
            attendeesListElement.innerHTML = '<div class="loading">Loading confirmed attendees</div>';

            // Initialize an empty list for attendees
            attendeesList = [];

            // Make API request to get payment-based attendees
            const DNA_API_URL = 'dna-proxy.php';
            const requestUrl = `${DNA_API_URL}?action=get_attendees`;

            // Log API request if console is available
            if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                CpunkAPIConsole.log('Attendees list request (payment)', {
                    endpoint: requestUrl,
                    type: 'local_api'
                });
            }

            try {
                const response = await fetch(requestUrl);
                const data = await response.json();

                // Log API response if console is available
                if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                    CpunkAPIConsole.log('Attendees list response (payment)', {
                        status: response.status,
                        attendeeCount: data.attendees ? data.attendees.length : 0,
                        data: data
                    });
                }

                if (data && Array.isArray(data.attendees)) {
                    // Add payment-based attendees
                    attendeesList = [...data.attendees];
                }
            } catch (error) {
                console.error('Error fetching payment attendees:', error);
                // Continue to fetch invitation-based attendees
            }

            // Make API request to get invitation-based attendees
            const invitationUrl = 'invitation_code.php?action=get_attendees';

            // Log API request if console is available
            if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                CpunkAPIConsole.log('Attendees list request (invitation)', {
                    endpoint: invitationUrl,
                    type: 'local_api'
                });
            }

            try {
                const invResponse = await fetch(invitationUrl);
                const invData = await invResponse.json();

                // Log API response if console is available
                if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                    CpunkAPIConsole.log('Attendees list response (invitation)', {
                        status: invResponse.status,
                        attendeeCount: invData.attendees ? invData.attendees.length : 0,
                        data: invData
                    });
                }

                if (invData && Array.isArray(invData.attendees)) {
                    // Merge invitation-based attendees with payment-based attendees
                    attendeesList = [...attendeesList, ...invData.attendees];
                }
            } catch (error) {
                console.error('Error fetching invitation attendees:', error);
            }

            // If we just reserved, add our nickname to the list
            if (forceRefresh && selectedDnaNickname) {
                const primaryNickname = selectedDnaNickname;

                if (primaryNickname && !attendeesList.some(a => a.nickname === primaryNickname)) {
                    attendeesList.push({
                        nickname: primaryNickname,
                        status: 'Confirmed',
                        type: validatedCode ? validatedCode.type : 'payment'
                    });
                }
            }
        }

        // Render attendees
        renderAttendees();
    } catch (error) {
        // Log error
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error loading attendees', 'error', { error });
        } else {
            console.error('Error loading attendees:', error);
        }

        attendeesListElement.innerHTML = `
            <div style="color: var(--error); text-align: center; padding: 20px;">
                Error loading attendees: ${error.message}
            </div>
        `;
    }
}

// Render the attendees list in the UI
function renderAttendees() {
    attendeesListElement.innerHTML = '';

    if (attendeesList.length === 0) {
        attendeesListElement.innerHTML = `
            <div style="text-align: center; padding: 20px; color: var(--text-dim);">
                No confirmed attendees yet. Be the first to register!
            </div>
        `;
        return;
    }

    attendeesList.forEach(attendee => {
        const attendeeCard = document.createElement('div');
        attendeeCard.className = 'attendee-card';

        // Add type-specific class if available
        if (attendee.type) {
            attendeeCard.classList.add(`attendee-type-${attendee.type}`);
        }

        const initial = attendee.nickname.charAt(0).toUpperCase();

        // Create avatar with appropriate styling
        let avatarClass = 'attendee-avatar';
        if (attendee.status && attendee.status.includes('Invitation')) {
            avatarClass += ' invitation-avatar';
        }

        attendeeCard.innerHTML = `
            <div class="${avatarClass}">${initial}</div>
            <div class="attendee-name">${attendee.nickname}</div>
            <div class="attendee-status">${attendee.status || 'Confirmed'}</div>
        `;

        attendeesListElement.appendChild(attendeeCard);
    });
}

/**
 * Countdown Timer
 */
function updateCountdown() {
    const eventDate = new Date("July 12, 2025 00:00:00").getTime();
    const now = new Date().getTime();
    const distance = eventDate - now;
    
    // Calculate time components
    const days = Math.floor(distance / (1000 * 60 * 60 * 24));
    const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((distance % (1000 * 60)) / 1000);
    
    // Update the UI
    if (daysElement) daysElement.textContent = days;
    if (hoursElement) hoursElement.textContent = hours;
    if (minutesElement) minutesElement.textContent = minutes;
    if (secondsElement) secondsElement.textContent = seconds;
    
    // If countdown is over
    if (distance < 0) {
        clearInterval(countdownInterval);
        if (daysElement) daysElement.textContent = "0";
        if (hoursElement) hoursElement.textContent = "0";
        if (minutesElement) minutesElement.textContent = "0";
        if (secondsElement) secondsElement.textContent = "0";
        
        // Update the UI to show the event is now
        const eventBanner = document.querySelector('.event-banner');
        if (eventBanner) {
            eventBanner.innerHTML = `
                <div class="banner-content">
                    <h2 style="color: var(--success);">The Event Is Happening Now! 🎉</h2>
                    <p style="text-align: center; margin-top: 20px;">
                        "The Post-Quantum Ark", Istanbul
                    </p>
                </div>
            `;
        }
    }
}

/**
 * Invitation Code Functions
 */

// Toggle invitation code section
function toggleInvitationSection() {
    if (invitationCodeSection.style.display === 'none') {
        invitationCodeSection.style.display = 'block';
        toggleInvitationButton.textContent = 'Cancel';
        toggleInvitationButton.classList.add('cancel-button');
        reserveButton.style.display = 'none';
    } else {
        invitationCodeSection.style.display = 'none';
        toggleInvitationButton.textContent = 'Use Invitation Code';
        toggleInvitationButton.classList.remove('cancel-button');
        reserveButton.style.display = 'block';

        // Reset the invitation code UI
        resetInvitationCodeUI();
    }
}

// Reset invitation code UI
function resetInvitationCodeUI() {
    invitationCodeInput.value = '';
    codeStatus.style.display = 'none';
    validCodeDetails.style.display = 'none';
    validatedCode = null;
}

// Validate invitation code
async function validateInvitationCode() {
    const code = invitationCodeInput.value.trim();

    // Check if code is empty
    if (!code) {
        showCodeStatus('Please enter an invitation code', 'error');
        return;
    }

    try {
        // Disable input and button while validating
        invitationCodeInput.disabled = true;
        validateCodeButton.disabled = true;
        validateCodeButton.textContent = 'Validating...';

        // Log validation attempt
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Validating invitation code', 'info', { code });
        } else {
            console.log('Validating invitation code:', code);
        }

        // Make API request to validate code
        const response = await fetch(`invitation_code.php?action=validate&code=${encodeURIComponent(code)}`);
        const data = await response.json();

        // Log response
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Invitation code validation response', 'info', { data });
        } else {
            console.log('Invitation code validation response:', data);
        }

        // Re-enable input and button
        invitationCodeInput.disabled = false;
        validateCodeButton.disabled = false;
        validateCodeButton.textContent = 'Validate';

        // Process response
        if (data.valid) {
            // Store validated code
            validatedCode = {
                code: code,
                type: data.code_type,
                description: data.description
            };

            // Show success message
            showCodeStatus('Valid invitation code!', 'success');

            // Show valid code details
            codeType.textContent = data.description || data.code_type;
            codeDescription.textContent = 'This code allows you to reserve your spot without CPUNK payment.';
            validCodeDetails.style.display = 'block';
        } else {
            // Show error message
            showCodeStatus(data.message || 'Invalid invitation code', 'error');
            validCodeDetails.style.display = 'none';
            validatedCode = null;
        }
    } catch (error) {
        // Log error
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error validating invitation code', 'error', { error });
        } else {
            console.error('Error validating invitation code:', error);
        }

        // Re-enable input and button
        invitationCodeInput.disabled = false;
        validateCodeButton.disabled = false;
        validateCodeButton.textContent = 'Validate';

        // Show error message
        showCodeStatus('Error validating code. Please try again.', 'error');
    }
}

// Show code status message
function showCodeStatus(message, type) {
    codeStatus.textContent = message;
    codeStatus.className = 'code-status';

    if (type) {
        codeStatus.classList.add(type);
    }

    codeStatus.style.display = 'block';
}

// Process reservation with invitation code
async function processCodeReservation() {
    if (!selectedWallet || !selectedDnaNickname || !validatedCode) {
        showCodeStatus('Missing wallet, DNA, or valid code data', 'error');
        return;
    }

    try {
        redeemCodeButton.disabled = true;
        redeemCodeButton.textContent = 'Processing...';

        // Hide DNA section
        dnaSection.style.display = 'none';

        // Show transaction section
        txSection.style.display = 'block';
        txStatus.style.display = 'block';
        txError.style.display = 'none';
        txSuccess.style.display = 'none';

        // Get the DNA nickname to use from SSO
        const primaryNickname = selectedDnaNickname;

        if (!primaryNickname) {
            throw new Error('No DNA nickname found for reservation');
        }

        txStatus.innerHTML = '<span class="tx-status-highlight">Processing invitation code...</span>';

        // Log code redemption request
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Redeeming invitation code', 'info', {
                code: validatedCode.code,
                dna: primaryNickname,
                wallet: walletAddress
            });
        } else {
            console.log('Redeeming invitation code:', {
                code: validatedCode.code,
                dna: primaryNickname,
                wallet: walletAddress
            });
        }

        // Make API request to redeem code
        const response = await fetch(`invitation_code.php?action=redeem&code=${encodeURIComponent(validatedCode.code)}&dna=${encodeURIComponent(primaryNickname)}&wallet=${encodeURIComponent(walletAddress)}`);
        const data = await response.json();

        // Log response
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Invitation code redemption response', 'info', { data });
        } else {
            console.log('Invitation code redemption response:', data);
        }

        if (data.success) {
            // Hide transaction section
            txSection.style.display = 'none';

            // Show confirmation section
            confirmationSection.style.display = 'block';

            // Update confirmation details
            reservedByDna.textContent = primaryNickname;
            reservationTxId.textContent = 'Invitation Code: ' + validatedCode.code;

            // Update attendees list
            await loadAttendees(true);
        } else {
            throw new Error(data.message || 'Failed to redeem invitation code');
        }
    } catch (error) {
        // Log error
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error redeeming invitation code', 'error', { error });
        } else {
            console.error('Error redeeming invitation code:', error);
        }

        // Show error message
        txStatus.style.display = 'none';
        txError.textContent = `Error: ${error.message}`;
        txError.style.display = 'block';

        // Re-enable button
        redeemCodeButton.disabled = false;
        redeemCodeButton.textContent = 'Reserve With Invitation Code';
    }
}

/**
 * Initialize DOM elements
 */
function initDOMElements() {
    // Main sections
    reservationInfo = document.getElementById('reservationInfo');
    loginRequiredSection = document.getElementById('loginRequiredSection');
    loginBtn = document.getElementById('loginBtn');
    statusIndicator = document.getElementById('statusIndicator');
    walletSection = document.getElementById('walletSection');
    walletsList = document.getElementById('walletsList');
    continueButton = document.getElementById('continueButton');
    walletError = document.getElementById('walletError');
    dnaSection = document.getElementById('dnaSection');
    dnaStatus = document.getElementById('dnaStatus');
    dnaError = document.getElementById('dnaError');
    dnaSelectionList = document.getElementById('dnaSelectionList');
    dnaDetails = document.getElementById('dnaDetails');
    profileAvatar = document.getElementById('profileAvatar');
    profileNickname = document.getElementById('profileNickname');
    profileNicknames = document.getElementById('profileNicknames');
    reserveButton = document.getElementById('reserveButton');
    txSection = document.getElementById('txSection');
    txStatus = document.getElementById('txStatus');
    txError = document.getElementById('txError');
    txSuccess = document.getElementById('txSuccess');
    confirmationSection = document.getElementById('confirmationSection');
    reservedByDna = document.getElementById('reservedByDna');
    reservationTxId = document.getElementById('reservationTxId');
    attendeesListElement = document.getElementById('attendeesList');
    
    // Invitation code elements
    toggleInvitationButton = document.getElementById('toggleInvitationButton');
    invitationCodeSection = document.getElementById('invitationCodeSection');
    invitationCodeInput = document.getElementById('invitationCodeInput');
    validateCodeButton = document.getElementById('validateCodeButton');
    codeStatus = document.getElementById('codeStatus');
    validCodeDetails = document.getElementById('validCodeDetails');
    codeType = document.getElementById('codeType');
    codeDescription = document.getElementById('codeDescription');
    redeemCodeButton = document.getElementById('redeemCodeButton');
    
    // Countdown elements
    daysElement = document.getElementById('days');
    hoursElement = document.getElementById('hours');
    minutesElement = document.getElementById('minutes');
    secondsElement = document.getElementById('seconds');
}

/**
 * Initialize Event Listeners
 */
function initEventListeners() {
    // Login button
    if (loginBtn) {
        loginBtn.addEventListener('click', () => {
            window.location.href = 'login.html?redirect=mainnet_party.html';
        });
    }
    
    // Remove wallet selection listeners as SSO handles this
    if (reserveButton) reserveButton.addEventListener('click', processReservation);

    // Invitation code
    if (toggleInvitationButton) toggleInvitationButton.addEventListener('click', toggleInvitationSection);
    if (validateCodeButton) validateCodeButton.addEventListener('click', validateInvitationCode);
    if (redeemCodeButton) redeemCodeButton.addEventListener('click', processCodeReservation);

    // Handle Enter key in invitation code input
    if (invitationCodeInput) {
        invitationCodeInput.addEventListener('keyup', function(event) {
            if (event.key === 'Enter') {
                validateInvitationCode();
            }
        });
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Initialize DOM elements
    initDOMElements();
    
    // Initialize API console if available
    if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.init) {
        CpunkAPIConsole.init();
        console.log('API Console initialized for mainnet party page');
    }
    
    // Initialize SSO
    if (typeof CpunkSSO !== 'undefined') {
        sso = CpunkSSO.getInstance();
        sso.init({
            onAuthenticated: async (user) => {
                console.log('User authenticated:', user.dna);
                // Hide login required section and update reservation info
                if (loginRequiredSection) loginRequiredSection.style.display = 'none';
                if (reservationInfo) reservationInfo.innerHTML = 'Secure your attendance by reserving with <span class="highlight">1,000,000 CPUNK</span> on the <span class="highlight">Backbone</span> network.';
                
                // Get wallet and DNA info from SSO
                walletAddress = sso.getCurrentWallet();
                sessionId = sso.sessionId;
                
                if (walletAddress && sessionId) {
                    // Set session ID for transaction module
                    if (typeof CpunkTransaction !== 'undefined' && CpunkTransaction.setSessionId) {
                        CpunkTransaction.setSessionId(sessionId);
                    }
                    
                    // Get wallet balance from dashboard
                    try {
                        const walletsResponse = await makeRequest('GetWallets', { id: sessionId });
                        if (walletsResponse.status === 'ok' && walletsResponse.data) {
                            const backboneWallets = walletsResponse.data.filter(w => w.network === 'Backbone');
                            const currentWallet = backboneWallets.find(w => w.address === walletAddress);
                            
                            if (currentWallet) {
                                selectedWallet = {
                                    name: currentWallet.name || 'Wallet',
                                    address: currentWallet.address,
                                    network: 'Backbone',
                                    cpunkBalance: currentWallet.cpunkBalance || 0
                                };
                            } else {
                                // Fallback if wallet not found
                                selectedWallet = {
                                    name: 'Wallet',
                                    address: walletAddress,
                                    network: 'Backbone',
                                    cpunkBalance: 0
                                };
                            }
                        }
                    } catch (error) {
                        console.error('Error loading wallet info:', error);
                        // Fallback wallet data
                        selectedWallet = {
                            name: 'Wallet',
                            address: walletAddress,
                            network: 'Backbone',
                            cpunkBalance: 0
                        };
                    }
                    
                    // Use DNA from SSO (user.dna)
                    selectedDnaNickname = user.dna;
                    
                    // Show DNA section directly
                    dnaSection.style.display = 'block';
                    dnaDetails.style.display = 'block';
                    
                    // Update profile preview
                    if (profileAvatar) profileAvatar.textContent = user.dna.charAt(0).toUpperCase();
                    if (profileNickname) profileNickname.textContent = user.dna;
                    
                    // Check if already reserved for the event
                    await checkExistingReservation(user.dna);
                }
            },
            onUnauthenticated: () => {
                console.log('User not authenticated');
                // Show login required section and restore original reservation info
                if (loginRequiredSection) loginRequiredSection.style.display = 'block';
                if (reservationInfo) reservationInfo.innerHTML = 'Secure your attendance by reserving with <span class="highlight">1,000,000 CPUNK</span> on the <span class="highlight">Backbone</span> network. Login to access reservation functionality.';
            }
        });
    }
    
    initEventListeners();
    updateCountdown();
    
    // Start countdown timer
    const countdownInterval = setInterval(updateCountdown, 1000);
    
    // Load initial attendees list immediately
    loadAttendees();
    
    // Show attendees section
    const attendeesSection = document.getElementById('attendeesSection');
    if (attendeesSection) {
        attendeesSection.style.display = 'block';
    }
});