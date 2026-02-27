// API Configuration
const TARGET_ADDRESS = 'Rj7J7MiX2bWy8sNyZcoLqkZuNznvU4KbK6RHgqrGj9iqwKPhoVKE1xNrEMmgtVsnyTZtFhftMPAJbaswuSLp7UeBS7jiRmE5uvuUJaKA';

// State variables
let sessionId = null;
let walletAddress = null;
let currentDna = null;
let currentBalances = {
    cpunk: 0,
    cell: 0
};
let dnaChecked = false;
let verificationTimers = [];
let currentTxHash = null;
let currentDnaName = null;

// Wait for document to load before accessing DOM elements
document.addEventListener('DOMContentLoaded', function() {
    // Initialize API Console
    CpunkAPIConsole.init();

    // Initialize CpunkUtils with debug enabled
    CpunkUtils.init({
        debug: {
            enabled: true,
            showInConsole: true,
            showInUI: true,
            showOnlyOnError: true
        }
    });
    
    // Initialize CpunkUI with our specific elements
    CpunkUI.init({
        dashboardConnectorElements: {
            statusIndicatorId: 'statusIndicator',
            connectButtonId: 'connectButton',
            connectionErrorId: 'errorMessage',
            walletSectionId: 'walletsSection',
            walletsListId: 'walletsList',
            walletErrorId: 'errorMessage'
        }
    });
    
    // Initialize transaction manager
    CpunkTransaction.init();

    // DOM Elements
    const connectButton = document.getElementById('connectButton');
    const walletsSection = document.getElementById('walletsSection');
    const walletsList = document.getElementById('walletsList');
    const registrationSection = document.getElementById('registrationSection');
    const transactionSection = document.getElementById('transactionSection');
    const resultSection = document.getElementById('resultSection');
    const selectedWalletDisplay = document.getElementById('selectedWalletDisplay');
    const dnaInput = document.getElementById('dnaInput');
    const dnaValidationStatus = document.getElementById('dnaValidationStatus');
    const registerButton = document.getElementById('registerButton');
    const errorMessage = document.getElementById('errorMessage');
    const transactionHash = document.getElementById('transactionHash');
    const transactionStatus = document.getElementById('transactionStatus');
    const txError = document.getElementById('txError');
    const txSuccess = document.getElementById('txSuccess');
    const registrationResult = document.getElementById('registrationResult');
    const currentPrice = document.getElementById('currentPrice');
    const priceAmount = document.getElementById('priceAmount');
    
    // Debug panel elements
    const debugPanel = document.getElementById('debugPanel');
    const debugLog = document.getElementById('debugLog');
    const copyDebugBtn = document.getElementById('copyDebugBtn');
    const closeDebugBtn = document.getElementById('closeDebugBtn');

    // Initialize debug panel
    initDebugPanel();
    CpunkUtils.logDebug('Debug panel initialized', 'info');
    CpunkUtils.logDebug('Page loaded - waiting for user interaction', 'info');

    // Add event listeners
    registerButton.addEventListener('click', registerDNA);
    
    // Initialize step indicators
    initializeSteps();
    
    // Check for existing session from SSO login
    const existingSessionId = sessionStorage.getItem('cpunk_dashboard_session');
    const existingWalletName = sessionStorage.getItem('cpunk_selected_wallet');
    const existingDna = sessionStorage.getItem('cpunk_selected_dna');
    
    // Get wallet address from wallet data
    let existingWallet = null;
    const walletDataStr = sessionStorage.getItem('cpunk_wallet_data');
    if (walletDataStr && existingWalletName) {
        try {
            const walletData = JSON.parse(walletDataStr);
            if (walletData[existingWalletName]) {
                existingWallet = walletData[existingWalletName].address;
            }
        } catch (e) {
            console.error('Error parsing wallet data:', e);
        }
    }
    
    
    // Add connect button handler if session is not restored
    if (connectButton && !existingSessionId) {
        connectButton.addEventListener('click', () => {
            console.log('Connect button clicked');
            CpunkDashboard.connect();
        });
    }
    
    if (existingSessionId && existingWallet) {
        // User has existing session from SSO
        console.log('Found existing session from SSO');
        
        // Store session info
        sessionId = existingSessionId;
        walletAddress = existingWallet;
        currentDna = existingDna;
        
        // Set session ID for transaction manager
        CpunkTransaction.setSessionId(existingSessionId);
        
        // Update UI to show authenticated state
        const statusIndicator = document.getElementById('statusIndicator');
        if (statusIndicator) {
            statusIndicator.textContent = 'Connected';
            statusIndicator.className = 'status-indicator status-connected';
        }
        
        // Hide connect button and wallet section
        if (connectButton) connectButton.style.display = 'none';
        if (walletsSection) walletsSection.style.display = 'none';
        
        // Update step 1 to completed
        updateStepStatus(1, 'completed');
        updateStepStatus(2, 'active');
        
        // Show registration section immediately
        registrationSection.style.display = 'block';
        
        // Update selected wallet display
        if (selectedWalletDisplay) {
            const displayName = currentDna || 'No DNA';
            selectedWalletDisplay.textContent = `${displayName} - ${walletAddress.substring(0, 10)}...${walletAddress.substring(walletAddress.length - 10)}`;
        }
        
        // Get wallet balance for registration
        getWalletData(existingWalletName).then(walletData => {
            console.log('Wallet data response:', walletData);
            
            if (walletData && walletData.data && walletData.data.length > 0) {
                // Find Backbone network data
                const backboneNetwork = walletData.data.find(network => network.network === 'Backbone');
                
                if (backboneNetwork) {
                    // Find CPUNK and CELL tokens
                    let cpunkBalance = 0;
                    let cellBalance = 0;
                    
                    if (backboneNetwork.tokens && Array.isArray(backboneNetwork.tokens)) {
                        const cpunkToken = backboneNetwork.tokens.find(token => token.tokenName === 'CPUNK');
                        const cellToken = backboneNetwork.tokens.find(token => token.tokenName === 'CELL');
                        
                        cpunkBalance = parseFloat(cpunkToken?.balance || 0);
                        cellBalance = parseFloat(cellToken?.balance || 0);
                    }
                    
                    // Update current balances
                    currentBalances.cpunk = cpunkBalance;
                    currentBalances.cell = cellBalance;
                    
                    console.log('Wallet balances loaded:', currentBalances);
                    
                    // Update the wallet display with balances
                    if (selectedWalletDisplay) {
                        const displayName = currentDna || 'No DNA';
                        selectedWalletDisplay.innerHTML = `
                            ${displayName} - ${walletAddress.substring(0, 10)}...${walletAddress.substring(walletAddress.length - 10)}<br>
                            <small>CPUNK: ${CpunkUtils.formatBalance(cpunkBalance)} | CELL: ${CpunkUtils.formatBalance(cellBalance)}</small>
                        `;
                    }
                } else {
                    console.error('No Backbone network found in wallet data');
                }
            } else {
                console.error('No wallet data received');
            }
        }).catch(error => {
            console.error('Error loading wallet data:', error);
        });
    }

    // Add debounce to DNA input validation
    let dnaCheckTimeout = null;
    dnaInput.addEventListener('input', () => {
        // Clear any existing timeout
        if (dnaCheckTimeout) {
            clearTimeout(dnaCheckTimeout);
        }

        const nickname = dnaInput.value.trim();

        if (nickname.length > 0) {
            // Show checking indicator immediately
            dnaValidationStatus.textContent = "Checking...";
            dnaValidationStatus.className = 'validation-message validation-checking';
            dnaValidationStatus.style.display = 'block';
        } else {
            dnaValidationStatus.style.display = 'none';
        }

        // Set a new timeout
        dnaCheckTimeout = setTimeout(async () => {
            await validateDnaInput();
        }, 500); // 500ms debounce delay
    });

    // Initialize step indicators
    function initializeSteps() {
        // Hide all checkmarks initially
        document.querySelectorAll('.step-check').forEach(check => {
            check.style.opacity = 0;
            check.style.transform = 'scale(0)';
        });
        
        // Reset all steps
        document.querySelectorAll('.step-item').forEach(step => {
            step.classList.remove('active', 'completed');
        });
        
        // Set first step as active
        document.getElementById('step1').classList.add('active');
    }
    
    // Update step status
    function updateStepStatus(stepNumber, status) {
        const steps = document.querySelectorAll('.step-item');
        
        // Reset all steps first
        steps.forEach((step, index) => {
            const stepNum = index + 1;
            const stepElement = document.getElementById(`step${stepNum}`);
            
            if (stepNum < stepNumber) {
                // Previous steps are completed
                stepElement.classList.remove('active');
                stepElement.classList.add('completed');
            } else if (stepNum === stepNumber) {
                // Current step is active
                stepElement.classList.remove('completed');
                stepElement.classList.add(status === 'completed' ? 'completed' : 'active');
            } else {
                // Future steps are neither active nor completed
                stepElement.classList.remove('active', 'completed');
            }
        });
    }
    
    // Initialize debug panel and controls
    function initDebugPanel() {
        // Initially hide the debug panel
        debugPanel.style.display = 'none';

        // Add event listeners for debug controls
        copyDebugBtn.addEventListener('click', () => {
            // Create a formatted text version of the debug info
            let debugText = "=== CPUNK DNA Registration Debug Info ===\n\n";
            const debugEntries = CpunkUtils.getDebugEntries(15); // Get last 15 entries
            
            debugEntries.forEach(entry => {
                const time = new Date(entry.timestamp).toLocaleTimeString();
                debugText += `[${time}] ${entry.type.toUpperCase()}: ${entry.message}\n`;
                if (entry.data) {
                    debugText += `DATA: ${JSON.stringify(entry.data, null, 2)}\n`;
                }
                debugText += "------------------------------\n";
            });
            
            // Copy to clipboard using CpunkUtils
            CpunkUtils.copyToClipboard(debugText, 
                // Success callback
                () => {
                    copyDebugBtn.textContent = "Copied!";
                    setTimeout(() => {
                        copyDebugBtn.textContent = "Copy All for Support";
                    }, 2000);
                }
            );
        });

        closeDebugBtn.addEventListener('click', () => {
            debugPanel.style.display = 'none';
        });
    }
    
    // Show debug panel (only called on errors)
    function showDebugPanel() {
        debugPanel.style.display = 'block';
        renderDebugLog();
    }

    // Render debug log in the UI
    function renderDebugLog() {
        if (!debugLog) return;

        const debugEntries = CpunkUtils.getDebugEntries(10); // Get last 10 entries
        let html = '';
        
        debugEntries.forEach(entry => {
            const time = new Date(entry.timestamp).toLocaleTimeString();
            let className = 'debug-entry';
            let icon = '';

            switch (entry.type) {
                case 'request':
                    className += ' debug-request';
                    icon = '🔷';
                    break;
                case 'response':
                    className += ' debug-response';
                    icon = '🔶';
                    break;
                case 'error':
                    className += ' debug-error';
                    icon = '❌';
                    break;
                default:
                    icon = 'ℹ️';
            }

            let formattedData = '';
            if (entry.data) {
                try {
                    formattedData = `<div class="debug-entry-json">${CpunkUtils.formatJsonForHtml(entry.data)}</div>`;
                } catch (e) {
                    formattedData = `<div class="debug-entry-json">${JSON.stringify(entry.data, null, 2)}</div>`;
                }
            }

            html += `
                <div class="${className}" data-time="${time}">
                    <span class="debug-type">${icon}</span>
                    <span class="debug-message">${entry.message}</span>
                    ${formattedData}
                </div>
            `;
        });

        debugLog.innerHTML = html;
    }

    // The connectToDashboard function is now handled by the DashboardConnector module

    // Get wallet data (including token balances)
    async function getWalletData(walletName) {
        try {
            CpunkUtils.logDebug(`Fetching wallet data for: ${walletName}`, 'info');
            
            // Use the session ID we already have
            if (!sessionId) {
                throw new Error('No session ID available');
            }
            
            const response = await CpunkDashboard.makeRequest('GetDataWallet', {
                id: sessionId,
                walletName: walletName
            });
            return response;
        } catch (error) {
            CpunkUtils.logDebug(`Error fetching wallet data for ${walletName}`, 'error', {
                message: error.message,
                stack: error.stack
            });
            return null;
        }
    }

    // loadWallets function removed - authentication is handled by SSO
    // The authenticated wallet is automatically available from SSO
    async function loadWallets() {
        // This function is no longer needed with SSO authentication
        return;
        try {
            CpunkUI.setLoading(true);
            walletsList.innerHTML = '<div style="text-align: center; padding: 20px;">Loading wallets...</div>';
            
            CpunkUtils.logDebug('Loading wallet list from dashboard', 'info');

            // Use CpunkDashboard to get wallets
            const wallets = await CpunkDashboard.getWallets();
            const response = { status: 'ok', data: wallets };

            if (response.status === 'ok' && response.data && Array.isArray(response.data)) {
                CpunkUtils.logDebug(`Found ${response.data.length} wallets`, 'info');
                
                // Get detailed wallet data
                const walletsWithData = await Promise.all(response.data.map(async (wallet) => {
                    const walletData = await getWalletData(wallet.name);
                    return {
                        ...wallet,
                        details: walletData?.data || null
                    };
                }));

                walletsList.innerHTML = '';
                let foundWallets = false;
                let insufficientBalanceWallets = [];

                // Process each wallet - show only wallet names with their CELL and CPUNK balances
                walletsWithData.forEach(wallet => {
                    if (!wallet.details) return;

                    // Create a simplified wallet object to track balances across networks
                    const walletBalances = {
                        name: wallet.name,
                        address: '',
                        network: '',
                        cpunkBalance: 0,
                        cellBalance: 0,
                        hasBackbone: false,
                        backboneData: null
                    };

                    // First check if this wallet has a Backbone network with required tokens
                    const backboneNetwork = wallet.details.find(network => network.network === 'Backbone');
                    
                    if (backboneNetwork) {
                        walletBalances.hasBackbone = true;
                        walletBalances.address = backboneNetwork.address;
                        walletBalances.network = 'Backbone';
                        walletBalances.backboneData = backboneNetwork;
                        
                        // Find CPUNK and CELL tokens on Backbone
                        if (backboneNetwork.tokens && Array.isArray(backboneNetwork.tokens)) {
                            const cpunkToken = backboneNetwork.tokens.find(token => token.tokenName === 'CPUNK');
                            const cellToken = backboneNetwork.tokens.find(token => token.tokenName === 'CELL');
                            
                            walletBalances.cpunkBalance = parseFloat(cpunkToken?.balance || 0);
                            walletBalances.cellBalance = parseFloat(cellToken?.balance || 0);
                        }
                    }

                    // Only proceed with wallets that have Backbone network
                    if (walletBalances.hasBackbone) {
                        // Check if wallet meets minimum requirements: 0.5 CELL and 5 CPUNK
                        const meetsRequirements = walletBalances.cellBalance >= 0.5 && walletBalances.cpunkBalance >= 5;
                        
                        if (meetsRequirements) {
                            // Create a simplified wallet card that shows only wallet name and balances
                            const walletCard = document.createElement('div');
                            walletCard.className = 'wallet-card';
                            walletCard.innerHTML = `
                                <div class="wallet-name">${walletBalances.name}</div>
                                <div class="wallet-balances">
                                    <div class="balance-item">CPUNK: ${CpunkUtils.formatBalance(walletBalances.cpunkBalance)}</div>
                                    <div class="balance-item">CELL: ${CpunkUtils.formatBalance(walletBalances.cellBalance)}</div>
                                </div>
                            `;
                            
                            // Add selection behavior
                            walletCard.addEventListener('click', () => {
                                // Deselect all wallets
                                document.querySelectorAll('.wallet-card').forEach(card => {
                                    card.classList.remove('selected');
                                });
                                
                                // Select this wallet
                                walletCard.classList.add('selected');
                                
                                // Reset DNA validation
                                dnaChecked = false;
                                dnaInput.value = '';
                                dnaValidationStatus.style.display = 'none';
                                currentPrice.style.display = 'none';
                                
                                // Store wallet info
                                selectedWallet = {
                                    name: walletBalances.name,
                                    network: walletBalances.network,
                                    address: walletBalances.address,
                                    cpunkBalance: walletBalances.cpunkBalance,
                                    cellBalance: walletBalances.cellBalance
                                };
                                
                                CpunkUtils.logDebug('Wallet selected', 'info', {
                                    wallet: walletBalances.name,
                                    network: walletBalances.network,
                                    cpunkBalance: walletBalances.cpunkBalance,
                                    cellBalance: walletBalances.cellBalance
                                });
                                
                                // Update current balances
                                currentBalances.cpunk = walletBalances.cpunkBalance;
                                currentBalances.cell = walletBalances.cellBalance;
                                
                                // Update selected wallet display
                                selectedWalletDisplay.innerHTML = `
                                    <h3>Selected Wallet</h3>
                                    <div class="wallet-name">${walletBalances.name} (Backbone)</div>
                                    <div class="wallet-address">${walletBalances.address}</div>
                                    <div class="wallet-balances">
                                        <div class="balance-item">CPUNK: ${CpunkUtils.formatBalance(walletBalances.cpunkBalance)}</div>
                                        <div class="balance-item">CELL: ${CpunkUtils.formatBalance(walletBalances.cellBalance)}</div>
                                    </div>
                                `;
                                
                                // Show registration form section
                                registrationSection.style.display = 'block';
                                
                                // Update step 2 to completed
                                updateStepStatus(2, 'completed');
                                updateStepStatus(3, 'active');
                                
                                // Disable register button until DNA is checked
                                registerButton.disabled = true;
                            });
                            
                            walletsList.appendChild(walletCard);
                            foundWallets = true;
                        } else {
                            // Track wallets with insufficient balance for possible display
                            insufficientBalanceWallets.push({
                                name: walletBalances.name,
                                cpunkBalance: walletBalances.cpunkBalance,
                                cellBalance: walletBalances.cellBalance
                            });
                        }
                    }
                });

                // Show wallets section
                walletsSection.style.display = 'block';

                // Show message if no suitable wallets found
                if (!foundWallets) {
                    CpunkUtils.logDebug('No wallets found meeting the requirements', 'warning');
                    
                    let message = '';
                    
                    if (insufficientBalanceWallets.length > 0) {
                        // Show message about wallets with insufficient balance
                        message = `
                            <div style="background-color: rgba(255, 68, 68, 0.1); color: var(--error); padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px;">
                                <p>You have wallets, but they don't meet the minimum requirements:</p>
                                <p>Minimum requirements: 0.5 CELL and 5 CPUNK on Backbone network.</p>
                            </div>
                            <div style="background-color: var(--section-bg); padding: 15px; border-radius: 8px;">
                                <p><strong>Your wallets:</strong></p>
                                <ul style="list-style: none; padding: 0;">
                        `;
                        
                        // List wallets with insufficient balance
                        insufficientBalanceWallets.forEach(wallet => {
                            message += `
                                <li style="padding: 10px; margin: 5px 0; border-radius: 4px; background-color: var(--dark-bg);">
                                    <div style="font-weight: bold;">${wallet.name}</div>
                                    <div>CPUNK: ${CpunkUtils.formatBalance(wallet.cpunkBalance)} ${wallet.cpunkBalance < 5 ? '<span style="color: var(--error);">(Need at least 5)</span>' : ''}</div>
                                    <div>CELL: ${CpunkUtils.formatBalance(wallet.cellBalance)} ${wallet.cellBalance < 0.5 ? '<span style="color: var(--error);">(Need at least 0.5)</span>' : ''}</div>
                                </li>
                            `;
                        });
                        
                        message += `</ul></div>`;
                    } else {
                        // No wallets found at all
                        message = `
                            <div style="background-color: rgba(255, 68, 68, 0.1); color: var(--error); padding: 20px; border-radius: 8px; text-align: center;">
                                No wallets found in your dashboard. Please create a wallet first and ensure it has at least 0.5 CELL and 5 CPUNK on the Backbone network.
                            </div>
                        `;
                    }
                    
                    walletsList.innerHTML = message;
                }
            } else {
                throw new Error(response.errorMsg || 'Failed to load wallets');
            }
        } catch (error) {
            CpunkUtils.logDebug('Error loading wallet list', 'error', {
                message: error.message,
                stack: error.stack
            });
            
            CpunkUI.showError(`Error loading wallets: ${error.message}`);
            showDebugPanel();
            
            walletsList.innerHTML = `
                <div style="background-color: rgba(255, 68, 68, 0.1); color: var(--error); padding: 20px; border-radius: 8px; text-align: center;">
                    Error loading wallets: ${error.message}
                </div>
            `;
        } finally {
            CpunkUI.setLoading(false);
        }
    }

    // Validate DNA input - using CpunkUtils for format and availability checking
    async function validateDnaInput() {
        const nickname = dnaInput.value.trim();
        
        // Always disable register button when validating
        registerButton.disabled = true;
        
        if (!nickname) {
            dnaValidationStatus.style.display = 'none';
            currentPrice.style.display = 'none';
            return false;
        }
        
        CpunkUtils.logDebug(`Validating DNA nickname: ${nickname}`, 'info');
        
        // Check nickname format first using utility
        if (!CpunkUtils.isValidNicknameFormat(nickname)) {
            let errorMessage = t('register.invalidNickname') + " ";
            
            if (nickname.length < 3) {
                errorMessage += t('register.minCharacters');
            } else if (nickname.length > 36) {
                errorMessage += "Must be 36 characters or less.";
            } else {
                errorMessage += "Only letters, numbers, underscore (_), hyphen (-), and period (.) allowed.";
            }
            
            CpunkUtils.logDebug(`Nickname format validation failed: ${errorMessage}`, 'info');
            
            dnaValidationStatus.textContent = errorMessage;
            dnaValidationStatus.className = 'validation-message validation-error';
            dnaValidationStatus.style.display = 'block';
            currentPrice.style.display = 'none';
            return false;
        }
        
        // Calculate price based on length
        const price = CpunkUtils.calculateDnaPrice(nickname);
        CpunkUtils.logDebug(`Nickname price: ${price} CPUNK`, 'info');
        
        // Check if user has enough CPUNK balance
        if (walletAddress && currentBalances.cpunk < price) {
            CpunkUtils.logDebug(`Insufficient CPUNK balance: ${currentBalances.cpunk}/${price}`, 'warning');
            
            dnaValidationStatus.textContent = t('register.insufficientBalance', {price: price});
            dnaValidationStatus.className = 'validation-message validation-error';
            dnaValidationStatus.style.display = 'block';
            
            // Still show price, but indicate it's too expensive
            priceAmount.textContent = price;
            currentPrice.style.display = 'block';
            currentPrice.classList.add('price-unavailable');
            
            return false;
        }
        
        try {
            // Setup API tracking
            const apiRequestTime = new Date().toISOString();
            const apiRequestUrl = `dna-proxy.php?lookup=${encodeURIComponent(nickname)}`;
            const apiRequestMethod = 'GET';
            
            // Log API request to console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logRequest) {
                CpunkAPIConsole.logRequest({
                    url: apiRequestUrl,
                    method: apiRequestMethod,
                    timestamp: apiRequestTime,
                    params: { lookup: nickname }
                });
            }
            
            // Check availability using utility
            const result = await CpunkUtils.checkNicknameAvailability(nickname);
            
            // Log API response to console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logResponse) {
                CpunkAPIConsole.logResponse({
                    url: apiRequestUrl,
                    method: apiRequestMethod,
                    timestamp: new Date().toISOString(),
                    requestTime: apiRequestTime,
                    data: result,
                    status: "success"
                });
            }
            
            if (!result.isAvailable) {
                // Check if it's already registered to this wallet
                if (result.isAlreadyOwned) {
                    // This means the DNA is already registered to this wallet
                    dnaValidationStatus.textContent = `This nickname is already registered to your wallet. You can proceed to confirm ownership.`;
                    dnaValidationStatus.className = 'validation-message validation-info';
                    dnaValidationStatus.style.display = 'block';
                    
                    // Show price
                    priceAmount.textContent = price;
                    currentPrice.style.display = 'block';
                    currentPrice.classList.remove('price-unavailable');
                    
                    // Enable registration button - user can proceed with "registration" to confirm ownership
                    registerButton.disabled = false;
                    dnaChecked = true;
                    
                    CpunkUtils.logDebug(`Nickname '${nickname}' already owned by this wallet`, 'info', {
                        isAvailable: false,
                        isAlreadyOwned: true,
                        price: price
                    });
                    
                    return true;
                } else {
                    // General unavailability
                    dnaValidationStatus.textContent = t('register.alreadyTaken');
                    dnaValidationStatus.className = 'validation-message validation-unavailable';
                    dnaValidationStatus.style.display = 'block';
                }
                
                // Show price, but indicate unavailable
                priceAmount.textContent = price;
                currentPrice.style.display = 'block'; 
                currentPrice.classList.add('price-unavailable');
                
                return false;
            }
            
            // Valid and available
            dnaValidationStatus.textContent = t('register.nicknameAvailable');
            dnaValidationStatus.className = 'validation-message validation-success';
            dnaValidationStatus.style.display = 'block';
            
            // Show price
            priceAmount.textContent = price;
            currentPrice.style.display = 'block';
            currentPrice.classList.remove('price-unavailable');
            
            // Enable registration button
            registerButton.disabled = false;
            dnaChecked = true;
            
            // Update step 3 to completed
            updateStepStatus(3, 'completed');
            
            CpunkUtils.logDebug(`Nickname '${nickname}' validation successful`, 'info', {
                isAvailable: true,
                price: price,
                balanceOk: true
            });
            
            return true;
        } catch (error) {
            CpunkUtils.logDebug('Error during nickname validation', 'error', {
                nickname: nickname,
                error: error.message,
                stack: error.stack
            });
            
            // Log to API console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logError) {
                CpunkAPIConsole.logError({
                    url: `dna-proxy.php?lookup=${encodeURIComponent(nickname)}`,
                    method: 'GET',
                    timestamp: new Date().toISOString(),
                    error: error.message,
                    details: {
                        nickname: nickname,
                        stack: error.stack
                    }
                });
            }
            
            dnaValidationStatus.textContent = "Error checking nickname availability. Please try again.";
            dnaValidationStatus.className = 'validation-message validation-warning';
            dnaValidationStatus.style.display = 'block';
            currentPrice.style.display = 'none';
            
            // Show debug panel on error
            showDebugPanel();
            
            return false;
        }
    }

    // Register DNA
    async function registerDNA() {
        // Check if user is authenticated
        if (!sessionId || !walletAddress) {
            CpunkUI.showError(t('register.connectWalletFirst'));
            return;
        }

        const nickname = dnaInput.value.trim();
        if (!nickname || !dnaChecked) {
            // Revalidate in case they modified the input
            if (!await validateDnaInput()) {
                return;
            }
        }

        const price = CpunkUtils.calculateDnaPrice(nickname);
        
        // For SSO authentication, we'll need to check balance differently
        // or assume the wallet has sufficient balance since we can't check directly
        // TODO: Implement balance checking for SSO authenticated wallets

        try {
            CpunkUtils.logDebug(`Starting DNA registration for nickname: ${nickname}`, 'info', {
                wallet: walletAddress,
                network: 'Backbone', // Default to Backbone for DNA registration
                price: price
            });
            
            // Disable UI elements
            registerButton.disabled = true;
            dnaInput.disabled = true;
            CpunkUI.setLoading(true);

            // Format the payment amount correctly
            const paymentAmount = `${price}.0e+18`;

            // Hide wallet section and registration section, show transaction section
            walletsSection.style.display = 'none';
            registrationSection.style.display = 'none';
            transactionSection.style.display = 'block';
            
            // Update step 4 to active
            updateStepStatus(4, 'active');
            
            // Store the current DNA name
            currentDnaName = nickname;

            // Log transaction request to API console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logRequest) {
                CpunkAPIConsole.logRequest({
                    url: 'dashboard-api://transaction',
                    method: 'POST',
                    timestamp: new Date().toISOString(),
                    params: {
                        walletName: selectedWallet.name,
                        network: selectedWallet.network,
                        toAddress: TARGET_ADDRESS,
                        tokenName: 'CPUNK',
                        value: paymentAmount
                    }
                });
            }
            
            // Send transaction using the transaction manager
            // Get wallet name from session storage
            const walletName = sessionStorage.getItem('cpunk_selected_wallet');
            
            console.log('Transaction parameters:', {
                sessionId: sessionId,
                walletName: walletName,
                network: 'Backbone',
                toAddress: TARGET_ADDRESS,
                tokenName: 'CPUNK',
                value: paymentAmount
            });
            
            const txResult = await CpunkTransaction.sendTransaction({
                sessionId: sessionId,
                walletName: walletName,
                network: 'Backbone',
                toAddress: TARGET_ADDRESS,
                tokenName: 'CPUNK',
                value: paymentAmount
            });

            // Log transaction response to API console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logResponse) {
                CpunkAPIConsole.logResponse({
                    url: 'dashboard-api://transaction',
                    method: 'POST',
                    timestamp: new Date().toISOString(),
                    data: txResult,
                    status: txResult && txResult.txHash ? "success" : "error"
                });
            }

            // Get transaction hash
            currentTxHash = txResult.txHash;
            
            CpunkUtils.logDebug('Transaction submitted successfully', 'info', {
                txHash: currentTxHash,
                nickname: nickname
            });

            // Show transaction hash
            transactionHash.innerHTML = `
                <strong>Transaction Hash:</strong>
                <div style="margin-top: 10px;">${currentTxHash}</div>
                <button class="copy-button" style="position: relative; display: block; margin: 10px auto; width: auto;" onclick="CpunkUI.copyHash('${currentTxHash}', this)">Copy Transaction Hash</button>
            `;

            // Update step 4 to completed and activate step 5
            updateStepStatus(4, 'completed');
            updateStepStatus(5, 'active');
            
            // Start verification process using the transaction manager
            CpunkTransaction.startVerification({
                txHash: currentTxHash,
                // When verification starts
                onVerificationStart: (txHash) => {
                    // Check if element exists before setting textContent
                    if (transactionStatus) {
                        transactionStatus.textContent = `Verifying transaction...`;
                    }
                },
                // On each verification attempt
                onVerificationAttempt: (attempt, maxAttempts) => {
                    // Check if element exists before setting textContent
                    if (transactionStatus) {
                        transactionStatus.textContent = `Verifying transaction... Attempt ${attempt}/${maxAttempts}`;
                    }
                },
                // On successful verification
                onVerificationSuccess: async (txHash, attempt) => {
                    // Complete step 5
                    updateStepStatus(5, 'completed');
                    await completeDnaRegistration(nickname, walletAddress, txHash);
                },
                // On verification failure
                onVerificationFail: (txHash, attempts, error) => {
                    // Show error message
                    if (txError) {
                        txError.textContent = `Transaction verification failed after ${attempts} attempts. Please try again.`;
                        txError.style.display = 'block';
                    }
                    // Call the function to show registration failed UI
                    showRegistrationFailed(txHash, nickname, walletAddress);
                }
            });
        } catch (error) {
            CpunkUtils.logDebug('Registration error', 'error', {
                nickname: nickname,
                error: error.message,
                stack: error.stack
            });
            
            CpunkUI.showError(`Registration error: ${error.message}`);
            showDebugPanel();
            
            // Show error in result section
            walletsSection.style.display = 'none'; // Keep wallets hidden
            transactionSection.style.display = 'none';
            resultSection.style.display = 'block';
            registrationResult.className = 'result-container error';
            registrationResult.innerHTML = `
                <h3>Registration Failed</h3>
                <p>Error: ${error.message}</p>
                <p>Please try again or check your wallet balance.</p>
                <button onclick="window.location.reload()" class="action-button" style="margin-top: 20px;">Try Again</button>
            `;
        } finally {
            CpunkUI.setLoading(false);
        }
    }

    // Complete DNA registration after transaction verification
    async function completeDnaRegistration(nickname, walletAddress, txHash) {
        try {
            // Update loading message
            if (transactionStatus) {
                transactionStatus.textContent = `Transaction verified! Registering your DNA...`;
            }
            
            // Display success message
            if (txSuccess) {
                txSuccess.textContent = 'Transaction verified successfully!';
                txSuccess.style.display = 'block';
            }
            
            CpunkUtils.logDebug('Transaction verified, proceeding with DNA registration', 'info', {
                nickname: nickname,
                walletAddress: walletAddress,
                txHash: txHash
            });

            // Log DNA registration request to API console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logRequest) {
                CpunkAPIConsole.logRequest({
                    url: 'dna-proxy.php?register',
                    method: 'POST',
                    timestamp: new Date().toISOString(),
                    params: {
                        nickname: nickname,
                        walletAddress: walletAddress,
                        txHash: txHash
                    }
                });
            }
            
            // Register DNA using utility
            const result = await CpunkUtils.registerDna({
                nickname: nickname,
                walletAddress: walletAddress,
                txHash: txHash
            });
            
            // Log DNA registration response to API console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logResponse) {
                CpunkAPIConsole.logResponse({
                    url: 'dna-proxy.php?register',
                    method: 'POST',
                    timestamp: new Date().toISOString(),
                    data: result,
                    status: result && result.success ? "success" : "error"
                });
            }
            
            // Hide wallet and transaction sections, show result section
            walletsSection.style.display = 'none';
            transactionSection.style.display = 'none';
            resultSection.style.display = 'block';
            
            if (result.success) {
                // Determine which success message to show based on if already registered
                if (result.isAlreadyRegistered) {
                    CpunkUtils.logDebug('DNA registration acknowledged - already owned by this wallet', 'info', {
                        nickname: nickname,
                        walletAddress: walletAddress,
                        txHash: txHash
                    });
                    
                    // Show already registered success message
                    registrationResult.className = 'result-container success';
                    registrationResult.innerHTML = `
                        <h3>Already Registered!</h3>
                        <p>The DNA nickname <strong>${nickname}</strong> is already registered to your wallet.</p>
                        <div class="success-message">
                            <p>This nickname is already associated with your wallet address:</p>
                            <code style="display: block; margin: 10px 0; padding: 10px; background-color: var(--dark-bg); border-radius: 4px; word-break: break-all;">${walletAddress}</code>
                        </div>
                        <div style="margin-top: 20px; display: flex; gap: 10px; flex-direction: column;">
                            <a href="/${nickname}" class="action-button">View My DNA Profile</a>
                            <button onclick="window.location.href='index.html'" class="action-button" style="background-color: var(--section-bg); color: var(--primary); border: 1px solid var(--primary);">Return to Home Page</button>
                        </div>
                    `;
                } else {
                    CpunkUtils.logDebug('DNA registration successful', 'info', {
                        nickname: nickname,
                        walletAddress: walletAddress,
                        txHash: txHash
                    });
                    
                    // Show new registration success message
                    registrationResult.className = 'result-container success';
                    registrationResult.innerHTML = `
                        <h3>Registration Successful!</h3>
                        <p>Your DNA nickname <strong>${nickname}</strong> has been successfully registered!</p>
                        <div class="success-message">
                            <p>Your nickname has been associated with wallet address:</p>
                            <code style="display: block; margin: 10px 0; padding: 10px; background-color: var(--dark-bg); border-radius: 4px; word-break: break-all;">${walletAddress}</code>
                        </div>
                        <div style="margin-top: 20px; display: flex; gap: 10px; flex-direction: column;">
                            <a href="/${nickname}" class="action-button">View My DNA Profile</a>
                            <button onclick="window.location.href='index.html'" class="action-button" style="background-color: var(--section-bg); color: var(--primary); border: 1px solid var(--primary);">Return to Home Page</button>
                        </div>
                    `;
                }
            } else {
                CpunkUtils.logDebug('DNA registration issue', 'warning', {
                    nickname: nickname,
                    response: result.response
                });
                
                // Show registration failed but with different message
                registrationResult.className = 'result-container error';
                registrationResult.innerHTML = `
                    <h3>Registration Issue</h3>
                    <p>Your payment was successful, but there was an issue registering your DNA nickname.</p>
                    <p>Transaction hash: <code>${txHash}</code></p>
                    <p>Please contact support with your transaction hash and desired nickname.</p>
                    <button onclick="window.location.reload()" class="action-button" style="margin-top: 20px;">Try Again</button>
                `;
            }
        } catch (error) {
            CpunkUtils.logDebug('Error completing DNA registration', 'error', {
                nickname: nickname,
                error: error.message,
                stack: error.stack
            });
            
            // Show debug panel
            showDebugPanel();
            
            // Show registration failed but keep wallets hidden
            walletsSection.style.display = 'none';
            transactionSection.style.display = 'none';
            resultSection.style.display = 'block';
            registrationResult.className = 'result-container error';
            registrationResult.innerHTML = `
                <h3>Registration Failed</h3>
                <p>Your payment was successful, but there was an error registering your DNA nickname.</p>
                <p>Error: ${error.message}</p>
                <p>Transaction hash: <code>${txHash}</code></p>
                <p>Please contact support with your transaction hash and desired nickname.</p>
                <button onclick="window.location.reload()" class="action-button" style="margin-top: 20px;">Try Again</button>
            `;
        }
    }

    // Show registration failed UI
    function showRegistrationFailed(txHash, nickname, walletAddress) {
        CpunkUtils.logDebug('Registration failed - transaction not verified after all attempts', 'error', {
            txHash: txHash,
            nickname: nickname
        });
        
        // Hide wallet and transaction sections, show result section
        walletsSection.style.display = 'none';
        transactionSection.style.display = 'none';
        resultSection.style.display = 'block';
        
        // Show registration failed message
        registrationResult.className = 'result-container error';
        registrationResult.innerHTML = `
            <h3>Transaction Not Verified</h3>
            <p>We were unable to verify your payment transaction after multiple attempts.</p>
            <p>If your transaction completes later, please contact support to complete your registration.</p>
            <div style="background-color: var(--section-bg); padding: 15px; border-radius: 8px; margin: 15px 0;">
                <p><strong>Transaction Details:</strong></p>
                <p>Nickname: ${nickname}</p>
                <p>Wallet: ${walletAddress}</p>
                <p>Transaction: ${txHash}</p>
            </div>
            <button onclick="window.location.reload()" class="action-button" style="margin-top: 20px;">Try Again</button>
        `;
        
        // Show support message
        const supportMessage = document.getElementById('supportMessage');
        if (supportMessage) {
            supportMessage.style.display = 'block';
            supportMessage.innerHTML = `
                <h4>What to do next?</h4>
                <ol>
                    <li>Check your dashboard to confirm if the transaction was completed</li>
                    <li>If the transaction was successful, contact support with your transaction details</li>
                    <li>If the transaction failed, you can try again</li>
                </ol>
                <p><strong>Note:</strong> Keep your transaction hash for reference: ${txHash}</p>
            `;
        }
        
        // Reset transaction display elements for next attempt
        if (transactionStatus) {
            transactionStatus.textContent = "Transaction verification failed. Please try again.";
        }
    }
});