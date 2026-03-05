/**
 * CPUNK.IO DNA Registration Library
 * Main orchestrator for DNA registration functionality
 * 
 * Features:
 * - Complete DNA registration workflow
 * - SSO integration and session management
 * - Real-time validation and availability checking
 * - Transaction processing and verification
 * - UI state management
 * - Error handling and recovery
 * - Cross-domain authentication
 * 
 * @version 1.0.0
 */

class CpunkDNARegistration {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        
        // Registration state
        this.currentStep = 0;
        this.registrationData = {};
        this.selectedWallet = null;
        this.sessionId = null;
        this.transactionId = null;
        this.verificationTimer = null;
        
        // UI elements
        this.elements = {
            steps: null,
            connectButton: null,
            walletsSection: null,
            registrationSection: null,
            transactionSection: null,
            resultSection: null,
            dnaInput: null,
            priceDisplay: null,
            registerButton: null,
            statusIndicator: null
        };
        
        // Component instances
        this.components = {
            stepIndicator: null,
            walletCards: null,
            transactionStatus: null,
            priceValidator: null
        };
        
        // Configuration
        this.config = {
            steps: [
                { id: 'connect', title: 'Connect to Dashboard' },
                { id: 'wallet', title: 'Select Wallet' },
                { id: 'nickname', title: 'Choose DNA Nickname' },
                { id: 'payment', title: 'Confirm Payment' },
                { id: 'verification', title: 'Verify Transaction' }
            ],
            debounceDelay: 500,
            autoConnectSSO: true,
            enableCrossDomainSSO: true
        };
        
        // Event handlers
        this.eventHandlers = {
            stepChanged: [],
            walletSelected: [],
            nicknameValidated: [],
            registrationComplete: [],
            error: []
        };
    }

    /**
     * Initialize DNA registration system
     * @param {Object} options - Configuration options
     */
    async init(options = {}) {
        if (this.initialized) return;

        // Merge configuration
        this.config = this.core?.deepMerge(this.config, options) || { ...this.config, ...options };

        // Get required modules
        this.api = this.core?.getModule('api');
        this.wallet = this.core?.getModule('wallet');
        this.transaction = this.core?.getModule('transaction');
        this.validation = this.core?.getModule('validation');
        this.storage = this.core?.getModule('storage');
        this.sso = this.core?.getModule('sso');
        this.ui = this.core?.getModule('ui');

        // Verify required modules
        this.verifyRequiredModules();

        // Setup DOM elements
        this.setupDOMElements();
        
        // Setup UI components
        this.setupUIComponents();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Setup SSO integration
        await this.setupSSO();
        
        // Initialize registration state
        this.initializeState();

        this.initialized = true;
        this.core?.log('DNA Registration initialized');
        
        // Start the registration flow
        await this.startRegistrationFlow();
    }

    /**
     * Verify required modules are available
     */
    verifyRequiredModules() {
        const required = ['api', 'wallet', 'transaction', 'validation', 'ui'];
        const missing = required.filter(module => !this.core?.getModule(module));
        
        if (missing.length > 0) {
            throw new Error(`Required modules not available: ${missing.join(', ')}`);
        }
    }

    /**
     * Setup DOM element references
     */
    setupDOMElements() {
        this.elements = {
            steps: document.querySelector('.registration-steps'),
            connectButton: document.getElementById('connectButton'),
            statusIndicator: document.getElementById('statusIndicator'),
            walletsSection: document.getElementById('walletsSection'),
            walletsList: document.getElementById('walletsList'),
            registrationSection: document.getElementById('registrationSection'),
            dnaInput: document.getElementById('dnaInput'),
            priceDisplay: document.getElementById('currentPrice'),
            priceAmount: document.getElementById('priceAmount'),
            registerButton: document.getElementById('registerButton'),
            selectedWalletDisplay: document.getElementById('selectedWalletDisplay'),
            transactionSection: document.getElementById('transactionSection'),
            transactionStatus: document.getElementById('transactionStatus'),
            transactionHash: document.getElementById('transactionHash'),
            resultSection: document.getElementById('resultSection'),
            registrationResult: document.getElementById('registrationResult'),
            errorMessage: document.getElementById('errorMessage')
        };

        // Log missing elements for debugging
        const missingElements = Object.entries(this.elements)
            .filter(([key, element]) => !element)
            .map(([key]) => key);
        
        if (missingElements.length > 0) {
            this.core?.warn('Missing DOM elements:', missingElements);
        }
    }

    /**
     * Setup UI components
     */
    setupUIComponents() {
        // Initialize step indicator
        if (this.elements.steps && this.ui) {
            this.components.stepIndicator = this.ui.createStepIndicator(
                this.elements.steps, 
                this.config.steps
            );
        }

        // Setup real-time DNA validation if elements exist
        if (this.elements.dnaInput && this.validation) {
            this.setupDNAValidation();
        }
    }

    /**
     * Setup DNA validation with real-time checking
     */
    setupDNAValidation() {
        const validator = async (nickname) => {
            try {
                // Format validation first
                const formatResult = this.validation.validateDNAFormat(nickname);
                if (!formatResult.valid) {
                    return formatResult;
                }

                // Check availability
                const availabilityResult = await this.validation.validateDNAAvailability(
                    nickname,
                    async (name) => {
                        const response = await this.api.checkDNAAvailability(name);
                        return response.error && response.error.includes('not found');
                    }
                );

                return availabilityResult;
            } catch (error) {
                return {
                    valid: false,
                    errors: ['Unable to validate nickname'],
                    available: null
                };
            }
        };

        this.components.priceValidator = this.validation.createRealTimeValidator(
            this.elements.dnaInput,
            validator,
            {
                debounceMs: this.config.debounceDelay,
                showSuccess: true,
                showErrors: true
            }
        );

        // Listen for validation events to update pricing
        this.elements.dnaInput.addEventListener('validation', (event) => {
            this.handleDNAValidation(event.detail);
        });
    }

    /**
     * Handle DNA validation results
     * @param {Object} validationResult - Validation result
     */
    handleDNAValidation(validationResult) {
        const { result, value } = validationResult;
        
        if (result.valid && result.available) {
            // Update price display
            const price = this.validation.calculateDNAPrice(value);
            this.updatePriceDisplay(price);
            
            // Enable register button
            if (this.elements.registerButton) {
                this.elements.registerButton.disabled = false;
            }
        } else {
            // Hide price display and disable button
            this.hidePriceDisplay();
            if (this.elements.registerButton) {
                this.elements.registerButton.disabled = true;
            }
        }

        this.emit('nicknameValidated', { nickname: value, result });
    }

    /**
     * Update price display
     * @param {number} price - Price in CPUNK
     */
    updatePriceDisplay(price) {
        if (this.elements.priceDisplay && this.elements.priceAmount) {
            this.elements.priceAmount.textContent = price;
            this.elements.priceDisplay.style.display = 'block';
        }
    }

    /**
     * Hide price display
     */
    hidePriceDisplay() {
        if (this.elements.priceDisplay) {
            this.elements.priceDisplay.style.display = 'none';
        }
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Connect button
        if (this.elements.connectButton) {
            this.elements.connectButton.addEventListener('click', () => {
                this.handleConnect();
            });
        }

        // Register button
        if (this.elements.registerButton) {
            this.elements.registerButton.addEventListener('click', () => {
                this.handleRegister();
            });
        }

        // Listen to wallet events
        if (this.wallet) {
            this.wallet.on('connected', (data) => this.handleWalletConnected(data));
            this.wallet.on('walletSelected', (data) => this.handleWalletSelected(data));
            this.wallet.on('error', (data) => this.handleWalletError(data));
        }

        // Listen to transaction events
        if (this.transaction) {
            this.transaction.on('submitted', (data) => this.handleTransactionSubmitted(data));
            this.transaction.on('verified', (data) => this.handleTransactionVerified(data));
            this.transaction.on('failed', (data) => this.handleTransactionFailed(data));
            this.transaction.on('progress', (data) => this.handleTransactionProgress(data));
        }

        // Listen to SSO events
        if (this.sso) {
            this.sso.on('authenticated', (data) => this.handleSSOAuthenticated(data));
            this.sso.on('unauthenticated', (data) => this.handleSSOUnauthenticated(data));
        }
    }

    /**
     * Setup SSO integration
     */
    async setupSSO() {
        if (!this.sso || !this.config.enableCrossDomainSSO) return;

        try {
            // Initialize SSO client
            await this.sso.init({
                enableAutoSync: true,
                domains: {
                    club: 'https://cpunk.club',
                    io: 'https://cpunk.io'
                }
            });

            // Check if already authenticated
            if (this.sso.isUserAuthenticated()) {
                const userData = this.sso.getCurrentUser();
                this.core?.log('SSO session found:', userData);
            }

        } catch (error) {
            this.core?.warn('SSO setup failed:', error.message);
        }
    }

    /**
     * Initialize registration state
     */
    initializeState() {
        this.currentStep = 0;
        this.registrationData = {};
        
        // Update step indicator
        this.updateStepStatus(0, 'active');
    }

    /**
     * Start the registration flow
     */
    async startRegistrationFlow() {
        // Check for existing SSO session first
        if (this.sso && this.sso.isUserAuthenticated()) {
            const sessionData = this.sso.getSessionData();
            if (sessionData && sessionData.sessionId) {
                // Skip to wallet selection or nickname input
                await this.restoreFromSSO(sessionData);
                return;
            }
        }

        // Start from connection step
        this.showStep('connect');
    }

    /**
     * Restore state from SSO session
     * @param {Object} sessionData - SSO session data
     */
    async restoreFromSSO(sessionData) {
        try {
            this.sessionId = sessionData.sessionId;
            
            // Update connection status
            this.updateConnectionStatus('connected', 'Connected');
            this.updateStepStatus(0, 'completed');
            
            // If wallet is already selected, skip to nickname input
            if (sessionData.walletName && sessionData.walletAddress) {
                this.selectedWallet = {
                    name: sessionData.walletName,
                    address: sessionData.walletAddress,
                    network: sessionData.network,
                    cpunkBalance: sessionData.balances?.cpunk || 0,
                    cellBalance: sessionData.balances?.cell || 0
                };
                
                this.updateStepStatus(1, 'completed');
                this.updateSelectedWalletDisplay();
                this.showStep('nickname');
            } else {
                // Show wallet selection
                await this.loadWallets();
                this.showStep('wallet');
            }

        } catch (error) {
            this.core?.error('Failed to restore from SSO:', error);
            this.showError('Failed to restore session. Please reconnect.');
        }
    }

    /**
     * Event Handlers
     */

    /**
     * Handle connect button click
     */
    async handleConnect() {
        try {
            this.showLoading('Connecting to dashboard...');
            
            const result = await this.wallet.connect();
            
            if (result.success) {
                this.sessionId = result.sessionId;
                this.updateConnectionStatus('connected', 'Connected');
                this.updateStepStatus(0, 'completed');
                
                // Load wallets and proceed to next step
                await this.loadWallets();
                this.showStep('wallet');
            }

        } catch (error) {
            this.core?.error('Connection failed:', error);
            this.showError(`Connection failed: ${error.message}`);
            this.updateConnectionStatus('disconnected', 'Connection Failed');
        } finally {
            this.hideLoading();
        }
    }

    /**
     * Handle wallet connected event
     */
    async handleWalletConnected(data) {
        this.sessionId = data.sessionId;
        this.updateConnectionStatus('connected', 'Connected');
        this.updateStepStatus(0, 'completed');
        
        // Automatically load wallets and show selection
        await this.loadWallets();
        this.showStep('wallet');
    }

    /**
     * Handle wallet selection
     */
    async handleWalletSelected(data) {
        try {
            this.selectedWallet = data.wallet;
            this.updateStepStatus(1, 'completed');
            this.updateSelectedWalletDisplay();
            
            // Create SSO session if not exists
            if (this.sso && !this.sso.isUserAuthenticated()) {
                await this.createSSOSession();
            }
            
            this.showStep('nickname');
            
        } catch (error) {
            this.core?.error('Wallet selection failed:', error);
            this.showError('Failed to select wallet');
        }
    }

    /**
     * Handle register button click
     */
    async handleRegister() {
        try {
            const nickname = this.elements.dnaInput?.value?.trim();
            if (!nickname) {
                this.showError('Please enter a DNA nickname');
                return;
            }

            // Final validation
            const validation = this.validation.validateDNAFormat(nickname);
            if (!validation.valid) {
                this.showError(validation.errors[0]);
                return;
            }

            // Check balance
            const price = this.validation.calculateDNAPrice(nickname);
            if (!this.selectedWallet || this.selectedWallet.cpunkBalance < price) {
                this.showError(`Insufficient CPUNK balance. Required: ${price} CPUNK`);
                return;
            }

            // Store registration data
            this.registrationData = {
                nickname,
                price,
                walletName: this.selectedWallet.name,
                walletAddress: this.selectedWallet.address,
                sessionId: this.sessionId
            };

            // Proceed to payment
            await this.processPayment();

        } catch (error) {
            this.core?.error('Registration failed:', error);
            this.showError(`Registration failed: ${error.message}`);
        }
    }

    /**
     * Process payment transaction
     */
    async processPayment() {
        try {
            this.updateStepStatus(2, 'completed');
            this.updateStepStatus(3, 'active');
            this.showStep('transaction');

            // Submit transaction
            const result = await this.transaction.sendTransaction({
                toAddress: this.core.config.blockchain.treasuryAddress,
                tokenName: 'CPUNK',
                amount: this.registrationData.price,
                walletName: this.registrationData.walletName,
                sessionId: this.registrationData.sessionId,
                metadata: {
                    type: 'dna_registration',
                    nickname: this.registrationData.nickname
                }
            });

            if (result.success) {
                this.transactionId = result.transactionId;
                this.registrationData.txHash = result.hash;
                
                this.updateStepStatus(3, 'completed');
                this.updateStepStatus(4, 'active');
                
                // Transaction verification will be handled by event listeners
            }

        } catch (error) {
            this.core?.error('Payment failed:', error);
            this.showTransactionError(`Payment failed: ${error.message}`);
        }
    }

    /**
     * Handle transaction submitted event
     */
    handleTransactionSubmitted(data) {
        const { transaction } = data;
        
        // Update transaction display
        if (this.elements.transactionHash) {
            this.elements.transactionHash.innerHTML = `
                <strong>Transaction Hash:</strong>
                <div style="margin-top: 10px; word-break: break-all;">${transaction.hash}</div>
                <button class="copy-button" onclick="window.CpunkIO.getModule('ui').copyToClipboard('${transaction.hash}', this)">
                    Copy Hash
                </button>
            `;
        }

        this.updateTransactionStatus('Transaction submitted. Waiting for verification...');
    }

    /**
     * Handle transaction progress event
     */
    handleTransactionProgress(data) {
        const { attempt, maxAttempts, status } = data;
        this.updateTransactionStatus(`Verifying transaction... (Attempt ${attempt}/${maxAttempts})`);
    }

    /**
     * Handle transaction verified event
     */
    async handleTransactionVerified(data) {
        try {
            const { transaction } = data;
            
            this.updateTransactionStatus('Transaction verified! Registering DNA...');
            
            // Register DNA with backend
            const registrationResult = await this.api.registerDNA({
                nickname: this.registrationData.nickname,
                walletAddress: this.registrationData.walletAddress,
                txHash: transaction.hash
            });

            // Complete registration
            this.completeRegistration(registrationResult);

        } catch (error) {
            this.core?.error('DNA registration failed:', error);
            this.showTransactionError(`DNA registration failed: ${error.message}`);
        }
    }

    /**
     * Handle transaction failed event
     */
    handleTransactionFailed(data) {
        const { error, timeout } = data;
        
        if (timeout) {
            this.showTransactionError(
                'Transaction verification timed out. Please check your wallet for the transaction status.',
                true // Show support info
            );
        } else {
            this.showTransactionError(`Transaction failed: ${error}`);
        }
    }

    /**
     * Complete registration process
     * @param {Object} result - Registration result from backend
     */
    completeRegistration(result) {
        this.updateStepStatus(4, 'completed');
        this.showStep('result');

        const { nickname } = this.registrationData;

        if (result.success || result.message?.includes('success')) {
            // Success result
            if (this.elements.registrationResult) {
                this.elements.registrationResult.className = 'result-container success';
                this.elements.registrationResult.innerHTML = `
                    <h3>🎉 DNA Registration Successful!</h3>
                    <p>Your DNA nickname <strong>${nickname}</strong> has been successfully registered!</p>
                    <div class="success-message">
                        <p>Your DNA is now associated with:</p>
                        <div style="background: rgba(10, 10, 10, 0.8); padding: 10px; border-radius: 4px; margin: 10px 0; word-break: break-all; font-family: 'Courier New', monospace;">
                            ${this.registrationData.walletAddress}
                        </div>
                    </div>
                    <div style="margin-top: 20px; display: flex; gap: 10px; flex-direction: column;">
                        <a href="https://cpunk.club/${nickname}" class="btn" target="_blank" rel="noopener">View DNA Profile</a>
                        <a href="/" class="btn" style="background: rgba(26, 26, 26, 0.8); color: var(--accent-primary); border: 1px solid var(--accent-primary);">Continue on CPUNK.IO</a>
                    </div>
                `;
            }

            this.emit('registrationComplete', { 
                nickname, 
                walletAddress: this.registrationData.walletAddress,
                txHash: this.registrationData.txHash 
            });

        } else {
            // Error result
            this.showRegistrationError(result.error || 'Unknown registration error');
        }
    }

    /**
     * UI Helper Methods
     */

    /**
     * Show specific step
     * @param {string} stepName - Step name
     */
    showStep(stepName) {
        // Hide all sections
        const sections = [
            this.elements.walletsSection,
            this.elements.registrationSection,
            this.elements.transactionSection,
            this.elements.resultSection
        ];

        sections.forEach(section => {
            if (section) section.style.display = 'none';
        });

        // Show appropriate section
        switch (stepName) {
            case 'connect':
                // Connection UI is always visible
                break;
            case 'wallet':
                if (this.elements.walletsSection) {
                    this.elements.walletsSection.style.display = 'block';
                }
                break;
            case 'nickname':
                if (this.elements.registrationSection) {
                    this.elements.registrationSection.style.display = 'block';
                }
                break;
            case 'transaction':
                if (this.elements.transactionSection) {
                    this.elements.transactionSection.style.display = 'block';
                }
                break;
            case 'result':
                if (this.elements.resultSection) {
                    this.elements.resultSection.style.display = 'block';
                }
                break;
        }

        this.currentStep = this.config.steps.findIndex(step => step.id === stepName);
    }

    /**
     * Update step status
     * @param {number} stepIndex - Step index
     * @param {string} status - Status
     */
    updateStepStatus(stepIndex, status) {
        if (this.components.stepIndicator) {
            this.ui.updateStepStatus(this.components.stepIndicator, stepIndex, status);
        }
    }

    /**
     * Update connection status
     * @param {string} status - Status
     * @param {string} text - Status text
     */
    updateConnectionStatus(status, text) {
        if (this.elements.statusIndicator) {
            this.elements.statusIndicator.textContent = text;
            this.elements.statusIndicator.className = `status-indicator status-${status}`;
        }

        if (this.elements.connectButton) {
            this.elements.connectButton.textContent = status === 'connected' ? 'Reconnect' : 'Connect';
        }
    }

    /**
     * Load and display wallets
     */
    async loadWallets() {
        try {
            const wallets = await this.wallet.getWallets();
            
            if (wallets.length === 0) {
                throw new Error('No wallets found');
            }

            // Create wallet cards
            if (this.elements.walletsList && this.ui) {
                this.components.walletCards = this.ui.createWalletCards(
                    this.elements.walletsList,
                    wallets,
                    {
                        onSelect: (wallet) => {
                            this.wallet.selectWallet(wallet);
                        }
                    }
                );
            }

        } catch (error) {
            this.core?.error('Failed to load wallets:', error);
            this.showError(`Failed to load wallets: ${error.message}`);
        }
    }

    /**
     * Update selected wallet display
     */
    updateSelectedWalletDisplay() {
        if (!this.elements.selectedWalletDisplay || !this.selectedWallet) return;

        this.elements.selectedWalletDisplay.innerHTML = `
            <h3>Selected Wallet</h3>
            <div class="wallet-name">${this.selectedWallet.name}</div>
            <div class="wallet-balances">
                <div class="balance-item">CPUNK: ${this.wallet.formatBalance(this.selectedWallet.cpunkBalance, 'CPUNK')}</div>
                <div class="balance-item">CELL: ${this.wallet.formatBalance(this.selectedWallet.cellBalance, 'CELL')}</div>
            </div>
        `;
    }

    /**
     * Update transaction status message
     * @param {string} message - Status message
     */
    updateTransactionStatus(message) {
        if (this.elements.transactionStatus) {
            this.elements.transactionStatus.textContent = message;
        }
    }

    /**
     * Show loading state
     * @param {string} message - Loading message
     */
    showLoading(message = 'Loading...') {
        if (this.ui) {
            this.ui.showNotification(message, 'info', { duration: 0 });
        }
    }

    /**
     * Hide loading state
     */
    hideLoading() {
        // Loading notifications will auto-hide or be replaced
    }

    /**
     * Show error message
     * @param {string} message - Error message
     */
    showError(message) {
        if (this.ui) {
            this.ui.showNotification(message, 'error');
        }

        if (this.elements.errorMessage) {
            this.elements.errorMessage.textContent = message;
            this.elements.errorMessage.style.display = 'block';
            
            setTimeout(() => {
                this.elements.errorMessage.style.display = 'none';
            }, 5000);
        }

        this.emit('error', { message });
    }

    /**
     * Show transaction error
     * @param {string} message - Error message
     * @param {boolean} showSupport - Show support information
     */
    showTransactionError(message, showSupport = false) {
        if (this.elements.transactionSection) {
            this.elements.transactionSection.style.display = 'none';
        }
        if (this.elements.resultSection) {
            this.elements.resultSection.style.display = 'block';
        }

        if (this.elements.registrationResult) {
            this.elements.registrationResult.className = 'result-container error';
            this.elements.registrationResult.innerHTML = `
                <h3>Transaction Error</h3>
                <p>${message}</p>
                ${this.registrationData.txHash ? `
                    <div style="background: rgba(26, 26, 26, 0.8); padding: 15px; border-radius: 8px; margin: 15px 0;">
                        <p><strong>Transaction Hash:</strong></p>
                        <div style="word-break: break-all; font-family: 'Courier New', monospace; margin-top: 5px;">
                            ${this.registrationData.txHash}
                        </div>
                    </div>
                ` : ''}
                ${showSupport ? `
                    <p>If your transaction completed, please contact support with the transaction hash above.</p>
                ` : ''}
                <button onclick="window.location.reload()" class="btn" style="margin-top: 20px;">Try Again</button>
            `;
        }
    }

    /**
     * Show registration error
     * @param {string} message - Error message
     */
    showRegistrationError(message) {
        if (this.elements.registrationResult) {
            this.elements.registrationResult.className = 'result-container error';
            this.elements.registrationResult.innerHTML = `
                <h3>Registration Failed</h3>
                <p>${message}</p>
                ${this.registrationData.txHash ? `
                    <p>Transaction Hash: <code>${this.registrationData.txHash}</code></p>
                    <p>Please contact support with this transaction hash.</p>
                ` : ''}
                <button onclick="window.location.reload()" class="btn" style="margin-top: 20px;">Try Again</button>
            `;
        }
    }

    /**
     * SSO Integration Methods
     */

    /**
     * Create SSO session from current state
     */
    async createSSOSession() {
        if (!this.sso || !this.selectedWallet || !this.sessionId) return;

        try {
            await this.sso.authenticate({
                sessionId: this.sessionId,
                dna: this.registrationData.nickname || 'pending',
                walletName: this.selectedWallet.name,
                walletAddress: this.selectedWallet.address,
                network: this.selectedWallet.network || 'Backbone',
                balances: {
                    cpunk: this.selectedWallet.cpunkBalance,
                    cell: this.selectedWallet.cellBalance
                }
            });

            this.core?.log('SSO session created successfully');

        } catch (error) {
            this.core?.warn('Failed to create SSO session:', error.message);
        }
    }

    /**
     * Handle SSO authentication event
     */
    handleSSOAuthenticated(data) {
        this.core?.log('SSO authenticated:', data.user);
        // Session data is automatically synced
    }

    /**
     * Handle SSO unauthentication event
     */
    handleSSOUnauthenticated(data) {
        this.core?.log('SSO unauthenticated');
        // Clear local session data if needed
        if (!data.logout) {
            // Session expired or invalid, may need to reconnect
        }
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
        this.core?.emit(`dna:${event}`, data);
    }

    /**
     * Public API
     */

    /**
     * Get registration status
     * @returns {Object} Current status
     */
    getStatus() {
        return {
            initialized: this.initialized,
            currentStep: this.currentStep,
            connected: !!this.sessionId,
            walletSelected: !!this.selectedWallet,
            transactionId: this.transactionId,
            registrationData: this.registrationData
        };
    }

    /**
     * Reset registration state
     */
    reset() {
        // Clear verification timer
        if (this.verificationTimer) {
            clearTimeout(this.verificationTimer);
            this.verificationTimer = null;
        }

        // Reset state
        this.currentStep = 0;
        this.registrationData = {};
        this.selectedWallet = null;
        this.transactionId = null;

        // Reset UI
        this.initializeState();
        this.showStep('connect');
        this.updateConnectionStatus('disconnected', 'Disconnected');

        // Clear form
        if (this.elements.dnaInput) {
            this.elements.dnaInput.value = '';
        }

        this.core?.log('DNA Registration reset');
    }

    /**
     * Clean up resources
     */
    destroy() {
        // Clear timers
        if (this.verificationTimer) {
            clearTimeout(this.verificationTimer);
        }

        // Cleanup validators
        if (this.components.priceValidator) {
            this.components.priceValidator();
        }

        // Clear state
        this.eventHandlers = {};
        this.elements = {};
        this.components = {};

        this.initialized = false;
        this.core?.log('DNA Registration destroyed');
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('dnaRegistration', new CpunkDNARegistration(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkDNARegistration;
}