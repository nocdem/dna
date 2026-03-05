/**
 * CPUNK DNA Registration Flow Library v1.0
 * Manages the complete DNA registration process
 * 
 * Dependencies: CPUNKWalletConnector, CPUNKDebugConsole
 * Features: Flow management, Validation, Retry logic, Error handling
 */

class CPUNKDNARegistration {
    constructor(config = {}) {
        // Required dependencies
        this.walletConnector = config.walletConnector;
        this.console = config.console || null;
        
        if (!this.walletConnector) {
            throw new Error('WalletConnector is required');
        }
        
        // Configuration
        this.proxyUrl = config.proxyUrl || 'dna-proxy.php';
        this.price = config.price || 5.0; // CPUNK
        this.currency = config.currency || 'CPUNK';
        
        // Registration flow state
        this.state = {
            phase: 'idle', // 'idle', 'validating', 'checking-balance', 'paying', 'verifying', 'registering', 'complete', 'error'
            nickname: null,
            walletName: null,
            walletAddress: null,
            txHash: null,
            attempts: 0,
            errors: [],
            startTime: null,
            completionTime: null,
            phaseStartTime: null
        };

        // Configuration options
        this.config = {
            maxAttempts: 10,
            timeouts: {
                availability: 30000,  // 30 seconds (increased from 10)
                transaction: 30000,   // 30 seconds
                verification: 30000,  // 30 seconds per attempt
                registration: 120000  // 120 seconds (increased for backend processing)
            },
            retryDelays: [15000, 30000, 30000, 30000, 30000, 60000, 60000, 60000, 60000, 60000], // 1st: 15s, 2-5: 30s, 6-10: 60s
            nicknameRules: {
                minLength: 3,
                maxLength: 20,
                pattern: /^[a-zA-Z0-9_]+$/,
                forbiddenWords: ['admin', 'root', 'system', 'cpunk', 'null', 'undefined']
            }
        };

        // Event handlers
        this.eventHandlers = {};
        
        // Initialize
        this.log('DNA Registration library initialized', {
            version: '1.0',
            proxyUrl: this.proxyUrl,
            price: this.price
        });
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

    // Logging wrapper
    log(message, data = null, level = 'info') {
        if (this.console) {
            this.console.log(`[DNARegistration] ${message}`, data, level);
        } else {
            console.log(`[DNARegistration] ${message}`, data);
        }
    }

    // Main Registration Flow
    async register(nickname) {
        try {
            this.resetState();
            this.state.nickname = nickname;
            this.state.startTime = Date.now();
            
            this.log('Starting DNA registration', { nickname });
            
            if (this.console) {
                this.console.trackPhase('registration', 'start', { nickname });
            }

            // Phase 1: Validation
            await this.validateNickname(nickname);
            
            // Phase 2: Availability check
            await this.checkAvailability(nickname);
            
            // Phase 3: Balance verification
            await this.checkBalance();
            
            // Phase 4: Payment processing
            const txHash = await this.processPayment();
            
            // Phase 5: Transaction verification
            await this.verifyTransaction(txHash);
            
            // Phase 6: Registration completion
            await this.completeRegistration();
            
            // Success
            this.updatePhase('complete');
            this.state.completionTime = Date.now();
            
            const result = {
                success: true,
                nickname: this.state.nickname,
                txHash: this.state.txHash,
                walletAddress: this.state.walletAddress,
                duration: this.state.completionTime - this.state.startTime,
                phases: this.getPhaseTimings()
            };
            
            this.log('DNA registration completed successfully', result);
            
            if (this.console) {
                this.console.trackPhase('registration', 'complete', result);
            }
            
            this.emit('registration-complete', result);
            
            return result;
            
        } catch (error) {
            this.handleRegistrationError(error);
            throw error;
        }
    }

    // Phase 1: Nickname Validation
    async validateNickname(nickname) {
        this.updatePhase('validating');
        
        this.log('Validating nickname', { nickname });
        
        // Length check
        if (!nickname || nickname.length < this.config.nicknameRules.minLength) {
            throw new Error(`Nickname must be at least ${this.config.nicknameRules.minLength} characters long`);
        }
        
        if (nickname.length > this.config.nicknameRules.maxLength) {
            throw new Error(`Nickname cannot exceed ${this.config.nicknameRules.maxLength} characters`);
        }
        
        // Pattern check
        if (!this.config.nicknameRules.pattern.test(nickname)) {
            throw new Error('Nickname can only contain letters, numbers, and underscores');
        }
        
        // Forbidden words check
        const lowerNickname = nickname.toLowerCase();
        for (const forbiddenWord of this.config.nicknameRules.forbiddenWords) {
            if (lowerNickname.includes(forbiddenWord)) {
                throw new Error(`Nickname cannot contain "${forbiddenWord}"`);
            }
        }
        
        this.log('Nickname validation passed', { nickname });
        
        return true;
    }

    // Phase 2: Availability Check
    async checkAvailability(nickname) {
        this.updatePhase('checking-availability');
        
        this.log('Checking nickname availability', { nickname });
        
        try {
            const response = await this.makeAPIRequest('GET', `lookup=${encodeURIComponent(nickname)}`, {
                timeout: this.config.timeouts.availability
            });
            
            // If found, it means the nickname is taken
            if (response && response.status_code !== -1 && !response.error) {
                throw new Error(`Nickname "${nickname}" is already taken`);
            }
            
            // If we get a "not found" error, that's good - it's available
            if (response && (response.status_code === -1 || response.message === 'NOK')) {
                this.log('Nickname is available', { nickname });
                return true;
            }
            
            // Unexpected response
            throw new Error('Unable to verify nickname availability');
            
        } catch (error) {
            if (error.message.includes('already taken')) {
                throw error;
            }
            
            this.log('Availability check error', { nickname, error: error.message }, 'warn');
            throw new Error(`Failed to check availability: ${error.message}`);
        }
    }

    // Phase 3: Balance Check
    async checkBalance() {
        this.updatePhase('checking-balance');
        
        this.log('Checking wallet balance');
        
        // Ensure wallet is selected and connected
        if (!this.walletConnector.isConnected()) {
            throw new Error('Wallet not connected');
        }
        
        const selectedWallet = this.walletConnector.getSelectedWallet();
        if (!selectedWallet) {
            throw new Error('No wallet selected');
        }
        
        this.state.walletName = selectedWallet.name;
        this.state.walletAddress = selectedWallet.address;
        
        // Get current balance
        const balance = this.walletConnector.getBalance(this.currency);
        
        this.log('Current balance', {
            wallet: this.state.walletName,
            balance: balance,
            currency: this.currency,
            required: this.price
        });
        
        if (balance < this.price) {
            throw new Error(`Insufficient ${this.currency} balance: ${balance} (required: ${this.price})`);
        }
        
        return true;
    }

    // Phase 4: Payment Processing
    async processPayment() {
        this.updatePhase('paying');
        
        this.log('Processing payment', {
            amount: this.price,
            currency: this.currency,
            wallet: this.state.walletName
        });
        
        try {
            const result = await this.walletConnector.sendTransaction({
                amount: this.price,
                token: this.currency,
                walletName: this.state.walletName
            });
            
            if (!result.success) {
                throw new Error('Transaction failed: ' + (result.error || 'Unknown error'));
            }
            
            this.state.txHash = result.txHash;
            
            this.log('Payment transaction sent', {
                txHash: result.txHash,
                amount: this.price,
                duration: result.duration
            });
            
            return result.txHash;
            
        } catch (error) {
            this.log('Payment processing failed', { error: error.message }, 'error');
            throw new Error(`Payment failed: ${error.message}`);
        }
    }

    // Phase 5: Transaction Verification
    async verifyTransaction(txHash) {
        this.updatePhase('verifying');
        
        this.log('Starting transaction verification', { txHash });
        
        for (let attempt = 1; attempt <= this.config.maxAttempts; attempt++) {
            this.state.attempts = attempt;
            
            try {
                this.log(`Verification attempt ${attempt}/${this.config.maxAttempts}`, { txHash });
                
                if (this.console) {
                    this.console.startTimer(`verification-attempt-${attempt}`);
                }
                
                const response = await this.makeAPIRequest('GET', `tx_validate=${encodeURIComponent(txHash)}`, {
                    timeout: this.config.timeouts.verification
                });
                
                const duration = this.console ? this.console.endTimer(`verification-attempt-${attempt}`) : null;
                
                if (this.console) {
                    this.console.trackVerification(attempt, response?.status_code === 0, duration, txHash);
                }
                
                // Check if verification succeeded
                if (response && response.status_code === 0 && response.message === 'OK') {
                    this.log('Transaction verification successful', {
                        txHash,
                        attempt,
                        duration: duration ? `${duration}ms` : 'unknown',
                        details: response.transaction_details
                    });
                    
                    return true;
                }
                
                // Log verification failure
                const errorMsg = response?.description || response?.message || 'Unknown verification error';
                this.log(`Verification attempt ${attempt} failed`, {
                    txHash,
                    error: errorMsg,
                    response
                }, 'warn');
                
                // If not the last attempt, wait before retrying
                if (attempt < this.config.maxAttempts) {
                    const delay = this.config.retryDelays[attempt - 1] || 30000;
                    this.log(`Waiting ${delay}ms before next attempt`, { attempt, delay });
                    
                    this.emit('verification-retry', {
                        attempt,
                        maxAttempts: this.config.maxAttempts,
                        delay,
                        error: errorMsg
                    });
                    
                    await this.delay(delay);
                }
                
            } catch (error) {
                const duration = this.console ? this.console.endTimer(`verification-attempt-${attempt}`) : null;
                
                if (this.console) {
                    this.console.trackVerification(attempt, false, duration, txHash);
                }
                
                this.log(`Verification attempt ${attempt} error`, {
                    txHash,
                    error: error.message
                }, 'warn');
                
                // If it's the last attempt or a critical error, fail
                if (attempt === this.config.maxAttempts || error.message.includes('timeout')) {
                    throw error;
                }
                
                // Wait before retrying on error
                const delay = this.config.retryDelays[attempt - 1] || 30000;
                await this.delay(delay);
            }
        }
        
        // All attempts failed
        throw new Error(`Transaction verification failed after ${this.config.maxAttempts} attempts`);
    }

    // Phase 6: Registration Completion
    async completeRegistration() {
        this.updatePhase('registering');
        
        this.log('Completing DNA registration', {
            nickname: this.state.nickname,
            wallet: this.state.walletAddress,
            txHash: this.state.txHash
        });
        
        try {
            const response = await this.makeAPIRequest('POST', null, {
                timeout: this.config.timeouts.registration,
                body: {
                    action: 'add',
                    name: this.state.nickname,
                    wallet: this.state.walletAddress,
                    tx_hash: this.state.txHash
                }
            });
            
            if (!response || response.status_code !== 0) {
                const error = response?.description || response?.message || 'Registration failed';
                throw new Error(error);
            }
            
            this.log('DNA registration completed', {
                nickname: this.state.nickname,
                response
            });
            
            return response;
            
        } catch (error) {
            this.log('Registration completion failed', {
                error: error.message,
                nickname: this.state.nickname,
                txHash: this.state.txHash
            }, 'error');
            
            throw new Error(`Registration failed: ${error.message}`);
        }
    }

    // Utility Methods
    async makeAPIRequest(method, params, options = {}) {
        const url = params ? `${this.proxyUrl}?${params}` : this.proxyUrl;
        
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), options.timeout || 30000);
        
        try {
            if (this.console) {
                this.console.startTimer('api-request');
            }
            
            const fetchOptions = {
                method,
                signal: controller.signal,
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            };
            
            if (options.body) {
                fetchOptions.body = JSON.stringify(options.body);
            }
            
            this.log(`Making ${method} request`, {
                url: url.replace(this.proxyUrl, '[PROXY]'),
                body: options.body ? 'present' : 'none',
                timeout: options.timeout || 30000
            }, 'debug');
            
            const response = await fetch(url, fetchOptions);
            
            const duration = this.console ? this.console.endTimer('api-request') : null;
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (this.console) {
                this.console.trackAPICall(method, url, duration, data);
            }
            
            this.log('API request completed', {
                method,
                status: response.status,
                duration: duration ? `${duration}ms` : 'unknown',
                success: !data.error
            }, 'debug');
            
            return data;
            
        } catch (error) {
            const duration = this.console ? this.console.endTimer('api-request') : null;
            
            if (this.console) {
                this.console.trackAPICall(method, url, duration, { error: error.message });
            }
            
            if (error.name === 'AbortError') {
                throw new Error(`Request timeout after ${options.timeout || 30000}ms`);
            }
            
            throw error;
        } finally {
            clearTimeout(timeout);
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // State Management
    updatePhase(phase) {
        const previousPhase = this.state.phase;
        const now = Date.now();
        
        // Track phase duration if we have a previous phase
        if (previousPhase !== 'idle' && this.state.phaseStartTime) {
            const phaseDuration = now - this.state.phaseStartTime;
            
            if (this.console) {
                this.console.trackPhase(previousPhase, 'complete', {
                    duration: phaseDuration
                });
            }
            
            this.log(`Phase ${previousPhase} completed`, {
                duration: `${phaseDuration}ms`
            }, 'debug');
        }
        
        this.state.phase = phase;
        this.state.phaseStartTime = now;
        
        if (this.console) {
            this.console.trackPhase(phase, 'start');
        }
        
        this.log(`Phase changed to: ${phase}`);
        
        this.emit('phase-change', {
            phase,
            previousPhase,
            progress: this.getProgress()
        });
    }

    resetState() {
        this.state = {
            phase: 'idle',
            nickname: null,
            walletName: null,
            walletAddress: null,
            txHash: null,
            attempts: 0,
            errors: [],
            startTime: null,
            completionTime: null,
            phaseStartTime: null
        };
    }

    handleRegistrationError(error) {
        this.state.errors.push({
            phase: this.state.phase,
            message: error.message,
            timestamp: Date.now()
        });
        
        this.updatePhase('error');
        
        if (this.console) {
            this.console.trackPhase(this.state.phase, 'error', {
                error: error.message
            });
        }
        
        this.log('Registration error', {
            phase: this.state.phase,
            error: error.message,
            nickname: this.state.nickname,
            txHash: this.state.txHash
        }, 'error');
        
        this.emit('registration-error', {
            error: error.message,
            phase: this.state.phase,
            state: { ...this.state }
        });
    }

    // Progress and Status
    getProgress() {
        const phases = ['idle', 'validating', 'checking-availability', 'checking-balance', 'paying', 'verifying', 'registering', 'complete'];
        const currentIndex = phases.indexOf(this.state.phase);
        
        return {
            phase: this.state.phase,
            percentage: currentIndex >= 0 ? Math.round((currentIndex / (phases.length - 1)) * 100) : 0,
            attempts: this.state.attempts,
            duration: this.state.startTime ? Date.now() - this.state.startTime : 0,
            phaseDescription: this.getPhaseDescription(this.state.phase)
        };
    }

    getPhaseDescription(phase) {
        const descriptions = {
            'idle': 'Ready to start',
            'validating': 'Validating nickname format',
            'checking-availability': 'Checking nickname availability',
            'checking-balance': 'Verifying wallet balance',
            'paying': 'Processing payment transaction',
            'verifying': 'Verifying transaction on blockchain',
            'registering': 'Registering DNA name',
            'complete': 'Registration completed successfully',
            'error': 'Registration failed'
        };
        
        return descriptions[phase] || 'Unknown phase';
    }

    getPhaseTimings() {
        if (!this.console) return {};
        
        const phases = this.console.performance.phases.filter(p => p.action === 'complete');
        const timings = {};
        
        phases.forEach(phase => {
            if (phase.duration) {
                timings[phase.phase] = phase.duration;
            }
        });
        
        return timings;
    }

    getState() {
        return { ...this.state };
    }

    getErrors() {
        return [...this.state.errors];
    }

    // Status Checks
    isIdle() {
        return this.state.phase === 'idle';
    }

    isInProgress() {
        return !['idle', 'complete', 'error'].includes(this.state.phase);
    }

    isComplete() {
        return this.state.phase === 'complete';
    }

    hasError() {
        return this.state.phase === 'error';
    }

    // Configuration
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        this.log('Configuration updated', newConfig, 'debug');
    }

    getConfig() {
        return { ...this.config };
    }

    // Static helper methods
    static validateNickname(nickname, rules = {}) {
        const defaultRules = {
            minLength: 3,
            maxLength: 20,
            pattern: /^[a-zA-Z0-9_]+$/,
            forbiddenWords: ['admin', 'root', 'system', 'cpunk']
        };
        
        const validationRules = { ...defaultRules, ...rules };
        const errors = [];
        
        if (!nickname || nickname.length < validationRules.minLength) {
            errors.push(`Must be at least ${validationRules.minLength} characters long`);
        }
        
        if (nickname.length > validationRules.maxLength) {
            errors.push(`Cannot exceed ${validationRules.maxLength} characters`);
        }
        
        if (!validationRules.pattern.test(nickname)) {
            errors.push('Can only contain letters, numbers, and underscores');
        }
        
        const lowerNickname = nickname.toLowerCase();
        for (const forbiddenWord of validationRules.forbiddenWords) {
            if (lowerNickname.includes(forbiddenWord)) {
                errors.push(`Cannot contain "${forbiddenWord}"`);
            }
        }
        
        return {
            valid: errors.length === 0,
            errors
        };
    }

    static formatDuration(ms) {
        if (ms < 1000) return `${ms}ms`;
        if (ms < 60000) return `${Math.round(ms / 100) / 10}s`;
        return `${Math.round(ms / 6000) / 10}min`;
    }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CPUNKDNARegistration;
}