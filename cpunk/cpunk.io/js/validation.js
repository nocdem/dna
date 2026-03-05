/**
 * CPUNK.IO Validation Library
 * Comprehensive input validation and formatting utilities
 * 
 * Features:
 * - DNA nickname validation
 * - Wallet address validation
 * - Transaction hash validation
 * - Email and contact validation
 * - Cryptographic validation
 * - Input sanitization
 * - Real-time validation
 * 
 * @version 1.0.0
 */

class CpunkValidation {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        
        // Validation patterns
        this.patterns = {
            dna: /^[a-zA-Z0-9._-]+$/,
            email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            hex: /^[a-fA-F0-9]+$/,
            base58: /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/,
            ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
            ipv6: /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
            url: /^https?:\/\/[^\s/$.?#].[^\s]*$/,
            phone: /^\+?[\d\s\-\(\)]{7,15}$/
        };

        // Validation rules
        this.rules = {
            dna: {
                minLength: 3,
                maxLength: 36,
                pattern: this.patterns.dna,
                reservedWords: ['admin', 'root', 'system', 'api', 'www', 'mail', 'ftp', 'cpunk', 'null', 'undefined']
            },
            password: {
                minLength: 8,
                maxLength: 128,
                requireUppercase: false,
                requireLowercase: false,
                requireNumbers: false,
                requireSpecialChars: false
            },
            wallet: {
                cellframeMinLength: 95,
                cellframeMaxLength: 98,
                cellframePrefix: 'mh'
            }
        };

        // Pricing tiers for DNA
        this.dnaPricing = {
            3: 500,  // 3 characters: 500 CPUNK
            4: 100,  // 4 characters: 100 CPUNK
            default: 5  // 5+ characters: 5 CPUNK
        };

        // Error messages
        this.messages = {
            dna: {
                required: 'DNA nickname is required',
                minLength: 'DNA nickname must be at least 3 characters long',
                maxLength: 'DNA nickname must be no more than 36 characters long',
                invalidFormat: 'DNA nickname can only contain letters, numbers, underscore (_), hyphen (-), and period (.)',
                reserved: 'This DNA nickname is reserved and cannot be used',
                taken: 'This DNA nickname is already taken',
                available: 'DNA nickname is available'
            },
            wallet: {
                required: 'Wallet address is required',
                invalidFormat: 'Invalid wallet address format',
                invalidNetwork: 'Wallet address is not for the correct network'
            },
            transaction: {
                required: 'Transaction hash is required',
                invalidFormat: 'Invalid transaction hash format',
                notFound: 'Transaction not found on blockchain'
            },
            email: {
                required: 'Email address is required',
                invalidFormat: 'Invalid email address format'
            },
            general: {
                required: 'This field is required',
                tooShort: 'Value is too short',
                tooLong: 'Value is too long',
                invalidFormat: 'Invalid format'
            }
        };
    }

    /**
     * Initialize validation library
     * @param {Object} options - Configuration options
     */
    init(options = {}) {
        if (this.initialized) return;

        // Merge custom rules and messages
        if (options.rules) {
            this.rules = this.core?.deepMerge(this.rules, options.rules) || { ...this.rules, ...options.rules };
        }
        if (options.messages) {
            this.messages = this.core?.deepMerge(this.messages, options.messages) || { ...this.messages, ...options.messages };
        }
        if (options.patterns) {
            this.patterns = { ...this.patterns, ...options.patterns };
        }

        this.initialized = true;
        this.core?.log('Validation library initialized');
    }

    /**
     * DNA Validation Methods
     */

    /**
     * Validate DNA nickname format
     * @param {string} nickname - DNA nickname to validate
     * @returns {Object} Validation result
     */
    validateDNAFormat(nickname) {
        const result = {
            valid: false,
            errors: [],
            warnings: []
        };

        if (!nickname) {
            result.errors.push(this.messages.dna.required);
            return result;
        }

        // Check length
        if (nickname.length < this.rules.dna.minLength) {
            result.errors.push(this.messages.dna.minLength);
        }
        if (nickname.length > this.rules.dna.maxLength) {
            result.errors.push(this.messages.dna.maxLength);
        }

        // Check pattern
        if (!this.rules.dna.pattern.test(nickname)) {
            result.errors.push(this.messages.dna.invalidFormat);
        }

        // Check reserved words
        if (this.rules.dna.reservedWords.includes(nickname.toLowerCase())) {
            result.errors.push(this.messages.dna.reserved);
        }

        // Add warnings for short names (expensive)
        if (nickname.length === 3) {
            result.warnings.push(`Short names cost ${this.dnaPricing[3]} CPUNK`);
        } else if (nickname.length === 4) {
            result.warnings.push(`4-character names cost ${this.dnaPricing[4]} CPUNK`);
        }

        result.valid = result.errors.length === 0;
        return result;
    }

    /**
     * Calculate DNA price based on length
     * @param {string} nickname - DNA nickname
     * @returns {number} Price in CPUNK
     */
    calculateDNAPrice(nickname) {
        if (!nickname) return 0;
        const length = nickname.length;
        return this.dnaPricing[length] || this.dnaPricing.default;
    }

    /**
     * Validate DNA nickname availability
     * @param {string} nickname - DNA nickname
     * @param {Function} checkCallback - Async function to check availability
     * @returns {Promise<Object>} Validation result with availability
     */
    async validateDNAAvailability(nickname, checkCallback) {
        const formatResult = this.validateDNAFormat(nickname);
        
        if (!formatResult.valid) {
            return formatResult;
        }

        try {
            const isAvailable = await checkCallback(nickname);
            const result = {
                ...formatResult,
                available: isAvailable,
                price: this.calculateDNAPrice(nickname)
            };

            if (!isAvailable) {
                result.errors.push(this.messages.dna.taken);
                result.valid = false;
            }

            return result;
        } catch (error) {
            return {
                ...formatResult,
                available: null,
                errors: [...formatResult.errors, 'Unable to check availability'],
                valid: false
            };
        }
    }

    /**
     * Wallet Validation Methods
     */

    /**
     * Validate Cellframe wallet address
     * @param {string} address - Wallet address
     * @returns {Object} Validation result
     */
    validateWalletAddress(address) {
        const result = {
            valid: false,
            errors: [],
            network: null,
            type: null
        };

        if (!address) {
            result.errors.push(this.messages.wallet.required);
            return result;
        }

        // Check Cellframe address format
        if (address.length >= this.rules.wallet.cellframeMinLength && 
            address.length <= this.rules.wallet.cellframeMaxLength) {
            
            // Basic Cellframe validation
            if (this.patterns.base58.test(address)) {
                result.valid = true;
                result.type = 'cellframe';
                result.network = 'backbone'; // Assume backbone for now
            } else {
                result.errors.push(this.messages.wallet.invalidFormat);
            }
        } else {
            result.errors.push(this.messages.wallet.invalidFormat);
        }

        return result;
    }

    /**
     * Transaction Validation Methods
     */

    /**
     * Validate transaction hash
     * @param {string} hash - Transaction hash
     * @returns {Object} Validation result
     */
    validateTransactionHash(hash) {
        const result = {
            valid: false,
            errors: [],
            format: null
        };

        if (!hash) {
            result.errors.push(this.messages.transaction.required);
            return result;
        }

        // Check for hex format (with or without 0x prefix)
        const cleanHash = hash.startsWith('0x') ? hash.slice(2) : hash;
        
        if (this.patterns.hex.test(cleanHash)) {
            if (cleanHash.length === 64) { // Standard 256-bit hash
                result.valid = true;
                result.format = 'hex256';
            } else if (cleanHash.length === 40) { // 160-bit hash
                result.valid = true;
                result.format = 'hex160';
            } else {
                result.errors.push(this.messages.transaction.invalidFormat);
            }
        } else {
            result.errors.push(this.messages.transaction.invalidFormat);
        }

        return result;
    }

    /**
     * General Validation Methods
     */

    /**
     * Validate email address
     * @param {string} email - Email address
     * @returns {Object} Validation result
     */
    validateEmail(email) {
        const result = {
            valid: false,
            errors: []
        };

        if (!email) {
            result.errors.push(this.messages.email.required);
            return result;
        }

        if (!this.patterns.email.test(email)) {
            result.errors.push(this.messages.email.invalidFormat);
        } else {
            result.valid = true;
        }

        return result;
    }

    /**
     * Validate URL
     * @param {string} url - URL to validate
     * @returns {Object} Validation result
     */
    validateURL(url) {
        const result = {
            valid: false,
            errors: [],
            protocol: null,
            domain: null
        };

        if (!url) {
            result.errors.push('URL is required');
            return result;
        }

        if (this.patterns.url.test(url)) {
            try {
                const urlObj = new URL(url);
                result.valid = true;
                result.protocol = urlObj.protocol;
                result.domain = urlObj.hostname;
            } catch (error) {
                result.errors.push('Invalid URL format');
            }
        } else {
            result.errors.push('Invalid URL format');
        }

        return result;
    }

    /**
     * Validate phone number
     * @param {string} phone - Phone number
     * @returns {Object} Validation result
     */
    validatePhone(phone) {
        const result = {
            valid: false,
            errors: [],
            formatted: null
        };

        if (!phone) {
            result.errors.push('Phone number is required');
            return result;
        }

        const cleaned = phone.replace(/\D/g, '');
        
        if (cleaned.length >= 7 && cleaned.length <= 15) {
            result.valid = true;
            result.formatted = this.formatPhone(cleaned);
        } else {
            result.errors.push('Invalid phone number length');
        }

        return result;
    }

    /**
     * Formatting Methods
     */

    /**
     * Format balance for display
     * @param {string|number} balance - Balance value
     * @param {number} decimals - Decimal places
     * @param {string} unit - Unit suffix
     * @returns {string} Formatted balance
     */
    formatBalance(balance, decimals = 3, unit = '') {
        const num = parseFloat(balance);
        if (isNaN(num)) return '0' + (unit ? ' ' + unit : '');
        if (num === 0) return '0' + (unit ? ' ' + unit : '');
        if (num < Math.pow(10, -decimals)) return `< ${Math.pow(10, -decimals)}` + (unit ? ' ' + unit : '');
        
        const formatted = num.toLocaleString(undefined, { 
            minimumFractionDigits: 0, 
            maximumFractionDigits: decimals 
        });
        
        return formatted + (unit ? ' ' + unit : '');
    }

    /**
     * Format address for display
     * @param {string} address - Address
     * @param {number} startChars - Characters at start
     * @param {number} endChars - Characters at end
     * @returns {string} Formatted address
     */
    formatAddress(address, startChars = 6, endChars = 6) {
        if (!address || address.length <= startChars + endChars) {
            return address || '';
        }
        return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
    }

    /**
     * Format transaction hash for display
     * @param {string} hash - Transaction hash
     * @param {number} startChars - Characters at start
     * @param {number} endChars - Characters at end
     * @returns {string} Formatted hash
     */
    formatTxHash(hash, startChars = 8, endChars = 8) {
        if (!hash) return '';
        if (hash.length <= startChars + endChars) return hash;
        return `${hash.slice(0, startChars)}...${hash.slice(-endChars)}`;
    }

    /**
     * Format phone number
     * @param {string} phone - Phone number digits
     * @returns {string} Formatted phone number
     */
    formatPhone(phone) {
        const cleaned = phone.replace(/\D/g, '');
        
        if (cleaned.length === 10) {
            return `(${cleaned.slice(0,3)}) ${cleaned.slice(3,6)}-${cleaned.slice(6)}`;
        } else if (cleaned.length === 11 && cleaned[0] === '1') {
            return `+1 (${cleaned.slice(1,4)}) ${cleaned.slice(4,7)}-${cleaned.slice(7)}`;
        }
        
        return phone;
    }

    /**
     * Sanitization Methods
     */

    /**
     * Sanitize input string
     * @param {string} input - Input to sanitize
     * @param {Object} options - Sanitization options
     * @returns {string} Sanitized string
     */
    sanitizeInput(input, options = {}) {
        if (typeof input !== 'string') return '';
        
        let sanitized = input;
        
        // Remove HTML tags
        if (options.stripHtml !== false) {
            sanitized = sanitized.replace(/<[^>]*>/g, '');
        }
        
        // Remove script content
        sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
        
        // Trim whitespace
        if (options.trim !== false) {
            sanitized = sanitized.trim();
        }
        
        // Limit length
        if (options.maxLength) {
            sanitized = sanitized.slice(0, options.maxLength);
        }
        
        // Remove dangerous characters
        if (options.removeDangerous) {
            sanitized = sanitized.replace(/[<>&"']/g, '');
        }
        
        return sanitized;
    }

    /**
     * Real-time Validation Methods
     */

    /**
     * Create real-time validator for input element
     * @param {HTMLElement} element - Input element
     * @param {Function} validator - Validation function
     * @param {Object} options - Validation options
     */
    createRealTimeValidator(element, validator, options = {}) {
        const {
            debounceMs = 500,
            showSuccess = true,
            showErrors = true,
            className = 'validation-message',
            successClass = 'validation-success',
            errorClass = 'validation-error'
        } = options;

        let timeout = null;
        let messageElement = element.parentNode.querySelector(`.${className}`);
        
        if (!messageElement) {
            messageElement = document.createElement('div');
            messageElement.className = className;
            element.parentNode.appendChild(messageElement);
        }

        const validate = async () => {
            const value = element.value;
            messageElement.style.display = 'none';
            messageElement.className = className;

            if (!value && !options.required) {
                return;
            }

            try {
                const result = await validator(value);
                
                if (result.valid && showSuccess) {
                    messageElement.textContent = result.message || this.messages.dna.available;
                    messageElement.className = `${className} ${successClass}`;
                    messageElement.style.display = 'block';
                } else if (!result.valid && showErrors) {
                    messageElement.textContent = result.errors?.[0] || 'Invalid input';
                    messageElement.className = `${className} ${errorClass}`;
                    messageElement.style.display = 'block';
                }

                // Emit validation event
                element.dispatchEvent(new CustomEvent('validation', {
                    detail: { result, value }
                }));
                
            } catch (error) {
                if (showErrors) {
                    messageElement.textContent = 'Validation error occurred';
                    messageElement.className = `${className} ${errorClass}`;
                    messageElement.style.display = 'block';
                }
            }
        };

        element.addEventListener('input', () => {
            clearTimeout(timeout);
            timeout = setTimeout(validate, debounceMs);
        });

        element.addEventListener('blur', validate);
        
        // Return cleanup function
        return () => {
            clearTimeout(timeout);
            element.removeEventListener('input', validate);
            element.removeEventListener('blur', validate);
            if (messageElement.parentNode) {
                messageElement.parentNode.removeChild(messageElement);
            }
        };
    }

    /**
     * Utility Methods
     */

    /**
     * Check if value is empty
     * @param {*} value - Value to check
     * @returns {boolean} Is empty
     */
    isEmpty(value) {
        if (value === null || value === undefined) return true;
        if (typeof value === 'string') return value.trim().length === 0;
        if (Array.isArray(value)) return value.length === 0;
        if (typeof value === 'object') return Object.keys(value).length === 0;
        return false;
    }

    /**
     * Get validation summary
     * @param {Array} results - Array of validation results
     * @returns {Object} Summary
     */
    getValidationSummary(results) {
        const summary = {
            valid: true,
            errorCount: 0,
            warningCount: 0,
            errors: [],
            warnings: []
        };

        results.forEach(result => {
            if (!result.valid) {
                summary.valid = false;
            }
            if (result.errors) {
                summary.errors.push(...result.errors);
                summary.errorCount += result.errors.length;
            }
            if (result.warnings) {
                summary.warnings.push(...result.warnings);
                summary.warningCount += result.warnings.length;
            }
        });

        return summary;
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('validation', new CpunkValidation(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkValidation;
}