/**
 * CPUNK Authentication Module
 * Provides centralized authentication functionality for admin-protected pages
 * 
 * Usage:
 * 1. Include this script before your page-specific code
 * 2. Call CpunkAuth.init() with configuration
 * 3. Handle callbacks for authentication events
 */

class CpunkAuthentication {
    constructor() {
        this.adminList = [];
        this.isAuthenticated = false;
        this.currentDna = null;
        this.currentWallet = null;
        this.sessionId = null;
        this.callbacks = {};
    }

    /**
     * Initialize authentication with configuration
     * @param {Object} config - Configuration object
     * @param {Function} config.onAuthenticated - Called when user is authenticated as admin
     * @param {Function} config.onAccessDenied - Called when user is not an admin
     * @param {Function} config.onError - Called on any error
     * @param {Function} config.onLogout - Called when user logs out
     * @param {boolean} config.autoConnect - Whether to show connect button automatically
     */
    async init(config) {
        this.callbacks = config || {};
        
        // Load admin list on initialization
        try {
            await this.loadAdmins();
            console.log('Authentication module initialized with', this.adminList.length, 'admins');
            
            // Initialize dashboard connector
            this.initDashboardConnector();
            
            // Auto-show connect section if configured
            if (config.autoConnect !== false) {
                this.showConnectSection();
            }
        } catch (error) {
            console.error('Failed to initialize authentication:', error);
            if (this.callbacks.onError) {
                this.callbacks.onError('Failed to initialize authentication: ' + error.message);
            }
        }
    }

    /**
     * Initialize the dashboard connector
     */
    initDashboardConnector() {
        if (typeof CpunkDashboard === 'undefined') {
            console.error('CpunkDashboard not found. Make sure dashboardConnector.js is loaded first.');
            return;
        }

        CpunkDashboard.init({
            onConnected: (sessionId) => {
                this.sessionId = sessionId;
                console.log('Connected to dashboard with session ID:', sessionId);
            },
            onWalletSelected: async (wallet) => {
                console.log('Wallet selected:', wallet);
                await this.handleWalletSelection(wallet);
            },
            onDnaSelected: (dna) => {
                // Legacy support - not used in new flow
                console.log('DNA selected (legacy):', dna);
            },
            onError: (message) => {
                console.error('Dashboard connector error:', message);
                if (this.callbacks.onError) {
                    this.callbacks.onError(message);
                }
            }
        });
    }

    /**
     * Load admin list from admins.txt
     */
    async loadAdmins() {
        try {
            const response = await fetch('admins.txt');
            
            if (!response.ok) {
                throw new Error(`Failed to load admins.txt: ${response.status}`);
            }
            
            const text = await response.text();
            
            // Parse admin nicknames - filtering out comments and empty lines
            this.adminList = text.split('\n')
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#'));
                
            return this.adminList;
        } catch (error) {
            console.error('Error loading admin list:', error);
            throw error;
        }
    }

    /**
     * Check if a DNA nickname is an admin
     */
    isAdmin(dna) {
        return this.adminList.some(admin => admin.toLowerCase() === dna.toLowerCase());
    }

    /**
     * Handle wallet selection and check for admin DNA
     */
    async handleWalletSelection(wallet) {
        if (!wallet || !wallet.address) {
            console.error('Invalid wallet selected');
            return;
        }

        try {
            this.currentWallet = wallet.address;
            
            // Show loading status
            this.showStatus('Checking DNA registration...', 'info');

            // Make API request to check DNA for this wallet
            const response = await fetch(`dna-proxy.php?lookup=${encodeURIComponent(wallet.address)}`);
            const text = await response.text();
            
            try {
                const data = JSON.parse(text);
                
                if (data.status_code === 0 && data.response_data) {
                    // Get registered names from response data
                    const registeredNames = data.response_data.registered_names || {};
                    const userNicknames = Object.keys(registeredNames);

                    if (userNicknames.length === 0) {
                        // No DNA registration found
                        this.showStatus('No DNA registrations found for this wallet.', 'warning');
                        if (this.callbacks.onAccessDenied) {
                            this.callbacks.onAccessDenied('No DNA registrations found');
                        }
                        return;
                    }

                    // Check if any of the DNA nicknames are in the admin list
                    const adminDnas = userNicknames.filter(name => this.isAdmin(name));
                    
                    if (adminDnas.length > 0) {
                        // Found admin DNA - grant access
                        const adminNickname = adminDnas[0]; // Use the first admin DNA found
                        
                        this.isAuthenticated = true;
                        this.currentDna = adminNickname;
                        
                        // Hide any error messages
                        this.hideStatus();
                        
                        // Hide wallet section on successful authentication
                        const walletSection = document.getElementById('walletSection');
                        if (walletSection) {
                            walletSection.style.display = 'none';
                        }
                        
                        // Call authenticated callback
                        if (this.callbacks.onAuthenticated) {
                            this.callbacks.onAuthenticated({
                                dna: adminNickname,
                                wallet: wallet.address,
                                allDnas: userNicknames,
                                adminDnas: adminDnas
                            });
                        }
                    } else {
                        // No admin access
                        const message = `Access denied. None of your DNA nicknames (${userNicknames.join(', ')}) have admin privileges.`;
                        this.showStatus(message, 'error');
                        
                        if (this.callbacks.onAccessDenied) {
                            this.callbacks.onAccessDenied(message);
                        }
                    }
                } else if (data.error) {
                    // Specific error from API
                    this.showStatus(`Error: ${data.error}`, 'error');
                    if (this.callbacks.onError) {
                        this.callbacks.onError(data.error);
                    }
                } else {
                    // No DNA data found
                    this.showStatus('No DNA registrations found for this wallet.', 'warning');
                    if (this.callbacks.onAccessDenied) {
                        this.callbacks.onAccessDenied('No DNA registrations found');
                    }
                }
            } catch (e) {
                // If not valid JSON, likely an error
                console.error("JSON Parse Error:", e);
                this.showStatus('Error checking DNA registration. Invalid response format.', 'error');
                if (this.callbacks.onError) {
                    this.callbacks.onError('Invalid response format');
                }
            }
        } catch (error) {
            console.error('Error checking DNA registration:', error);
            this.showStatus(`Error checking DNA registration: ${error.message}`, 'error');
            if (this.callbacks.onError) {
                this.callbacks.onError(error.message);
            }
        }
    }

    /**
     * Show connect section
     */
    showConnectSection() {
        const connectSection = document.getElementById('connect-section');
        if (connectSection) {
            connectSection.style.display = 'block';
        }
    }

    /**
     * Hide connect section
     */
    hideConnectSection() {
        const connectSection = document.getElementById('connect-section');
        if (connectSection) {
            connectSection.style.display = 'none';
        }
    }

    /**
     * Show status message
     */
    showStatus(message, type = 'info') {
        // Try multiple common status element IDs
        const statusElements = [
            document.getElementById('authStatus'),
            document.getElementById('dnaError'),
            document.getElementById('statusMessage')
        ];
        
        const statusElement = statusElements.find(el => el !== null);
        
        if (statusElement) {
            statusElement.textContent = message;
            statusElement.className = `message ${type}`;
            statusElement.style.display = 'block';
        } else {
            console.warn('No status element found to display message:', message);
        }
    }

    /**
     * Hide status message
     */
    hideStatus() {
        // Try multiple common status element IDs
        const statusElements = [
            document.getElementById('authStatus'),
            document.getElementById('dnaError'),
            document.getElementById('statusMessage')
        ];
        
        statusElements.forEach(el => {
            if (el) {
                el.style.display = 'none';
            }
        });
    }

    /**
     * Connect to dashboard
     */
    async connect() {
        if (typeof CpunkDashboard !== 'undefined') {
            await CpunkDashboard.connect();
        } else {
            console.error('Dashboard connector not available');
            if (this.callbacks.onError) {
                this.callbacks.onError('Dashboard connector not available');
            }
        }
    }

    /**
     * Logout and reset authentication
     */
    logout() {
        this.isAuthenticated = false;
        this.currentDna = null;
        this.currentWallet = null;
        this.sessionId = null;
        
        // Clear all session storage
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.removeItem('cpunk_dashboard_session');
            sessionStorage.removeItem('cpunk_selected_wallet');
            sessionStorage.removeItem('cpunk_selected_network');
            sessionStorage.removeItem('cpunk_selected_dna');
            sessionStorage.clear();
        }
        
        // Reset dashboard connector
        if (typeof CpunkDashboard !== 'undefined') {
            CpunkDashboard.reset();
        }
        
        // Show connect section
        this.showConnectSection();
        
        // Hide any authenticated content
        const editorContainer = document.getElementById('editorContainer');
        if (editorContainer) {
            editorContainer.style.display = 'none';
        }
        
        const editorSection = document.getElementById('editor-section');
        if (editorSection) {
            editorSection.style.display = 'none';
        }
        
        // Reset status indicator
        const statusIndicator = document.getElementById('statusIndicator');
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator status-disconnected';
            statusIndicator.textContent = 'Disconnected';
        }
        
        // Call logout callback
        if (this.callbacks.onLogout) {
            this.callbacks.onLogout();
        }
    }

    /**
     * Get current authentication status
     */
    getStatus() {
        return {
            isAuthenticated: this.isAuthenticated,
            dna: this.currentDna,
            wallet: this.currentWallet,
            sessionId: this.sessionId
        };
    }
}

// Create global instance
window.CpunkAuth = new CpunkAuthentication();