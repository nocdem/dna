/**
 * CPUNK SSO (Single Sign-On) Module
 * Provides unified authentication across all pages
 * 
 * This module:
 * 1. Checks authentication state on page load
 * 2. Updates navbar to reflect login status
 * 3. Provides easy access to user identity
 * 4. Handles automatic session restoration
 * 5. Manages authentication redirects
 */

class CpunkSSO {
    constructor() {
        this.isAuthenticated = false;
        this.currentDna = null;
        this.currentWallet = null;
        this.sessionId = null;
        this.walletData = null;
        this.callbacks = {};
        this.initialized = false;
        this.navbarUpdated = false;
    }

    /**
     * Initialize SSO - call this on every page
     * @param {Object} config - Configuration object
     * @param {Function} config.onAuthenticated - Called when user is authenticated
     * @param {Function} config.onUnauthenticated - Called when user is not authenticated
     * @param {Function} config.onSessionRestored - Called when session is restored from storage
     * @param {boolean} config.requireAuth - If true, redirect to login if not authenticated
     * @param {boolean} config.updateNavbar - If true, update navbar login/logout state (default: true)
     */
    async init(config = {}) {
        this.callbacks = config;
        
        // Check for existing session in sessionStorage
        const sessionData = this.restoreSession();
        
        if (sessionData) {
            // Session found - user is authenticated
            this.isAuthenticated = true;
            this.currentDna = sessionData.dna;
            this.currentWallet = sessionData.wallet;
            this.sessionId = sessionData.sessionId;
            this.walletData = sessionData.walletData;
            
            // Update navbar if requested (default true)
            if (config.updateNavbar !== false) {
                this.updateNavbar();
            }
            
            // Call session restored callback
            if (this.callbacks.onSessionRestored) {
                this.callbacks.onSessionRestored(sessionData);
            }
            
            // Call authenticated callback
            if (this.callbacks.onAuthenticated) {
                this.callbacks.onAuthenticated(sessionData);
            }
        } else {
            // No session - user is not authenticated
            this.isAuthenticated = false;
            
            // Update navbar if requested (default true)
            if (config.updateNavbar !== false) {
                this.updateNavbar();
            }
            
            // Call unauthenticated callback
            if (this.callbacks.onUnauthenticated) {
                this.callbacks.onUnauthenticated();
            }
            
            // Redirect to login if authentication is required
            if (config.requireAuth === true) {
                const currentPage = window.location.pathname.split('/').pop() || 'index.html';
                
                // Don't redirect if already on login page
                if (currentPage !== 'login.html') {
                    window.location.href = `login.html?redirect=${encodeURIComponent(currentPage)}`;
                }
            }
        }
        
        this.initialized = true;
    }

    /**
     * Restore session from sessionStorage
     */
    restoreSession() {
        try {
            const sessionId = sessionStorage.getItem('cpunk_dashboard_session');
            const dna = sessionStorage.getItem('cpunk_selected_dna');
            const address = sessionStorage.getItem('cpunk_backbone_address');
            
            // Also check for old wallet key for backwards compatibility
            const oldWallet = sessionStorage.getItem('cpunk_selected_wallet');
            const wallet = address || oldWallet;
            
            if (sessionId && wallet && dna) {
                const sessionData = {
                    sessionId: sessionId,
                    wallet: wallet,
                    dna: dna,
                    address: wallet  // For consistency
                };
                
                return sessionData;
            }
        } catch (error) {
            console.error('Error restoring session:', error);
        }
        
        return null;
    }

    /**
     * Save authentication session
     */
    saveSession(data) {
        try {
            // Store only essential data: session ID, DNA nickname, and backbone address
            if (data.sessionId) sessionStorage.setItem('cpunk_dashboard_session', data.sessionId);
            
            // Ensure DNA is stored as string
            if (data.dna) {
                const dnaString = typeof data.dna === 'string' ? data.dna : 
                                  (data.dna.name || data.dna.dna || data.dna.toString());
                sessionStorage.setItem('cpunk_selected_dna', dnaString);
                this.currentDna = dnaString;
            }
            
            // Store only backbone address
            if (data.wallet || data.address) {
                const address = data.wallet || data.address;
                sessionStorage.setItem('cpunk_backbone_address', address);
                this.currentWallet = address;
            }
            
            // Remove old wallet data if it exists
            sessionStorage.removeItem('cpunk_selected_wallet');
            sessionStorage.removeItem('cpunk_wallet_data');
            
            // Update internal state
            this.isAuthenticated = true;
            this.sessionId = data.sessionId;
            
            // Update navbar
            this.updateNavbar();
            
        } catch (error) {
            console.error('Error saving session:', error);
        }
    }

    /**
     * Login - redirect to login page or show login modal
     */
    login(redirectUrl = null) {
        const currentPage = redirectUrl || window.location.pathname.split('/').pop() || 'index.html';
        
        // Redirect to login page with return URL
        window.location.href = `login.html?redirect=${encodeURIComponent(currentPage)}`;
    }

    /**
     * Logout and clear session
     */
    logout() {
        // Clear only SSO session storage keys
        sessionStorage.removeItem('cpunk_dashboard_session');
        sessionStorage.removeItem('cpunk_selected_dna');
        sessionStorage.removeItem('cpunk_backbone_address');
        
        // Also clear old keys if they exist
        sessionStorage.removeItem('cpunk_selected_wallet');
        sessionStorage.removeItem('cpunk_wallet_data');
        sessionStorage.removeItem('cpunk_selected_network');
        
        // Reset internal state
        this.isAuthenticated = false;
        this.currentDna = null;
        this.currentWallet = null;
        this.sessionId = null;
        this.walletData = null;
        this.navbarUpdated = false;
        
        // Update navbar
        this.updateNavbar();
        
        // Redirect to home page
        window.location.href = 'index.html';
    }

    /**
     * Update navbar to reflect authentication state
     */
    updateNavbar() {
        console.log('SSO updateNavbar called:', {
            isAuthenticated: this.isAuthenticated,
            currentDna: this.currentDna,
            navbarUpdated: this.navbarUpdated
        });
        
        // Reset navbarUpdated flag on each call to ensure updates happen
        this.navbarUpdated = false;
        
        // Find login link in navbar - should only be one
        const navbar = document.querySelector('.navbar-nav');
        if (!navbar) {
            // Navbar not loaded yet - try again after a delay
            console.log('SSO: Navbar not found, retrying in 100ms');
            setTimeout(() => this.updateNavbar(), 100);
            return;
        }
        
        // Find the login link specifically - it's a direct child of navbar-nav
        const loginLink = navbar.querySelector('li > a[href*="login.html"]');
        if (!loginLink) {
            console.log('SSO: Login link not found in navbar');
            return;
        }
        
        // Debug log
        console.log('SSO: Found login link:', {
            href: loginLink.href,
            text: loginLink.textContent,
            isAuth: this.isAuthenticated,
            dna: this.currentDna
        });
        
        // Only update if this is actually the login link
        if (loginLink.href.includes('login.html') || loginLink.textContent.includes('Login')) {
            if (this.isAuthenticated && this.currentDna) {
                // Ensure DNA is a string
                const dnaName = typeof this.currentDna === 'string' ? this.currentDna : 
                               (this.currentDna.name || this.currentDna.dna || 'User');
                console.log('SSO: Updating navbar to show DNA:', dnaName);
                // Change to show DNA name that links to settings
                loginLink.innerHTML = `<span class="menu-icon">👤</span> ${dnaName}`;
                loginLink.href = 'settings.html';
                this.navbarUpdated = true;
            } else {
                // Ensure it shows login
                loginLink.innerHTML = '<span class="menu-icon">🔐</span> Login';
                loginLink.href = 'login.html';
            }
        }
    }

    /**
     * Check if user is authenticated
     */
    isUserAuthenticated() {
        return this.isAuthenticated;
    }

    /**
     * Get current user info
     */
    getCurrentUser() {
        if (!this.isAuthenticated) return null;
        
        return {
            dna: this.currentDna,
            wallet: this.currentWallet,
            sessionId: this.sessionId,
            walletData: this.walletData
        };
    }

    /**
     * Get current DNA nickname
     */
    getCurrentDna() {
        return this.currentDna;
    }

    /**
     * Get current wallet address
     */
    getCurrentWallet() {
        return this.currentWallet;
    }

    /**
     * Initialize dashboard connector only when needed for operations
     * This prevents automatic wallet selection UI from showing
     */
    initDashboardForOperations() {
        if (typeof CpunkDashboard === 'undefined') {
            console.error('CpunkDashboard not available');
            return false;
        }

        // Only initialize if not already connected and we have a saved session
        const sessionId = sessionStorage.getItem('cpunk_dashboard_session');
        if (sessionId && this.isAuthenticated) {
            CpunkDashboard.restoreSession(sessionId);
            return true;
        }
        
        return false;
    }

    /**
     * Static instance getter
     */
    static getInstance() {
        if (!window._cpunkSSOInstance) {
            window._cpunkSSOInstance = new CpunkSSO();
        }
        return window._cpunkSSOInstance;
    }
}

// Create and expose global instance
window.CpunkSSO = CpunkSSO;