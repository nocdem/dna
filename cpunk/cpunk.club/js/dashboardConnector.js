/**
 * CPUNK Dashboard Connector
 * A reusable utility for connecting to Cellframe dashboard, selecting wallets and DNA identities
 * 
 * Usage:
 * 1. Import the script in your HTML: <script src="js/dashboardConnector.js"></script>
 * 2. Use the CpunkDashboard object to interact with the dashboard
 * 
 * Example:
 * CpunkDashboard.init({
 *    onConnected: function(sessionId) { console.log('Connected with session:', sessionId) },
 *    onWalletSelected: function(wallet) { console.log('Selected wallet:', wallet) },
 *    onDnaSelected: function(dna) { console.log('Selected DNA:', dna) }
 * });
 */

const CpunkDashboard = (function() {
    // Configuration
    const DEFAULT_CONFIG = {
        apiUrl: 'http://localhost:8045/',
        dnaProxyUrl: 'dna-proxy.php',
        statusIndicatorId: 'statusIndicator',
        connectButtonId: 'connectButton',
        connectionErrorId: 'connectionError',
        walletSectionId: 'walletSection',
        walletsListId: 'walletsList',
        walletErrorId: 'walletError',
        dnaSectionId: 'dnaSection',
        dnaListId: 'dnaList',
        dnaErrorId: 'dnaError',
        onConnected: null,
        onWalletSelected: null,
        onDnaSelected: null,
        onError: null
    };

    // State
    let config = {...DEFAULT_CONFIG};
    let sessionId = null;
    let selectedWallet = null;
    let selectedNetwork = null;
    let selectedDNA = null;
    let userDNAs = [];
    let walletsByName = {}; // Store wallet data by name
    
    // Session persistence keys
    const SESSION_KEYS = {
        sessionId: 'cpunk_dashboard_session',
        selectedWallet: 'cpunk_selected_wallet',
        selectedNetwork: 'cpunk_selected_network',
        selectedDNA: 'cpunk_selected_dna',
        walletData: 'cpunk_wallet_data'
    };

    // DOM Elements
    let elements = {};

    /**
     * Initialize the dashboard connector with custom configuration
     * @param {Object} customConfig - Custom configuration options
     */
    function init(customConfig = {}) {
        console.log('CpunkDashboard.init called with:', customConfig);
        
        // Check if already initialized to prevent double initialization
        if (window.dashboardInitCount === undefined) {
            window.dashboardInitCount = 1;
        } else {
            window.dashboardInitCount++;
            console.warn(`Dashboard connector initialized ${window.dashboardInitCount} times`);
        }
        
        // Merge configurations
        config = {...DEFAULT_CONFIG, ...customConfig};

        // Wait for document to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', onDocumentReady);
        } else {
            onDocumentReady();
        }
    }

    /**
     * Called when the document is ready
     */
    function onDocumentReady() {
        // Cache DOM elements
        cacheElements();

        // Load existing session state
        loadSessionState();

        // Set up event listeners - but check if we're in settings.js context
        // where we might have already registered an event handler
        if (elements.connectButton) {
            // First, remove any existing event listeners
            const oldButton = elements.connectButton.cloneNode(true);
            if (elements.connectButton.parentNode) {
                elements.connectButton.parentNode.replaceChild(oldButton, elements.connectButton);
                elements.connectButton = oldButton;
                console.log('Replaced connect button to clear existing event listeners');
            }
            
            // Now add the event listener
            elements.connectButton.addEventListener('click', connectToDashboard);
            console.log('Added connect button event listener');
        }

        // If we have an existing session, update UI accordingly
        if (sessionId) {
            updateStatus('connected', 'Connected');
            
            if (elements.connectButton) {
                elements.connectButton.textContent = 'Reconnect';
                elements.connectButton.disabled = false;
            }

            if (elements.walletSection && selectedWallet) {
                elements.walletSection.style.display = 'block';
                // Auto-load wallets if we have existing session
                loadWallets().catch(error => {
                    console.log('Failed to restore wallets, session may have expired:', error);
                    clearSessionState();
                });
            }
        }
    }

    /**
     * Cache all necessary DOM elements
     */
    function cacheElements() {
        elements.statusIndicator = document.getElementById(config.statusIndicatorId);
        elements.connectButton = document.getElementById(config.connectButtonId);
        elements.connectionError = document.getElementById(config.connectionErrorId);
        elements.walletSection = document.getElementById(config.walletSectionId);
        elements.walletsList = document.getElementById(config.walletsListId);
        elements.walletError = document.getElementById(config.walletErrorId);
        elements.dnaSection = document.getElementById(config.dnaSectionId);
        elements.dnaList = document.getElementById(config.dnaListId);
        elements.dnaError = document.getElementById(config.dnaErrorId);
    }

    /**
     * Load session state from sessionStorage
     */
    function loadSessionState() {
        try {
            sessionId = sessionStorage.getItem(SESSION_KEYS.sessionId);
            selectedWallet = sessionStorage.getItem(SESSION_KEYS.selectedWallet);
            selectedNetwork = sessionStorage.getItem(SESSION_KEYS.selectedNetwork);
            selectedDNA = sessionStorage.getItem(SESSION_KEYS.selectedDNA);
            
            const walletDataJson = sessionStorage.getItem(SESSION_KEYS.walletData);
            if (walletDataJson) {
                walletsByName = JSON.parse(walletDataJson);
            }
            
            console.log('Loaded session state:', {
                sessionId: sessionId ? 'exists' : 'none',
                selectedWallet,
                selectedNetwork,
                selectedDNA
            });
        } catch (error) {
            console.warn('Failed to load session state:', error);
            clearSessionState();
        }
    }

    /**
     * Save session state to sessionStorage
     */
    function saveSessionState() {
        try {
            if (sessionId) sessionStorage.setItem(SESSION_KEYS.sessionId, sessionId);
            if (selectedWallet) sessionStorage.setItem(SESSION_KEYS.selectedWallet, selectedWallet);
            if (selectedNetwork) sessionStorage.setItem(SESSION_KEYS.selectedNetwork, selectedNetwork);
            if (selectedDNA) sessionStorage.setItem(SESSION_KEYS.selectedDNA, selectedDNA);
            if (Object.keys(walletsByName).length > 0) {
                sessionStorage.setItem(SESSION_KEYS.walletData, JSON.stringify(walletsByName));
            }
        } catch (error) {
            console.warn('Failed to save session state:', error);
        }
    }

    /**
     * Clear session state from sessionStorage
     */
    function clearSessionState() {
        Object.values(SESSION_KEYS).forEach(key => {
            sessionStorage.removeItem(key);
        });
        
        sessionId = null;
        selectedWallet = null;
        selectedNetwork = null;
        selectedDNA = null;
        userDNAs = [];
        walletsByName = {};
    }

    /**
     * Update dashboard connection status UI
     * @param {string} status - The status to display (connected, connecting, disconnected)
     * @param {string} message - Optional message to display
     */
    function updateStatus(status, message = '') {
        if (!elements.statusIndicator) return;
        
        elements.statusIndicator.className = 'status-indicator status-' + status;
        elements.statusIndicator.textContent = message || status.charAt(0).toUpperCase() + status.slice(1);
    }

    /**
     * Show an error message
     * @param {string} message - The error message to display
     * @param {string} elementId - The ID of the element to show the error in
     */
    function showError(message, elementId = 'connectionError') {
        const errorElement = document.getElementById(elementId);
        if (!errorElement) return;

        errorElement.textContent = message;
        errorElement.style.display = 'block';

        // Call error callback if provided
        if (typeof config.onError === 'function') {
            config.onError(message, elementId);
        }
    }

    /**
     * Connect to the Cellframe dashboard
     * @returns {Promise} A promise that resolves with the session ID
     */
    async function connectToDashboard() {
        console.log('Dashboard connector: connectToDashboard called');
        
        // If we already have a valid session, try to reuse it first
        if (sessionId) {
            try {
                console.log('Attempting to reuse existing session:', sessionId);
                
                // Test if the session is still valid by making a simple request
                const testResponse = await makeRequest('GetWallets', { id: sessionId });
                
                if (testResponse.status === 'ok') {
                    console.log('Existing session is valid, reusing it');
                    updateStatus('connected', 'Connected');
                    
                    if (elements.connectButton) {
                        elements.connectButton.textContent = 'Reconnect';
                        elements.connectButton.disabled = false;
                    }

                    if (elements.walletSection) {
                        elements.walletSection.style.display = 'block';
                    }

                    // Load wallets with existing session
                    await loadWallets();

                    if (typeof config.onConnected === 'function') {
                        config.onConnected(sessionId);
                    }
                    
                    return sessionId;
                }
            } catch (error) {
                console.log('Existing session invalid, creating new one:', error.message);
                clearSessionState();
            }
        }
        
        try {
            // Reset UI
            if (elements.connectionError) {
                elements.connectionError.style.display = 'none';
            }
            
            if (elements.connectButton) {
                elements.connectButton.disabled = true;
                elements.connectButton.textContent = 'Connecting...';
            }
            
            updateStatus('connecting', 'Connecting...');

            // Make connection request
            const response = await makeRequest('Connect');

            if (response.status === 'ok' && response.data && response.data.id) {
                // Store session ID
                sessionId = response.data.id;
                saveSessionState(); // Save to sessionStorage
                
                updateStatus('connected', 'Connected');
                
                if (elements.connectButton) {
                    elements.connectButton.textContent = 'Reconnect';
                    elements.connectButton.disabled = false;
                }

                if (elements.walletSection) {
                    elements.walletSection.style.display = 'block';
                }

                // Load wallets
                await loadWallets();

                if (typeof config.onConnected === 'function') {
                    config.onConnected(sessionId);
                }
                
                return sessionId;
            } else {
                throw new Error(response.errorMsg || 'Failed to connect to dashboard');
            }
        } catch (error) {
            console.error('Connection error:', error);
            clearSessionState();
            
            if (elements.connectionError) {
                showError(`Error connecting to dashboard: ${error.message}`, 'connectionError');
            }
            
            updateStatus('disconnected', 'Connection Failed');
            
            if (elements.connectButton) {
                elements.connectButton.textContent = 'Connect to Dashboard';
                elements.connectButton.disabled = false;
            }
            
            throw error;
        }
    }

    /**
     * Load wallets from the dashboard
     * @returns {Promise} A promise that resolves with the list of active wallets
     */
    async function loadWallets() {
        if (!sessionId) {
            throw new Error('Not connected to dashboard');
        }

        try {
            if (elements.walletsList) {
                elements.walletsList.innerHTML = '<div style="text-align: center; padding: 20px;">Loading wallets...</div>';
            }

            const response = await makeRequest('GetWallets', { id: sessionId });

            if (response.status === 'ok' && response.data && Array.isArray(response.data)) {
                // Get all wallets
                const allWallets = response.data;
                
                if (allWallets.length === 0) {
                    if (elements.walletsList) {
                        elements.walletsList.innerHTML = '<div style="color: var(--error); text-align: center; padding: 20px;">No wallets found in your dashboard.</div>';
                    }
                    return [];
                }
                
                // Filter active wallets (those that don't have status="non-Active")
                const activeWallets = allWallets.filter(wallet => wallet.status !== "non-Active");
                
                if (activeWallets.length === 0) {
                    if (elements.walletsList) {
                        elements.walletsList.innerHTML = '<div style="color: var(--error); text-align: center; padding: 20px;">No active wallets found. Please ensure you have active wallets in your dashboard.</div>';
                    }
                    return [];
                }

                // Clear wallet list if element exists
                if (elements.walletsList) {
                    elements.walletsList.innerHTML = '';

                    // Add each active wallet to the list
                    activeWallets.forEach(wallet => {
                        const walletCard = document.createElement('div');
                        walletCard.className = 'wallet-card';
                        walletCard.innerHTML = `<div class="wallet-name">${wallet.name}</div>`;

                        walletCard.addEventListener('click', async () => {
                            // Deselect all wallet cards
                            document.querySelectorAll('.wallet-card').forEach(card => {
                                card.classList.remove('selected');
                            });

                            // Select this wallet card
                            walletCard.classList.add('selected');

                            // Handle wallet selection
                            await selectWallet(wallet.name);
                        });

                        elements.walletsList.appendChild(walletCard);
                    });
                }

                return activeWallets;
            } else {
                throw new Error(response.errorMsg || 'Failed to load wallets');
            }
        } catch (error) {
            console.error('Error loading wallets:', error);
            
            if (elements.walletsList) {
                elements.walletsList.innerHTML = `<div style="color: var(--error); text-align: center; padding: 20px;">Error loading wallets: ${error.message}</div>`;
            }
            
            if (elements.walletError) {
                showError(`Error loading wallets: ${error.message}`, 'walletError');
            }
            
            throw error;
        }
    }

    /**
     * Select a wallet and get its details
     * @param {string} walletName - The name of the wallet to select
     * @returns {Promise} A promise that resolves with the wallet details
     */
    async function selectWallet(walletName) {
        if (!sessionId) {
            throw new Error('Not connected to dashboard');
        }

        try {
            // Store selected wallet
            selectedWallet = walletName;

            // Retrieve wallet data to get networks
            const walletData = await getWalletData(walletName);
            
            if (walletData && walletData.data && walletData.data.length > 0) {
                // Use the first network (typically Backbone)
                selectedNetwork = walletData.data[0].network;
                
                // Get wallet address from first network
                const walletAddress = walletData.data[0].address;

                // Create wallet object
                const wallet = {
                    name: walletName,
                    network: selectedNetwork,
                    address: walletAddress,
                    data: walletData.data
                };
                
                // Store wallet data by name for future reference
                walletsByName[walletName] = wallet;
                console.log(`Stored wallet data for ${walletName}:`, wallet);
                
                // Save session state
                saveSessionState();

                // Call the onWalletSelected callback if provided
                if (typeof config.onWalletSelected === 'function') {
                    config.onWalletSelected(wallet);
                }

                // Move to DNA selection step if elements exist
                if (elements.walletSection && elements.dnaSection) {
                    elements.walletSection.style.display = 'none';
                    elements.dnaSection.style.display = 'block';
                }

                // Load DNA nicknames for this wallet
                await loadDNAs(walletName, walletAddress);

                return wallet;
            } else {
                throw new Error('Failed to get wallet data');
            }
        } catch (error) {
            console.error('Error selecting wallet:', error);
            
            if (elements.walletError) {
                showError(`Error selecting wallet: ${error.message}`, 'walletError');
            }
            
            throw error;
        }
    }

    /**
     * Get detailed wallet data
     * @param {string} walletName - The name of the wallet
     * @returns {Promise} A promise that resolves with the wallet data
     */
    async function getWalletData(walletName) {
        try {
            return await makeRequest('GetDataWallet', {
                id: sessionId,
                walletName: walletName
            });
        } catch (error) {
            console.error(`Error fetching data for wallet ${walletName}:`, error);
            throw error;
        }
    }

    /**
     * Load DNA nicknames associated with the wallet address
     * @param {string} walletName - The wallet name
     * @param {string} walletAddress - The wallet address
     * @returns {Promise} A promise that resolves with the list of DNA nicknames
     */
    async function loadDNAs(walletName, walletAddress) {
        try {
            if (elements.dnaList) {
                elements.dnaList.innerHTML = '<div style="text-align: center; padding: 20px;">Loading DNA nicknames...</div>';
            }

            // Query the DNA API to find nicknames registered to this address
            const dnaResponse = await fetch(`${config.dnaProxyUrl}?lookup=${encodeURIComponent(walletAddress)}`);
            const text = await dnaResponse.text();

            try {
                const data = JSON.parse(text);

                // Check if we have a proper response with DNA data
                if (data.status_code === 0 && data.response_data) {
                    const registeredNames = data.response_data.registered_names || {};
                    userDNAs = Object.keys(registeredNames);

                    if (userDNAs.length === 0) {
                        if (elements.dnaList) {
                            elements.dnaList.innerHTML = `
                                <div style="color: var(--error); text-align: center; padding: 20px;">
                                    No DNA nicknames found for this wallet.<br>
                                    <a href="register.html" style="color: var(--primary); text-decoration: underline;">Register a DNA nickname</a> first.
                                </div>
                            `;
                        }
                        return [];
                    }

                    // Clear DNA list if element exists
                    if (elements.dnaList) {
                        elements.dnaList.innerHTML = '';

                        // Add each DNA to the list
                        userDNAs.forEach(dna => {
                            const dnaCard = document.createElement('div');
                            dnaCard.className = 'wallet-card';  // Use same class as wallets
                            
                            dnaCard.innerHTML = `
                                <div class="wallet-name">${dna}</div>
                                <div class="wallet-address">Wallet: ${walletName}</div>
                            `;

                            dnaCard.addEventListener('click', () => {
                                // Deselect all DNA cards
                                document.querySelectorAll('#dnaList .wallet-card').forEach(card => {
                                    card.classList.remove('selected');
                                });

                                // Select this DNA card
                                dnaCard.classList.add('selected');

                                // Handle DNA selection
                                selectDNA(dna, registeredNames[dna]);
                            });

                            elements.dnaList.appendChild(dnaCard);
                        });
                    }

                    return userDNAs;
                } else {
                    // No DNA found - handle gracefully
                    if (elements.dnaList) {
                        elements.dnaList.innerHTML = `
                            <div style="color: var(--error); text-align: center; padding: 20px;">
                                No DNA registration found for this wallet.<br>
                                <a href="register.html" style="color: var(--primary); text-decoration: underline;">Register a DNA nickname</a> first.
                            </div>
                        `;
                    }
                    return [];
                }
            } catch (e) {
                // If parsing fails or no data found
                if (text.includes('not found') || text.trim() === '') {
                    if (elements.dnaList) {
                        elements.dnaList.innerHTML = `
                            <div style="color: var(--error); text-align: center; padding: 20px;">
                                No DNA registration found for this wallet.<br>
                                <a href="register.html" style="color: var(--primary); text-decoration: underline;">Register a DNA nickname</a> first.
                            </div>
                        `;
                    }
                    return [];
                } else {
                    throw new Error(`Failed to parse response: ${e.message}`);
                }
            }
        } catch (error) {
            console.error('Error loading DNAs:', error);
            
            if (elements.dnaList) {
                elements.dnaList.innerHTML = `<div style="color: var(--error); text-align: center; padding: 20px;">Error loading DNA nicknames: ${error.message}</div>`;
            }
            
            if (elements.dnaError) {
                showError(`Error loading DNA nicknames: ${error.message}`, 'dnaError');
            }
            
            throw error;
        }
    }

    /**
     * Select a DNA nickname
     * @param {string} dna - The DNA nickname to select
     * @param {Object} dnaInfo - The DNA information object
     */
    function selectDNA(dna, dnaInfo) {
        selectedDNA = dna;

        // Create DNA object with additional info
        // Get the actual wallet address from the most recently selected wallet
        let walletAddress = null;
        
        try {
            // Try to look up the wallet data to get the address
            const walletData = walletsByName[selectedWallet];
            if (walletData && walletData.address) {
                walletAddress = walletData.address;
                console.log('Using address from walletsByName:', walletAddress);
            }
        } catch (e) {
            console.error('Error getting wallet address:', e);
        }
        
        // Create the DNA object with either address or name
        const dnaObject = {
            name: dna,
            info: dnaInfo,
            wallet: walletAddress || selectedWallet, // Use address if available, fallback to wallet name
            network: selectedNetwork,
            walletName: selectedWallet // Always include the wallet name for reference
        };

        // Call the onDnaSelected callback if provided
        if (typeof config.onDnaSelected === 'function') {
            config.onDnaSelected(dnaObject);
        }

        return dnaObject;
    }

    /**
     * Make a request to the Cellframe dashboard API
     * @param {string} method - The API method to call
     * @param {Object} params - The parameters to send
     * @returns {Promise} A promise that resolves with the API response
     */
    async function makeRequest(method, params = {}) {
        // Add a call stack trace to help debug where this function is being called from
        console.log(`makeRequest('${method}') called from:`, new Error().stack);
        
        // Check if we have a request in progress for this method
        if (!window.apiRequestsInProgress) {
            window.apiRequestsInProgress = {};
        }
        
        // For Connect method specifically, prevent duplicate requests
        if (method === 'Connect' && window.apiRequestsInProgress[method]) {
            console.warn(`Request to ${method} already in progress, blocking duplicate request`);
            return window.apiRequestsInProgress[method]; // Return the existing promise
        }
        
        const url = new URL(config.apiUrl);
        url.searchParams.append('method', method);

        for (const [key, value] of Object.entries(params)) {
            url.searchParams.append(key, value);
        }

        // Use logAPI if it exists (for on-screen logging)
        if (typeof window.logAPI === 'function') {
            window.logAPI(`API Request: ${method}`, {
                url: url.toString(),
                params: params
            });
        } else {
            console.log(`API Request (${method}):`, {
                url: url.toString(),
                params: params
            });
        }

        try {
            const response = await fetch(url.toString());
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const jsonResponse = await response.json();
            
            // Use logAPI if it exists (for on-screen logging)
            if (typeof window.logAPI === 'function') {
                window.logAPI(`API Response: ${method}`, jsonResponse);
            } else {
                console.log(`API Response (${method}):`, jsonResponse);
            }
            
            return jsonResponse;
        } catch (error) {
            // Log the error to both console and on-screen logger if available
            if (typeof window.logAPI === 'function') {
                window.logAPI(`API Error: ${method}`, { error: error.message, stack: error.stack });
            } else {
                console.error(`API Request Error (${method}):`, error);
            }
            throw error;
        }
    }

    /**
     * Get the current session ID
     * @returns {string|null} The current session ID or null if not connected
     */
    function getSessionId() {
        return sessionId;
    }

    /**
     * Get the selected wallet
     * @returns {string|null} The selected wallet name or null if none selected
     */
    function getSelectedWallet() {
        return selectedWallet;
    }

    /**
     * Get the selected DNA
     * @returns {string|null} The selected DNA nickname or null if none selected
     */
    function getSelectedDNA() {
        return selectedDNA;
    }

    /**
     * Reset the dashboard connector state
     */
    function reset() {
        sessionId = null;
        selectedWallet = null;
        selectedNetwork = null;
        selectedDNA = null;
        userDNAs = [];
        walletsByName = {};
        
        // Clear cached session data
        clearSessionState();
        
        updateStatus('disconnected', 'Disconnected');
        
        if (elements.connectButton) {
            elements.connectButton.disabled = false;
            elements.connectButton.textContent = 'Connect to Dashboard';
        }
        
        if (elements.walletSection) {
            elements.walletSection.style.display = 'none';
        }
        
        if (elements.dnaSection) {
            elements.dnaSection.style.display = 'none';
        }
    }

    // Public API
    return {
        init,
        connectToDashboard,
        loadWallets,
        selectWallet,
        loadDNAs,
        selectDNA,
        getSessionId,
        getSelectedWallet,
        getSelectedDNA,
        reset,
        makeRequest,
        getWallets: loadWallets  // Adding getWallets as an alias for loadWallets
    };
})();
