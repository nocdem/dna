// settings.js - Core functionality for the settings page

// Global variables
let walletAddress = null;
let dnaData = null;

// External wallets now managed by WalletIntegration module
let externalWallets = {};

document.addEventListener('DOMContentLoaded', function() {
    
    // Initialize UI components
    initUI();
    
    // Initialize Social Integration module
    if (typeof SocialIntegration !== 'undefined') {
        SocialIntegration.init();
    }
    
    // Initialize Wallet Integration module
    if (typeof WalletIntegration !== 'undefined') {
        WalletIntegration.init({
            onWalletUpdate: function(wallets) {
                // Update external wallets reference
                externalWallets = wallets;
                // Auto-save profile data when wallet is connected
                saveProfileDataSilently();
            }
        });
    }
    
    // Set up event listeners
    setupEventListeners();
    
    // Check for pending Telegram verification and show instructions if needed
    setTimeout(() => {
        if (typeof SocialIntegration !== 'undefined') {
            SocialIntegration.checkPendingTelegramVerification();
        }
    }, 1000);
    
    // Initialize Dashboard connector
    if (typeof CpunkDashboard !== 'undefined') {
        CpunkDashboard.init({
            onConnected: function(sessionId) { 
                // Show wallet selection after connection and hide other sections
                const walletSection = document.getElementById('walletSection');
                const dnaSection = document.getElementById('dnaSection');
                const editSection = document.getElementById('editSection');
                
                if (walletSection) walletSection.style.display = 'block';
                if (dnaSection) dnaSection.style.display = 'none';
                if (editSection) editSection.style.display = 'none';
            },
            onWalletSelected: function(wallet) {
                // Store wallet address
                if (wallet && wallet.address) {
                    walletAddress = wallet.address;
                    
                    // External wallets (dinosaur wallets) will be loaded from API for this wallet
                    
                    // Clear cached DNA data
                    dnaData = null;
                    
                    // Update Social Integration module with wallet address
                    if (typeof SocialIntegration !== 'undefined') {
                        SocialIntegration.setWalletAddress(walletAddress);
                        SocialIntegration.setDnaData(null); // Clear cached DNA data
                    }
                    
                    // Set wallet address to hidden input for forms
                    const walletAddressInput = document.getElementById('walletAddress');
                    if (walletAddressInput) walletAddressInput.value = walletAddress;
                    
                    // Hide wallet section and show DNA section
                    const walletSection = document.getElementById('walletSection');
                    const dnaSection = document.getElementById('dnaSection');
                    
                    if (walletSection) walletSection.style.display = 'none';
                    if (dnaSection) dnaSection.style.display = 'block';
                    
                    // Check DNA registration
                    checkDnaRegistration();
                }
            }
        });
    }
});

/**
 * Initialize UI components
 */
function initUI() {
    // Initialize tab navigation
    initTabNavigation();
    
    // Initially hide Save button unless Info tab is active
    const saveButton = document.getElementById('saveButton');
    const infoTabButton = document.querySelector('.tab-button[data-tab="info-tab"]');
    if (saveButton && !infoTabButton.classList.contains('active')) {
        saveButton.style.display = 'none';
    }
}

/**
 * Initialize tab navigation
 */
function initTabNavigation() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');


    if (!tabButtons.length || !tabContents.length) {
        console.error('Tab navigation elements not found');
        return;
    }

    // No initial tab restrictions

    // Define tab switching function
    window.switchTab = function(tabId) {
        
        // All tabs are accessible regardless of wallet selection
        
        // Update active tab button
        tabButtons.forEach(btn => {
            if (btn.getAttribute('data-tab') === tabId) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        // Show selected tab content
        tabContents.forEach(content => {
            if (content.id === tabId) {
                content.classList.add('active');
                content.style.display = 'block';
            } else {
                content.classList.remove('active');
                content.style.display = 'none';
            }
        });
        
        // Show/hide save button based on active tab
        const saveButton = document.getElementById('saveButton');
        if (saveButton) {
            // Only show save button on the Info tab
            if (tabId === 'info-tab') {
                saveButton.style.display = 'block';
            } else {
                saveButton.style.display = 'none';
            }
        }
        
        // Special handling for specific tabs
        if (tabId === 'delegations-tab') {
            // Load delegations data when the tab is clicked
            loadDelegationsTab();
        } else if (tabId === 'dna-tab') {
            // Load DNA information when the tab is clicked
            loadDNAInformation();
        }
    };

    // Add click handlers to all tab buttons
    tabButtons.forEach(button => {
        const tabId = button.getAttribute('data-tab');
        
        button.addEventListener('click', () => {
            
            window.switchTab(tabId);
        });
    });
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // IMPORTANT: DO NOT add an event listener to connectButton in this file.
    // The dashboardConnector.js file already adds its own click handler.
    // Just setup other buttons below.
    
    // Wallet connection buttons are now handled by WalletIntegration module
    
    // Edit button
    const editButton = document.getElementById('editButton');
    if (editButton) {
        editButton.addEventListener('click', function() {
            document.getElementById('dnaSection').style.display = 'none';
            document.getElementById('editSection').style.display = 'block';
            editButton.style.display = 'none';
        });
    }
    
    // Save button
    const saveButton = document.getElementById('saveButton');
    if (saveButton) {
        saveButton.addEventListener('click', async function() {
            const saveSuccess = document.getElementById('saveSuccess');
            const saveError = document.getElementById('saveError');
            
            try {
                // Disable button during save
                saveButton.disabled = true;
                saveButton.textContent = 'Saving...';
                
                await saveProfileData(false);
                
            } catch (error) {
                console.error('Error saving settings:', error);
                
                // Show error
                if (saveError) {
                    saveError.textContent = error.message || 'Failed to save settings';
                    saveError.style.display = 'block';
                    setTimeout(() => {
                        saveError.style.display = 'none';
                    }, 5000);
                }
                
                // Hide success message if shown
                if (saveSuccess) {
                    saveSuccess.style.display = 'none';
                }
            } finally {
                // Reset button
                saveButton.disabled = false;
                saveButton.textContent = 'Save Profile Changes';
            }
        });
    }
    
    /**
     * Save profile data to server
     * @param {boolean} silent - Whether to show success/error messages
     * @returns {Promise<boolean>} - Whether the save was successful
     */
    async function saveProfileData(silent = false) {
        const saveSuccess = document.getElementById('saveSuccess');
        const saveError = document.getElementById('saveError');
        
        try {
            // Get profile data
            const profileDescription = document.getElementById('profileDescription');
            const profileImageUrl = document.getElementById('profileImageUrl');
            const description = profileDescription ? profileDescription.value : '';
            const imageUrl = profileImageUrl ? profileImageUrl.value : '';
            
            // Only proceed if we have the wallet address
            if (!walletAddress) {
                throw new Error('No wallet address available. Please connect to dashboard first.');
            }
            
            // Prepare update data including wallet connections
            const updateData = {
                action: 'update',
                wallet: walletAddress,
                bio: description,
                profile_picture: imageUrl,
                dinosaur_wallets: externalWallets  // Contains ETH, BTC, SOL addresses from all connected wallets
            };
            
            
            // Post to dna-proxy.php to update the DNA record
            const response = await fetch('dna-proxy.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updateData)
            });
            
            if (!response.ok) {
                throw new Error(`Failed to save settings: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.status_code !== 0 && !data.success) {
                throw new Error(data.error_message || 'Failed to save settings');
            }
            
            // Display success message if not silent
            if (!silent && saveSuccess) {
                saveSuccess.textContent = 'Profile settings saved successfully!';
                saveSuccess.style.display = 'block';
                setTimeout(() => {
                    saveSuccess.style.display = 'none';
                }, 3000);
            }
            
            return true;
        } catch (error) {
            console.error('Error saving settings:', error);
            
            // Show error if not silent
            if (!silent && saveError) {
                saveError.textContent = error.message || 'Failed to save settings';
                saveError.style.display = 'block';
                setTimeout(() => {
                    saveError.style.display = 'none';
                }, 5000);
            }
            
            // Hide success message if shown
            if (!silent && saveSuccess) {
                saveSuccess.style.display = 'none';
            }
            
            return false;
        }
    }
    
    /**
     * Save profile data silently (no UI feedback)
     */
    async function saveProfileDataSilently() {
        try {
            // Add a delay to ensure wallet values are properly set
            setTimeout(async () => {
                try {
                    // Log the data being saved for debugging
                    
                    const result = await saveProfileData(true);
                } catch (innerError) {
                    console.error('Failed in delayed auto-save:', innerError);
                }
            }, 500);
        } catch (error) {
            console.error('Failed to auto-save profile data:', error);
        }
    }
    
    // Continue button
    const continueButton = document.getElementById('continueButton');
    if (continueButton) {
        continueButton.addEventListener('click', function() {
            // Hide wallet section, show DNA section
            const walletSection = document.getElementById('walletSection');
            const dnaSection = document.getElementById('dnaSection');
            
            if (walletSection) walletSection.style.display = 'none';
            if (dnaSection) dnaSection.style.display = 'block';
            
            // Check DNA registration if wallet is selected
            if (walletAddress) {
                checkDnaRegistration();
            }
        });
    }
}

/**
 * Check DNA registration for the selected wallet
 */
async function checkDnaRegistration() {
    if (!walletAddress) {
        console.error('Wallet address is missing');
        return;
    }

    const dnaStatus = document.getElementById('dnaStatus');
    const dnaError = document.getElementById('dnaError');
    const dnaDetails = document.getElementById('dnaDetails');
    
    // Show loading state
    if (dnaStatus) {
        dnaStatus.textContent = 'Checking DNA registration...';
        dnaStatus.style.display = 'block';
        dnaStatus.className = 'loading';
    }
    if (dnaError) {
        dnaError.style.display = 'none';
    }
    if (dnaDetails) {
        dnaDetails.style.display = 'none';
    }

    try {
        // Use the dna-proxy.php endpoint to check DNA registration
        const response = await fetch(`dna-proxy.php?lookup=${encodeURIComponent(walletAddress)}`);
        if (!response.ok) {
            throw new Error(`DNA check failed: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // Debug entire response object structure
        
        // Store data globally
        dnaData = data;
        
        // Update Social Integration module with DNA data
        if (typeof SocialIntegration !== 'undefined') {
            SocialIntegration.setDnaData(data);
        }
        
        // Hide loading state
        if (dnaStatus) {
            dnaStatus.style.display = 'none';
        }

        // Check data format and normalize it
        let userData = null;
        
        // Handle different API response formats
        if (data.status_code === 0 && data.response_data) {
            // Official API format (api.dna.cpunk.club)
            userData = data.response_data;
            
            // Check for dinosaur_wallets in response_data
            if (data.response_data.dinosaur_wallets) {
                // Update wallet integration module with stored wallet addresses
                if (typeof WalletIntegration !== 'undefined') {
                    WalletIntegration.setExternalWallets(data.response_data.dinosaur_wallets);
                    externalWallets = WalletIntegration.getExternalWallets();
                }
            }
            
            // Check for delegations in response_data
            if (data.response_data.delegations && Array.isArray(data.response_data.delegations)) {
                displayDelegationsData(data.response_data.delegations);
            }
        } else if (data.registered_names) {
            // Direct data format (no wrapper)
            userData = data;
            
            // Check for dinosaur_wallets directly in data
            if (data.dinosaur_wallets) {
                // Update wallet integration module with stored wallet addresses
                if (typeof WalletIntegration !== 'undefined') {
                    WalletIntegration.setExternalWallets(data.dinosaur_wallets);
                    externalWallets = WalletIntegration.getExternalWallets();
                }
            }
            
            // Check for delegations directly in data
            if (data.delegations && Array.isArray(data.delegations)) {
                displayDelegationsData(data.delegations);
            }
        } else if (data.data && data.data.registered_names) {
            // Alternative wrapper format
            userData = data.data;
            
            // Check for dinosaur_wallets in data.data
            if (data.data.dinosaur_wallets) {
                // Update wallet integration module with stored wallet addresses
                if (typeof WalletIntegration !== 'undefined') {
                    WalletIntegration.setExternalWallets(data.data.dinosaur_wallets);
                    externalWallets = WalletIntegration.getExternalWallets();
                }
            }
            
            // Check for delegations in data.data
            if (data.data.delegations && Array.isArray(data.data.delegations)) {
                displayDelegationsData(data.data.delegations);
            }
        }
        
        // Process normalized user data
        if (userData) {
            const registeredNames = userData.registered_names || {};
            const nicknames = Object.keys(registeredNames);

            if (nicknames.length === 0) {
                // No DNA registrations found
                if (dnaStatus) {
                    dnaStatus.className = '';
                    dnaStatus.textContent = 'No DNA registration found';
                    dnaStatus.style.display = 'block';
                }
                return;
            }

            // Update profile preview with normalized data
            updateProfilePreview(userData);
            
            // Load DNA information right away without waiting for tab click
            displayDNAInformation(data);

            // Show DNA details and edit button
            if (dnaDetails) {
                dnaDetails.style.display = 'block';
            }
            
            // Show edit button when DNA data is found
            const editButton = document.getElementById('editButton');
            if (editButton) {
                editButton.style.display = 'block';
            }
            
            // Check for pending Telegram verification and show instructions if needed
            if (typeof SocialIntegration !== 'undefined') {
                SocialIntegration.checkPendingTelegramVerification();
            }
        } else {
            // Error or no DNA registrations
            if (dnaStatus) {
                dnaStatus.className = '';
                dnaStatus.textContent = data.error_message || 'No DNA registration found';
                dnaStatus.style.display = 'block';
            }
        }
    } catch (error) {
        console.error('DNA check error:', error);
        
        // Show error
        if (dnaStatus) {
            dnaStatus.style.display = 'none';
        }
        if (dnaError) {
            dnaError.textContent = error.message || 'Failed to check DNA registration';
            dnaError.style.display = 'block';
        }
    }
}


/**
 * Update profile preview with DNA data
 */
function updateProfilePreview(data) {
    if (!data) return;

    const registeredNames = data.registered_names || {};
    const nicknames = Object.keys(registeredNames);
    const socialAccounts = data.social_accounts || {};
    
    // Check for dinosaur_wallets in the data
    if (data.dinosaur_wallets) {
        // Update wallet integration module with stored wallet addresses
        if (typeof WalletIntegration !== 'undefined') {
            WalletIntegration.setExternalWallets(data.dinosaur_wallets);
            externalWallets = WalletIntegration.getExternalWallets();
        }
    }
    
    // Check for delegations in the data
    if (data.delegations && Array.isArray(data.delegations)) {
        // Update the delegations UI
        displayDelegationsData(data.delegations);
    }

    // Update avatar and nickname
    const profileAvatar = document.getElementById('profileAvatar');
    const profileNickname = document.getElementById('profileNickname');
    const profileNicknames = document.getElementById('profileNicknames');

    if (profileAvatar && nicknames.length > 0) {
        // Set avatar letter to first letter of primary nickname
        const firstLetter = nicknames[0].charAt(0).toUpperCase();
        profileAvatar.textContent = firstLetter;
    }

    if (profileNickname && nicknames.length > 0) {
        profileNickname.textContent = nicknames[0];
    }

    // Update nickname tags for secondary nicknames
    if (profileNicknames) {
        let nicknameTags = '';
        if (nicknames.length > 1) {
            for (let i = 1; i < nicknames.length; i++) {
                nicknameTags += `<span class="nickname-tag">${nicknames[i]}</span>`;
            }
        }
        profileNicknames.innerHTML = nicknameTags;
    }

    // Update profile stats
    const nicknamesCount = document.getElementById('nicknamesCount');
    const socialsCount = document.getElementById('socialsCount');
    const walletsCount = document.getElementById('walletsCount');

    if (nicknamesCount) nicknamesCount.textContent = nicknames.length;
    if (socialsCount) socialsCount.textContent = Object.keys(socialAccounts).length;
    if (walletsCount) walletsCount.textContent = Object.keys(externalWallets).length;

    // Populate form fields
    const profileDescription = document.getElementById('profileDescription');
    const profileImageUrl = document.getElementById('profileImageUrl');
    const pubkeyHash = document.getElementById('pubkeyHash');
    
    if (profileDescription) {
        // Check multiple possible field names for bio/description
        const description = data.description || data.bio || 
            (data.response_data ? (data.response_data.description || data.response_data.bio || '') : '');
        profileDescription.value = description;
    }
    if (profileImageUrl) {
        // Check multiple possible field names for profile image
        const imageUrl = data.image_url || data.profile_picture || 
            (data.response_data ? (data.response_data.image_url || data.response_data.profile_picture || '') : '');
        profileImageUrl.value = imageUrl;
    }
    if (pubkeyHash) {
        pubkeyHash.value = walletAddress || '';
    }

    // Update social profiles
    if (typeof SocialIntegration !== 'undefined') {
        SocialIntegration.updateSocialProfiles(data);
    }
}

// Social integration functions have been moved to social-integration.js
// The following functions have been removed and replaced with SocialIntegration module calls:
// - updateSocialProfiles, updateSocialProfile, updateSocialSummary, updateConnectButtons
// - updateSocialCount, setupSocialButtons, setupDuplicateSocialButtons
// - openOAuthPopup, handleOAuthCallback, handleTwitterSuccess, handleGoogleSuccess
// - handleLinkedInSuccess, handleGitHubSuccess, openTelegramVerification
// - continueTelegramVerification, checkPendingTelegramVerification


// Cryptocurrency wallet functions have been moved to wallet-integration.js
// The following functions have been removed and replaced with WalletIntegration module calls:
// - connectEthWallet, connectBtcWallet, connectSolWallet, connectBnbWallet
// - connectSolWalletWithPhantom, updateWalletUI, setupWalletButtons





/**
 * Load DNA information in the DNA tab
 */
function loadDNAInformation() {
    
    const linkedDNAsElement = document.getElementById('linkedDNAs');
    const noDNAsElement = document.getElementById('noDNAs');
    
    if (!linkedDNAsElement || !noDNAsElement) return;
    
    // If no wallet is selected, show message
    if (!walletAddress) {
        linkedDNAsElement.style.display = 'none';
        noDNAsElement.style.display = 'block';
        noDNAsElement.innerHTML = `
            <p>No wallet selected.</p>
            <p>Please select a wallet first to view DNA information.</p>
        `;
        return;
    }
    
    // If we already have DNA data, ensure it's displayed
    if (dnaData) {
        displayDNAInformation(dnaData);
    }
}

/**
 * Load and display delegations tab data
 */
function loadDelegationsTab() {
    const delegationsListElement = document.getElementById('delegationsList');
    const noDelegationsElement = document.getElementById('noDelegations');
    
    if (!delegationsListElement || !noDelegationsElement) return;

    
    // Show loading state
    delegationsListElement.innerHTML = '<div class="loading">Loading delegation history...</div>';
    delegationsListElement.style.display = 'block';
    noDelegationsElement.style.display = 'none';
    
    // If we don't have a wallet address, we can't load delegations
    if (!walletAddress) {
        delegationsListElement.style.display = 'none';
        noDelegationsElement.style.display = 'block';
        noDelegationsElement.innerHTML = `
            <p>No wallet selected.</p>
            <p>Please select a wallet first to view delegation history.</p>
        `;
        return;
    }
    
    // If we already have dnaData with delegations, display them
    if (dnaData) {
        // Check different possible data structures for delegations
        let delegations = [];
        
        if (dnaData.response_data && dnaData.response_data.delegations) {
            delegations = dnaData.response_data.delegations;
        } else if (dnaData.delegations) {
            delegations = dnaData.delegations;
        } else if (dnaData.data && dnaData.data.delegations) {
            delegations = dnaData.data.delegations;
        }
        
        // Display delegations if we found any
        if (delegations && delegations.length > 0) {
            displayDelegationsData(delegations);
            return;
        }
        
        // If no delegations were found in the data, show "No delegations" message
        delegationsListElement.style.display = 'none';
        noDelegationsElement.style.display = 'block';
        return;
    }
    
    // If we don't have delegation data yet, fetch it from the API
    refreshDelegationsData();
}

/**
 * Refresh delegations data from the API
 */
async function refreshDelegationsData() {
    if (!walletAddress) {
        console.error('Cannot refresh delegations: No wallet address');
        return;
    }
    
    const delegationsListElement = document.getElementById('delegationsList');
    const noDelegationsElement = document.getElementById('noDelegations');
    
    try {
        // Fetch fresh data from API
        const response = await fetch(`dna-proxy.php?lookup=${encodeURIComponent(walletAddress)}`);
        
        if (!response.ok) {
            throw new Error(`Failed to fetch DNA data: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // Find delegations in the response
        let delegations = [];
        
        if (data.response_data && data.response_data.delegations) {
            delegations = data.response_data.delegations;
        } else if (data.delegations) {
            delegations = data.delegations;
        } else if (data.data && data.data.delegations) {
            delegations = data.data.delegations;
        }
        
        // Display delegations
        if (delegations && Array.isArray(delegations) && delegations.length > 0) {
            displayDelegationsData(delegations);
        } else {
            if (delegationsListElement) delegationsListElement.style.display = 'none';
            if (noDelegationsElement) noDelegationsElement.style.display = 'block';
        }
    } catch (error) {
        console.error('Error refreshing delegations data:', error);
        
        // Show error state
        if (delegationsListElement) {
            delegationsListElement.innerHTML = `<div style="color: var(--error); text-align: center; padding: 20px;">Error loading delegations: ${error.message}</div>`;
        }
    }
}

/**
 * Display delegation data in the delegations tab
 */
function displayDelegationsData(delegations) {
    const delegationsListElement = document.getElementById('delegationsList');
    const noDelegationsElement = document.getElementById('noDelegations');
    
    if (!delegationsListElement || !noDelegationsElement) return;
    
    // Clear the loading message first
    delegationsListElement.innerHTML = '';
    
    // Check if we have any delegations
    if (!delegations || delegations.length === 0) {
        delegationsListElement.style.display = 'none';
        noDelegationsElement.style.display = 'block';
        return;
    }
    
    // We have delegations to display
    let delegationsHTML = '';
    
    // Format amount to show with appropriate decimal places
    const formatAmount = (amount) => {
        if (typeof amount === 'number') {
            // Check if scientific notation (e.g., 1e-06)
            if (amount.toString().includes('e')) {
                // Convert from scientific notation and show proper decimals
                return Number(amount).toFixed(8);
            } else {
                return amount.toString();
            }
        }
        return amount || 'N/A';
    };
    
    // Format date from timestamp or ISO string
    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        
        try {
            if (typeof dateString === 'number') {
                // Assume it's a Unix timestamp
                return new Date(dateString * 1000).toLocaleDateString();
            } else {
                // Assume it's an ISO string
                return new Date(dateString).toLocaleDateString();
            }
        } catch (e) {
            console.error('Error formatting date:', e);
            return dateString;
        }
    };
    
    // Sort delegations by timestamp (newest first)
    const sortedDelegations = [...delegations].sort((a, b) => {
        const timeA = a.timestamp || (a.delegation_time ? new Date(a.delegation_time).getTime() / 1000 : 0);
        const timeB = b.timestamp || (b.delegation_time ? new Date(b.delegation_time).getTime() / 1000 : 0);
        return timeB - timeA;
    });
    
    // For each delegation, create a display card
    sortedDelegations.forEach(delegation => {
        delegationsHTML += `
            <div class="delegation-card" style="margin-bottom: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15); background-color: var(--primary-bg); border: 1px solid var(--border-color);">
                <!-- Card header removed as requested -->
                
                <!-- Basic info section -->
                <div style="padding: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); display: grid; grid-template-columns: 100px 1fr; gap: 5px; font-size: 0.9em;">
                    <p style="margin: 5px 0; opacity: 0.8;">Amount:</p>
                    <p style="margin: 5px 0; font-weight: bold;">${formatAmount(delegation.amount)}</p>
                    
                    <p style="margin: 5px 0; opacity: 0.8;">Network:</p>
                    <p style="margin: 5px 0;">${delegation.network}</p>
                    
                    <p style="margin: 5px 0; opacity: 0.8;">Tax Rate:</p>
                    <p style="margin: 5px 0;">${delegation.tax || 'N/A'}%</p>
                    
                    <p style="margin: 5px 0; opacity: 0.8;">Date:</p>
                    <p style="margin: 5px 0;">${formatDate(delegation.delegation_time || delegation.timestamp)}</p>
                </div>
                
                <!-- Hash information section -->
                <div style="padding: 15px; background-color: rgba(0,0,0,0.05);">
                    <p style="margin: 5px 0 8px 0; opacity: 0.8; font-weight: bold;">Tx Hash:</p>
                    <div style="font-family: monospace; word-break: break-all; background-color: rgba(0,0,0,0.2); padding: 10px; border-radius: 4px; font-size: 0.85em;">${delegation.tx_hash || 'N/A'}</div>
                    
                    <p style="margin: 15px 0 8px 0; opacity: 0.8; font-weight: bold;">Order Hash:</p>
                    <div style="font-family: monospace; word-break: break-all; background-color: rgba(0,0,0,0.2); padding: 10px; border-radius: 4px; font-size: 0.85em;">${delegation.order_hash || 'N/A'}</div>
                </div>
            </div>
        `;
    });
    
    // Update the delegationsList element with our HTML
    delegationsListElement.innerHTML = delegationsHTML;
    delegationsListElement.style.display = 'block';
    noDelegationsElement.style.display = 'none';
}

/**
 * Display DNA information in the DNA tab
 */
function displayDNAInformation(data) {
    const linkedDNAsElement = document.getElementById('linkedDNAs');
    const noDNAsElement = document.getElementById('noDNAs');
    
    if (!linkedDNAsElement || !noDNAsElement) return;
    
    // Get registration data
    let registeredNames = {};
    
    // Handle different data formats
    if (data.response_data && data.response_data.registered_names) {
        registeredNames = data.response_data.registered_names;
        
        // Check for dinosaur_wallets in response_data
        if (data.response_data.dinosaur_wallets) {
            // Update wallet integration module with stored wallet addresses
            if (typeof WalletIntegration !== 'undefined') {
                WalletIntegration.setExternalWallets(data.response_data.dinosaur_wallets);
                externalWallets = WalletIntegration.getExternalWallets();
            }
        }
    } else if (data.registered_names) {
        registeredNames = data.registered_names;
        
        // Check for dinosaur_wallets directly in data
        if (data.dinosaur_wallets) {
            // Update wallet integration module with stored wallet addresses
            if (typeof WalletIntegration !== 'undefined') {
                WalletIntegration.setExternalWallets(data.dinosaur_wallets);
                externalWallets = WalletIntegration.getExternalWallets();
            }
        }
    }
    
    const nicknames = Object.keys(registeredNames);
    
    // Check if we have any names
    if (nicknames.length === 0) {
        linkedDNAsElement.style.display = 'none';
        noDNAsElement.style.display = 'block';
        return;
    }
    
    // We have DNA data to display
    let dnaHTML = '';
    
    // For each nickname/DNA, create a display card
    nicknames.forEach(nickname => {
        const registrationData = registeredNames[nickname];
        
        // Format dates - handle different property names from API
        let registrationDate = 'N/A';
        let expirationDate = 'N/A';
        
        // Try different possible property names for registration date
        if (registrationData.created_at) {
            // ISO string format from API
            registrationDate = new Date(registrationData.created_at).toLocaleDateString();
        } else if (registrationData.registration_date) {
            // Unix timestamp format
            registrationDate = new Date(registrationData.registration_date * 1000).toLocaleDateString();
        }
        
        // Try different possible property names for expiration date
        if (registrationData.expires_on) {
            // ISO string format from API
            expirationDate = new Date(registrationData.expires_on).toLocaleDateString();
        } else if (registrationData.expiration_date) {
            // Unix timestamp format
            expirationDate = new Date(registrationData.expiration_date * 1000).toLocaleDateString();
        }
        
        dnaHTML += `
            <div class="dna-card" style="margin-bottom: 15px; padding: 15px; background-color: rgba(0, 0, 0, 0.1); border-radius: 6px; border: 1px solid var(--border-color);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="margin: 0; font-size: 1.2em;">${nickname}</h3>
                    <span class="badge" style="background-color: var(--accent-color); padding: 3px 8px; border-radius: 4px; font-size: 0.8em;">Active</span>
                </div>
                
                <div style="display: grid; grid-template-columns: 120px 1fr; gap: 5px; font-size: 0.9em;">
                    <span style="opacity: 0.7;">Registration Date:</span>
                    <span>${registrationDate}</span>
                    
                    <span style="opacity: 0.7;">Expiration Date:</span>
                    <span>${expirationDate}</span>
                    
                    <span style="opacity: 0.7;">Transaction Hash:</span>
                    <span style="font-size: 0.8em; word-break: break-all;">${registrationData.tx_hash || 'N/A'}</span>
                    
                    <span style="opacity: 0.7;">Public URL:</span>
                    <a href="https://cpunk.club/${nickname}" target="_blank" style="color: var(--accent-color);">https://cpunk.club/${nickname}</a>
                </div>
            </div>
        `;
    });
    
    // Update the linkedDNAs element with our HTML
    linkedDNAsElement.innerHTML = dnaHTML;
    linkedDNAsElement.style.display = 'block';
    noDNAsElement.style.display = 'none';
}



/**
 * Show error message
 */
function showError(message) {
    console.error(message);
    
    const saveError = document.getElementById('saveError');
    if (saveError) {
        saveError.textContent = message;
        saveError.style.display = 'block';
        
        // Hide success message if shown
        const saveSuccess = document.getElementById('saveSuccess');
        if (saveSuccess) saveSuccess.style.display = 'none';
        
        // Auto-hide error after a delay
        setTimeout(() => {
            saveError.style.display = 'none';
        }, 5000);
    }
}

/**
 * Show success message
 */
function showSuccess(message) {
    const saveSuccess = document.getElementById('saveSuccess');
    if (saveSuccess) {
        saveSuccess.textContent = message;
        saveSuccess.style.display = 'block';
        
        // Hide error message if shown
        const saveError = document.getElementById('saveError');
        if (saveError) saveError.style.display = 'none';
        
        // Auto-hide success after a delay
        setTimeout(() => {
            saveSuccess.style.display = 'none';
        }, 5000);
    }
}