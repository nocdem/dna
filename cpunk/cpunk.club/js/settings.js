// settings.js - Core functionality for the settings page

// Global variables
let walletAddress = null;
let dnaData = null;

// Store external wallet addresses
let externalWallets = {
    BTC: '',
    ETH: '',
    SOL: '',
    BNB: '',  // Added BNB wallet support
    QEVM: ''  // Added QEVM field to match updated API
};

document.addEventListener('DOMContentLoaded', function() {
    
    // Initialize UI components
    initUI();
    
    // Set up event listeners
    setupEventListeners();
    
    // Check for pending Telegram verification and show instructions if needed
    setTimeout(checkPendingTelegramVerification, 1000);
    
    // Initialize Dashboard connector
    if (typeof CpunkDashboard !== 'undefined') {
        CpunkDashboard.init({
            onConnected: function(sessionId) { 
                // Show wallet selection after connection
                const walletSection = document.getElementById('walletSection');
                if (walletSection) walletSection.style.display = 'block';
            },
            onWalletSelected: function(wallet) {
                // Store wallet address
                if (wallet && wallet.address) {
                    walletAddress = wallet.address;
                    
                    // Set wallet address to hidden input for forms
                    const walletAddressInput = document.getElementById('walletAddress');
                    if (walletAddressInput) walletAddressInput.value = walletAddress;
                    
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
    
    // Set up wallet connection buttons
    setupWalletButtons();
    
    // Set up social connection buttons
    setupSocialButtons();
    
    // Set up duplicate social buttons to connect the same functions
    setupDuplicateSocialButtons();
    
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
                // Store wallet addresses
                externalWallets = {
                    BTC: data.response_data.dinosaur_wallets.BTC || '',
                    ETH: data.response_data.dinosaur_wallets.ETH || '',
                    SOL: data.response_data.dinosaur_wallets.SOL || '',
                    QEVM: data.response_data.dinosaur_wallets.QEVM || ''
                };
                
                // Update UI for connected wallets
                updateWalletUI(data.response_data.dinosaur_wallets);
                
                // Force update to wallet tabs with a delay
                setTimeout(() => {
                    updateWalletUI(data.response_data.dinosaur_wallets);
                }, 500);
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
                externalWallets = {
                    BTC: data.dinosaur_wallets.BTC || '',
                    ETH: data.dinosaur_wallets.ETH || '',
                    SOL: data.dinosaur_wallets.SOL || '',
                    QEVM: data.dinosaur_wallets.QEVM || ''
                };
                
                // Update UI for connected wallets
                updateWalletUI(data.dinosaur_wallets);
                
                // Force update to wallet tabs with a delay
                setTimeout(() => {
                    updateWalletUI(data.dinosaur_wallets);
                }, 500);
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
                externalWallets = {
                    BTC: data.data.dinosaur_wallets.BTC || '',
                    ETH: data.data.dinosaur_wallets.ETH || '',
                    SOL: data.data.dinosaur_wallets.SOL || '',
                    QEVM: data.data.dinosaur_wallets.QEVM || ''
                };
                
                // Update UI for connected wallets
                updateWalletUI(data.data.dinosaur_wallets);
                
                // Force update to wallet tabs with a delay
                setTimeout(() => {
                    updateWalletUI(data.data.dinosaur_wallets);
                }, 500);
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

            // Show DNA details
            if (dnaDetails) {
                dnaDetails.style.display = 'block';
            }
            
            // Check for pending Telegram verification and show instructions if needed
            checkPendingTelegramVerification();
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
        // Store wallet addresses and update UI
        updateWalletUI(data.dinosaur_wallets);
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
    updateSocialProfiles(data);
}

/**
 * Update social profiles in the UI
 */
function updateSocialProfiles(data) {
    if (!data) return;
    
    // Store connected social profiles to update summary box later
    let connectedProfiles = [];
    
    // Check for socials in API response format (api.dna.cpunk.club format)
    // Example: data.response_data.socials.github.profile
    let socials = null;
    
    if (data.response_data && data.response_data.socials) {
        socials = data.response_data.socials;
    } else if (data.socials) {
        socials = data.socials;
    } else {
        // Fall back to old format if neither is found
        const socialAccounts = data.social_accounts || {};
        
        // Telegram
        if (socialAccounts.telegram) {
            const telegramProfile = socialAccounts.telegram;
            const isPending = telegramProfile.endsWith('-unverified');
            
            // For display, remove -unverified suffix
            const displayValue = telegramProfile.replace('-unverified', '');
            
            updateSocialProfile('telegram', displayValue, {
                inputId: 'telegramProfile',
                statusId: 'telegramVerificationStatus',
                buttonId: 'verifyTelegramButton',
                status: isPending ? 'pending' : 'verified'
            });
            
            connectedProfiles.push({
                platform: 'Telegram',
                icon: '📱',
                value: displayValue,
                verified: !isPending,
                status: isPending ? 'Pending' : 'Verified'
            });
        }
        
        // Twitter/X
        if (socialAccounts.twitter) {
            updateSocialProfile('twitter', socialAccounts.twitter, {
                inputId: 'xProfile',
                statusId: 'twitterVerificationStatus',
                buttonId: 'connectTwitterButton'
            });
            connectedProfiles.push({
                platform: 'Twitter',
                icon: '🐦',
                value: socialAccounts.twitter,
                verified: true
            });
        }
        
        // Google
        if (socialAccounts.google) {
            updateSocialProfile('google', socialAccounts.google, {
                inputId: 'googleProfile',
                statusId: 'googleVerificationStatus',
                buttonId: 'connectGoogleButton',
                buttonStyle: {
                    disabled: true,
                    text: 'Connected',
                    backgroundColor: '#00C851'
                }
            });
            connectedProfiles.push({
                platform: 'Google',
                icon: 'G',
                value: socialAccounts.google,
                verified: true
            });
        }
        
        // LinkedIn
        if (socialAccounts.linkedin) {
            updateSocialProfile('linkedin', socialAccounts.linkedin, {
                inputId: 'linkedinProfile',
                statusId: 'linkedinVerificationStatus',
                buttonId: 'connectLinkedInButton'
            });
            connectedProfiles.push({
                platform: 'LinkedIn',
                icon: '💼',
                value: socialAccounts.linkedin,
                verified: true
            });
        }
        
        // GitHub
        if (socialAccounts.github) {
            updateSocialProfile('github', socialAccounts.github, {
                inputId: 'githubProfile',
                statusId: 'githubVerificationStatus',
                buttonId: 'connectGitHubButton'
            });
            connectedProfiles.push({
                platform: 'GitHub',
                icon: '🐙',
                value: socialAccounts.github,
                verified: true
            });
        }
        
        // Update social summary box
        updateSocialSummary(connectedProfiles);
        
        // Exit early as we've handled the old format
        return;
    }
    
    // Process new format with socials.platform.profile structure
    
    // Telegram
    if (socials.telegram && socials.telegram.profile) {
        const telegramProfile = socials.telegram.profile;
        const isPending = telegramProfile.endsWith('-unverified');
        
        // For display, remove -unverified suffix
        const displayValue = telegramProfile.replace('-unverified', '');
        
        updateSocialProfile('telegram', displayValue, {
            inputId: 'telegramProfile',
            statusId: 'telegramVerificationStatus',
            buttonId: 'verifyTelegramButton',
            status: isPending ? 'pending' : 'verified'
        });
        
        connectedProfiles.push({
            platform: 'Telegram',
            icon: '📱',
            value: displayValue,
            verified: !isPending,
            status: isPending ? 'Pending' : 'Verified'
        });
    }
    
    // Twitter/X - Note: API uses "x" as the key
    if (socials.x && socials.x.profile) {
        updateSocialProfile('twitter', socials.x.profile, {
            inputId: 'xProfile',
            statusId: 'twitterVerificationStatus',
            buttonId: 'connectTwitterButton'
        });
        connectedProfiles.push({
            platform: 'Twitter',
            icon: '🐦',
            value: socials.x.profile,
            verified: true
        });
    }
    
    // Google
    if (socials.google && socials.google.profile) {
        updateSocialProfile('google', socials.google.profile, {
            inputId: 'googleProfile',
            statusId: 'googleVerificationStatus',
            buttonId: 'connectGoogleButton',
            buttonStyle: {
                disabled: true,
                text: 'Connected',
                backgroundColor: '#00C851'
            }
        });
        connectedProfiles.push({
            platform: 'Google',
            icon: 'G',
            value: socials.google.profile,
            verified: true
        });
    }
    
    // LinkedIn
    if (socials.linkedin && socials.linkedin.profile) {
        updateSocialProfile('linkedin', socials.linkedin.profile, {
            inputId: 'linkedinProfile',
            statusId: 'linkedinVerificationStatus',
            buttonId: 'connectLinkedInButton'
        });
        connectedProfiles.push({
            platform: 'LinkedIn',
            icon: '💼',
            value: socials.linkedin.profile,
            verified: true
        });
    }
    
    // GitHub
    if (socials.github && socials.github.profile) {
        updateSocialProfile('github', socials.github.profile, {
            inputId: 'githubProfile',
            statusId: 'githubVerificationStatus',
            buttonId: 'connectGitHubButton'
        });
        connectedProfiles.push({
            platform: 'GitHub',
            icon: '🐙',
            value: socials.github.profile,
            verified: true
        });
    }
    
    // Update social summary box
    updateSocialSummary(connectedProfiles);
    
    // Update the social count in the profile preview
    updateSocialCount();
}

/**
 * Update the social accounts summary box
 */
function updateSocialSummary(profiles) {
    const socialsListElement = document.getElementById('socialsList');
    const noSocialsElement = document.getElementById('noSocials');
    
    if (!socialsListElement || !noSocialsElement) return;
    
    // Check if we have any connected profiles
    if (profiles.length === 0) {
        socialsListElement.style.display = 'none';
        noSocialsElement.style.display = 'block';
        return;
    }
    
    // We have profiles to display
    let socialHTML = '';
    
    // Keep track of which platforms are connected
    const connectedPlatforms = profiles.map(p => p.platform.toLowerCase());
    
    // For each social profile, create a display entry
    profiles.forEach(profile => {
        socialHTML += `
            <div class="social-summary-item" style="display: flex; align-items: center; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.1);">
                <div style="width: 30px; height: 30px; border-radius: 50%; background-color: var(--accent-color); display: flex; align-items: center; justify-content: center; margin-right: 12px; font-weight: bold;">${profile.icon}</div>
                <div style="flex-grow: 1;">
                    <div style="font-weight: bold; margin-bottom: 2px;">
                        ${profile.platform} 
                        ${profile.verified 
                            ? '<span style="color: #4CAF50; margin-left: 5px;">✓</span>' 
                            : (profile.status === 'Pending' 
                                ? '<span style="color: #FFA500; margin-left: 5px;">(Pending)</span>' 
                                : '')
                        }
                    </div>
                    <div style="font-size: 0.9em; opacity: 0.9;">${profile.value}</div>
                </div>
            </div>
        `;
    });
    
    // Update the socialsList element with our HTML
    socialsListElement.innerHTML = socialHTML;
    socialsListElement.style.display = 'block';
    noSocialsElement.style.display = 'none';
    
    // Hide connect buttons for connected platforms
    updateConnectButtons(connectedPlatforms);
}

/**
 * Hide connect buttons for platforms that are already connected
 */
function updateConnectButtons(connectedPlatforms) {
    // Map of platform names to button IDs
    const buttonMap = {
        'twitter': 'connectTwitterButton2',
        'google': 'connectGoogleButton2',
        'telegram': 'verifyTelegramButton2',
        'linkedin': 'connectLinkedInButton2',
        'github': 'connectGitHubButton2'
    };
    
    // Track platforms with pending verification
    const pendingPlatforms = [];
    
    // Get all social profiles
    const socialItems = document.querySelectorAll('.social-summary-item');
    socialItems.forEach(item => {
        if (item.textContent.includes('Telegram') && item.textContent.includes('(Pending)')) {
            pendingPlatforms.push('telegram');
        }
    });
    
    // Already logged connected platforms above
    
    // Hide buttons for connected platforms (but not for pending verification)
    let visibleButtonCount = 0;
    
    for (const [platform, buttonId] of Object.entries(buttonMap)) {
        const button = document.getElementById(buttonId);
        if (button) {
            // Only fully hide if platform is connected and NOT pending
            if (connectedPlatforms.includes(platform) && !pendingPlatforms.includes(platform)) {
                button.style.display = 'none';
            } else {
                button.style.display = 'inline-block';
                visibleButtonCount++;
            }
        }
    }
    
    // Show/hide the instructions section based on whether any buttons are visible
    const connectInstructions = document.querySelector('.connect-instructions');
    if (connectInstructions) {
        if (visibleButtonCount > 0) {
            connectInstructions.style.display = 'block';
        } else {
            connectInstructions.style.display = 'none';
        }
    }
}

/**
 * Helper function to update wallet UI
 */
function updateWalletUI(wallets) {
    if (!wallets) return;
    
    
    // Store wallet addresses globally
    if (wallets.BTC) externalWallets.BTC = wallets.BTC;
    if (wallets.ETH) externalWallets.ETH = wallets.ETH;
    if (wallets.SOL) externalWallets.SOL = wallets.SOL;
    if (wallets.BNB) externalWallets.BNB = wallets.BNB;
    if (wallets.QEVM) externalWallets.QEVM = wallets.QEVM;
    
    // Update ETH wallet UI
    if (wallets.ETH) {
        const ethWalletStatus = document.getElementById('ethWalletStatus');
        const ethWalletAddress = document.getElementById('ethWalletAddress');
        const connectEthWallet = document.getElementById('connectEthWallet');
        
        if (ethWalletAddress) ethWalletAddress.textContent = wallets.ETH;
        if (ethWalletStatus) ethWalletStatus.style.display = 'block';
        if (connectEthWallet) connectEthWallet.innerHTML = 'Connected to MetaMask';
    }
    
    // Update BTC wallet UI
    if (wallets.BTC) {
        const btcWalletStatus = document.getElementById('btcWalletStatus');
        const btcWalletAddress = document.getElementById('btcWalletAddress');
        const connectBtcWallet = document.getElementById('connectBtcWallet');
        
        if (btcWalletAddress) btcWalletAddress.textContent = wallets.BTC;
        if (btcWalletStatus) btcWalletStatus.style.display = 'block';
        if (connectBtcWallet) connectBtcWallet.innerHTML = 'Connected to Bitcoin Wallet';
    }
    
    // Update SOL wallet UI
    if (wallets.SOL) {
        const solWalletStatus = document.getElementById('solWalletStatus');
        const solWalletAddress = document.getElementById('solWalletAddress');
        const connectSolWallet = document.getElementById('connectSolWallet');
        
        if (solWalletAddress) solWalletAddress.textContent = wallets.SOL;
        if (solWalletStatus) solWalletStatus.style.display = 'block';
        if (connectSolWallet) connectSolWallet.innerHTML = 'Connected to Solana Wallet';
    }
    
    // Update BNB wallet UI
    if (wallets.BNB) {
        const bnbWalletStatus = document.getElementById('bnbWalletStatus');
        const bnbWalletAddress = document.getElementById('bnbWalletAddress');
        const connectBnbWallet = document.getElementById('connectBnbWallet');
        
        if (bnbWalletAddress) bnbWalletAddress.textContent = wallets.BNB;
        if (bnbWalletStatus) bnbWalletStatus.style.display = 'block';
        if (connectBnbWallet) connectBnbWallet.innerHTML = 'Connected to BNB Wallet';
    }
    
    // Update wallet count in UI
    const walletsCount = document.getElementById('walletsCount');
    if (walletsCount) {
        const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
        walletsCount.textContent = count;
    }
}

/**
 * Helper function to update a single social profile
 */
function updateSocialProfile(platform, value, elements) {
    // Skip if no value or empty string
    if (!value || value === '') return;
    
    
    const inputElement = document.getElementById(elements.inputId);
    const statusElement = document.getElementById(elements.statusId);
    const buttonElement = document.getElementById(elements.buttonId);
    
    // Update input field
    if (inputElement) {
        inputElement.value = value;
        inputElement.readOnly = true;
    }
    
    // Update verification status
    if (statusElement) {
        // Check if a specific status is provided
        const status = elements.status || 'verified';
        
        if (status === 'pending') {
            statusElement.innerHTML = `
                <div class="status-circle status-pending"></div>
                <span class="status-text">Pending</span>
            `;
        } else {
            statusElement.innerHTML = `
                <div class="status-circle status-verified"></div>
                <span class="status-text">Verified</span>
            `;
        }
    }
    
    // Update button
    if (buttonElement) {
        if (elements.buttonStyle) {
            // Apply custom style if provided
            if (elements.buttonStyle.disabled !== undefined) buttonElement.disabled = elements.buttonStyle.disabled;
            if (elements.buttonStyle.text) buttonElement.textContent = elements.buttonStyle.text;
            if (elements.buttonStyle.backgroundColor) buttonElement.style.backgroundColor = elements.buttonStyle.backgroundColor;
        } else {
            // Default: hide the button
            buttonElement.style.display = 'none';
        }
    }
}

/**
 * Update count of verified social accounts
 */
function updateSocialCount() {
    const socialsCountElement = document.getElementById('socialsCount');
    if (!socialsCountElement) return;
    
    let verifiedCount = 0;
    
    // Check if Twitter/X is verified
    const twitterStatus = document.querySelector('#twitterVerificationStatus .status-circle');
    if (twitterStatus && twitterStatus.classList.contains('status-verified')) {
        verifiedCount++;
    }
    
    // Check if Telegram is verified
    const telegramStatus = document.querySelector('#telegramVerificationStatus .status-circle');
    if (telegramStatus && telegramStatus.classList.contains('status-verified')) {
        verifiedCount++;
    }
    
    // Check if Google is verified
    const googleStatus = document.querySelector('#googleVerificationStatus .status-circle');
    if (googleStatus && googleStatus.classList.contains('status-verified')) {
        verifiedCount++;
    }
    
    // Check if LinkedIn is verified
    const linkedinStatus = document.querySelector('#linkedinVerificationStatus .status-circle');
    if (linkedinStatus && linkedinStatus.classList.contains('status-verified')) {
        verifiedCount++;
    }
    
    // Check if GitHub is verified
    const githubStatus = document.querySelector('#githubVerificationStatus .status-circle');
    if (githubStatus && githubStatus.classList.contains('status-verified')) {
        verifiedCount++;
    }
    
    // Update the count
    socialsCountElement.textContent = verifiedCount;
}

/**
 * Set up wallet connection buttons
 */
function setupWalletButtons() {
    // Ethereum wallet
    const connectEthWalletButton = document.getElementById('connectEthWallet');
    if (connectEthWalletButton) {
        connectEthWalletButton.addEventListener('click', connectEthWallet);
    }
    
    // Bitcoin wallet
    const connectBtcWalletButton = document.getElementById('connectBtcWallet');
    if (connectBtcWalletButton) {
        connectBtcWalletButton.addEventListener('click', connectBtcWallet);
    }
    
    // Solana wallet
    const connectSolWalletButton = document.getElementById('connectSolWallet');
    if (connectSolWalletButton) {
        connectSolWalletButton.addEventListener('click', connectSolWallet);
    }
    
    // BNB wallet
    const connectBnbWalletButton = document.getElementById('connectBnbWallet');
    if (connectBnbWalletButton) {
        connectBnbWalletButton.addEventListener('click', connectBnbWallet);
    }
}

/**
 * Set up social connection buttons
 */
function setupSocialButtons() {
    // Twitter/X Connect
    const connectTwitterButton = document.getElementById('connectTwitterButton');
    if (connectTwitterButton) {
        connectTwitterButton.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('twitter_oauth.php', 'twitterAuth', walletAddress);
        });
    }
    
    // Google Connect
    const connectGoogleButton = document.getElementById('connectGoogleButton');
    if (connectGoogleButton) {
        connectGoogleButton.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('google_oauth.php', 'googleAuth', walletAddress);
        });
    }
    
    // LinkedIn Connect
    const connectLinkedInButton = document.getElementById('connectLinkedInButton');
    if (connectLinkedInButton) {
        connectLinkedInButton.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('linkedin_oauth.php', 'linkedinAuth', walletAddress);
        });
    }
    
    // GitHub Connect
    const connectGitHubButton = document.getElementById('connectGitHubButton');
    if (connectGitHubButton) {
        connectGitHubButton.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('github_oauth.php', 'githubAuth', walletAddress);
        });
    }
    
    // Telegram Verify
    const verifyTelegramButton = document.getElementById('verifyTelegramButton');
    if (verifyTelegramButton) {
        verifyTelegramButton.addEventListener('click', function() {
            openTelegramVerification();
        });
    }
    
    // Close Telegram modal
    const closeModalButton = document.getElementById('closeModalButton');
    if (closeModalButton) {
        closeModalButton.addEventListener('click', function() {
            const modal = document.getElementById('telegramVerificationModal');
            if (modal) modal.style.display = 'none';
        });
    }
    
    // Copy Telegram verification code
    const copyGuidButton = document.getElementById('copyGuidButton');
    if (copyGuidButton) {
        copyGuidButton.addEventListener('click', function() {
            const guidDisplay = document.getElementById('guidDisplay');
            if (guidDisplay && guidDisplay.textContent) {
                navigator.clipboard.writeText(guidDisplay.textContent)
                    .then(() => {
                        copyGuidButton.textContent = 'Copied!';
                        setTimeout(() => {
                            copyGuidButton.textContent = 'Copy DNA Nickname';
                        }, 2000);
                    })
                    .catch(err => {
                        console.error('Failed to copy text: ', err);
                    });
            }
        });
    }
    
    // Set up message event listener for OAuth callbacks
    window.addEventListener('message', handleOAuthCallback);
}

/**
 * Set up duplicate social buttons
 */
function setupDuplicateSocialButtons() {
    // Twitter/X Connect
    const connectTwitterButton2 = document.getElementById('connectTwitterButton2');
    if (connectTwitterButton2) {
        connectTwitterButton2.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('twitter_oauth.php', 'twitterAuth', walletAddress);
        });
    }
    
    // Google Connect
    const connectGoogleButton2 = document.getElementById('connectGoogleButton2');
    if (connectGoogleButton2) {
        connectGoogleButton2.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('google_oauth.php', 'googleAuth', walletAddress);
        });
    }
    
    // LinkedIn Connect
    const connectLinkedInButton2 = document.getElementById('connectLinkedInButton2');
    if (connectLinkedInButton2) {
        connectLinkedInButton2.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('linkedin_oauth.php', 'linkedinAuth', walletAddress);
        });
    }
    
    // GitHub Connect
    const connectGitHubButton2 = document.getElementById('connectGitHubButton2');
    if (connectGitHubButton2) {
        connectGitHubButton2.addEventListener('click', function() {
            if (!walletAddress) {
                showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
                return;
            }
            
            openOAuthPopup('github_oauth.php', 'githubAuth', walletAddress);
        });
    }
    
    // Telegram Verify
    const verifyTelegramButton2 = document.getElementById('verifyTelegramButton2');
    if (verifyTelegramButton2) {
        verifyTelegramButton2.addEventListener('click', function() {
            openTelegramVerification();
        });
    }
}

/**
 * Open OAuth popup for social login
 */
function openOAuthPopup(oauthUrl, windowName, walletAddress) {
    // Set up popup dimensions
    const width = 600;
    const height = 600;
    const left = window.screen.width / 2 - width / 2;
    const top = window.screen.height / 2 - height / 2;
    const features = `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no,location=no`;
    
    // Build URL with wallet parameter
    const authUrl = `${oauthUrl}?request=auth&wallet=${encodeURIComponent(walletAddress)}`;
    
    // Try to open popup
    const popup = window.open(authUrl, windowName, features);
    
    // Check if popup was blocked
    if (!popup || popup.closed || typeof popup.closed === 'undefined') {
        console.error('Popup window was blocked or failed to open');
        showError(`Please allow popups for this site to use ${windowName.replace('Auth', '')} authentication`);
    }
}

/**
 * Handle OAuth callback messages from popups
 */
function handleOAuthCallback(event) {
    // Verify the origin for security
    if (event.origin !== window.location.origin) {
        console.warn('Received message from unknown origin', event.origin);
        return;
    }
    
    
    // Process based on message type
    if (!event.data || !event.data.type) return;
    
    // Handle telegram username updates
    if (event.data.type === 'telegram_username') {
        const username = event.data.username;
        
        // Log whether the update was successful
        if (event.data.updated) {
            
            // Store the username in the hidden field
            const telegramProfile = document.getElementById('telegramProfile');
            if (telegramProfile) {
                telegramProfile.value = username;
            }
            
            // Update any existing Telegram entries in the UI
            
            document.querySelectorAll('.social-summary-item').forEach(item => {
                // Check if this is a Telegram item by looking at the first div's content
                const firstDiv = item.querySelector('div:first-child');
                const contentDiv = item.querySelector('div:nth-child(2)');
                
                if (firstDiv && contentDiv && item.textContent.includes('Telegram')) {
                    // Get the header element (first div in content div)
                    const headerDiv = contentDiv.querySelector('div:first-child');
                    
                    // Create or update the username element (second div in content div)
                    let usernameDiv = contentDiv.querySelector('div:nth-child(2)');
                    
                    // If username div doesn't exist, create it with proper style
                    if (!usernameDiv) {
                        usernameDiv = document.createElement('div');
                        usernameDiv.style.fontSize = '0.9em';
                        usernameDiv.style.opacity = '0.9';
                        contentDiv.appendChild(usernameDiv);
                    }
                    
                    // Update the username text
                    usernameDiv.textContent = username;
                }
            });
        }
        
        // Continue with the telegram verification process
        continueTelegramVerification(username);
        
        return;
    }
    
    // Handle successful authentication
    if (event.data.type.includes('_auth_success')) {
        const platform = event.data.type.split('_')[0];
        
        // Update UI based on platform
        switch (platform) {
            case 'twitter':
                handleTwitterSuccess(event.data);
                break;
            case 'google':
                handleGoogleSuccess(event.data);
                break;
            case 'linkedin':
                handleLinkedInSuccess(event.data);
                break;
            case 'github':
                handleGitHubSuccess(event.data);
                break;
        }
        
        // Update social count after verification
        setTimeout(updateSocialCount, 500);
        
        // Show success message
        const saveSuccess = document.getElementById('saveSuccess');
        if (saveSuccess) {
            saveSuccess.textContent = `${platform.charAt(0).toUpperCase() + platform.slice(1)} account connected successfully!`;
            saveSuccess.style.display = 'block';
            setTimeout(() => {
                saveSuccess.style.display = 'none';
            }, 3000);
        }
        
        // Refresh DNA data to get the updated profile with the new social connection
        setTimeout(() => {
            checkDnaRegistration();
        }, 2000);
    }
    
    // Handle authentication errors
    if (event.data.type.includes('_auth_error')) {
        const platform = event.data.type.split('_')[0];
        console.error(`${platform} authentication error:`, event.data.error);
        
        showError(`Error connecting ${platform}: ${event.data.error || 'Unknown error'}`);
    }
}

/**
 * Handle Twitter authentication success
 */
function handleTwitterSuccess(data) {
    const profileInput = document.getElementById('xProfile');
    const statusElement = document.getElementById('twitterVerificationStatus');
    const connectButton = document.getElementById('connectTwitterButton');
    
    if (profileInput && data.username) {
        profileInput.value = data.username;
        profileInput.readOnly = true;
    }
    
    if (statusElement) {
        statusElement.innerHTML = `
            <div class="status-circle status-verified"></div>
            <span class="status-text">Verified</span>
        `;
    }
    
    if (connectButton) {
        connectButton.style.display = 'none';
    }
}

/**
 * Handle Google authentication success
 */
function handleGoogleSuccess(data) {
    const profileInput = document.getElementById('googleProfile');
    const statusElement = document.getElementById('googleVerificationStatus');
    const connectButton = document.getElementById('connectGoogleButton');
    
    if (profileInput && data.email) {
        profileInput.value = data.email;
        profileInput.readOnly = true;
    }
    
    if (statusElement) {
        statusElement.innerHTML = `
            <div class="status-circle status-verified"></div>
            <span class="status-text">Verified</span>
        `;
    }
    
    if (connectButton) {
        connectButton.disabled = true;
        connectButton.textContent = 'Connected';
        connectButton.style.backgroundColor = '#00C851';
    }
}

/**
 * Handle LinkedIn authentication success
 */
function handleLinkedInSuccess(data) {
    const profileInput = document.getElementById('linkedinProfile');
    const statusElement = document.getElementById('linkedinVerificationStatus');
    const connectButton = document.getElementById('connectLinkedInButton');
    
    if (profileInput && data.profile) {
        profileInput.value = data.profile;
        profileInput.readOnly = true;
    }
    
    if (statusElement) {
        statusElement.innerHTML = `
            <div class="status-circle status-verified"></div>
            <span class="status-text">Verified</span>
        `;
    }
    
    if (connectButton) {
        connectButton.style.display = 'none';
    }
}

/**
 * Handle GitHub authentication success
 */
function handleGitHubSuccess(data) {
    const profileInput = document.getElementById('githubProfile');
    const statusElement = document.getElementById('githubVerificationStatus');
    const connectButton = document.getElementById('connectGitHubButton');
    
    if (profileInput && data.username) {
        profileInput.value = data.username;
        profileInput.readOnly = true;
    }
    
    if (statusElement) {
        statusElement.innerHTML = `
            <div class="status-circle status-verified"></div>
            <span class="status-text">Verified</span>
        `;
    }
    
    if (connectButton) {
        connectButton.style.display = 'none';
    }
    
    // GitHub verification complete
}

/**
 * Open Telegram verification modal
 */
function openTelegramVerification() {
    if (!walletAddress) {
        showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
        return;
    }
    
    // We have a valid wallet address, proceed
    
    // Create a popup for telegram username entry
    const width = 400;
    const height = 300;
    const left = window.screen.width / 2 - width / 2;
    const top = window.screen.height / 2 - height / 2;
    
    // Create a simple HTML content for the popup
    const popupContent = `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Enter Telegram Username</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #0d1117;
                    color: #e6edf3;
                    padding: 20px;
                    margin: 0;
                }
                h3 {
                    margin-top: 0;
                    color: #58a6ff;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    font-weight: bold;
                }
                input {
                    width: 100%;
                    padding: 8px;
                    background-color: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    color: #e6edf3;
                    box-sizing: border-box;
                }
                button {
                    background-color: #238636;
                    color: white;
                    border: none;
                    padding: 10px 15px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-weight: bold;
                }
                button:hover {
                    background-color: #2ea043;
                }
                .error {
                    color: #f85149;
                    margin-top: 10px;
                    display: none;
                }
                .log-container {
                    margin-top: 20px;
                    padding: 15px;
                    background-color: rgba(0,0,0,0.3);
                    border-radius: 6px;
                    border: 1px solid #30363d;
                    font-family: monospace;
                    font-size: 13px;
                    white-space: pre-wrap;
                    max-height: 300px;
                    overflow-y: auto;
                    display: block; /* Always visible */
                }
            </style>
        </head>
        <body>
            <h3>Enter Your Telegram Username</h3>
            <p>To verify your Telegram account, you'll need to interact with our verification bot. First, enter your Telegram username without the @ symbol.</p>
            
            <div class="form-group">
                <label for="telegramUsername">Username:</label>
                <input type="text" id="telegramUsername" placeholder="username">
            </div>
            
            <div class="error" id="usernameError">Please enter a valid Telegram username</div>
            
            <button id="submitButton">Continue to Verification</button>
            
            <div id="resultContainer" style="display: none; margin-top: 20px;"></div>
            
            <script>
                // Get wallet address from parent window
                function getWalletAddress() {
                    return window.parentWalletAddress || window.opener.parentWalletAddress;
                }
                
                document.getElementById('submitButton').addEventListener('click', async function() {
                    const username = document.getElementById('telegramUsername').value.trim();
                    if (!username) {
                        document.getElementById('usernameError').style.display = 'block';
                        return;
                    }
                    
                    // Update this button to show loading state
                    const submitButton = document.getElementById('submitButton');
                    submitButton.disabled = true;
                    submitButton.textContent = 'Updating...';
                    
                    try {
                        // Get wallet address from parent window
                        const walletAddress = getWalletAddress();
                        
                        if (!walletAddress) {
                            throw new Error('No wallet address available');
                        }
                        
                        // Create username with unverified suffix
                        const unverifiedUsername = username + '-unverified';
                        
                        // Create update data
                        const updateData = {
                            action: 'update',
                            wallet: walletAddress,
                            socials: {
                                telegram: { profile: unverifiedUsername }
                            }
                        };
                        
                        // Post to dna-proxy.php to update the DNA record
                        const response = await fetch('dna-proxy.php', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify(updateData)
                        });
                        
                        const responseText = await response.text();
                        
                        // Check if the response was successful
                        let isSuccess = false;
                        try {
                            const jsonResponse = JSON.parse(responseText);
                            if (jsonResponse.status_code === 0 || responseText.includes('"message":"OK"')) {
                                isSuccess = true;
                            } 
                        } catch (e) {
                            isSuccess = false;
                        }
                        
                        if (!isSuccess) {
                            throw new Error('Failed to update DNA record. Please try again.');
                        }
                        
                        // On success, just send message to parent window and close
                        window.opener.postMessage({
                            type: 'telegram_username',
                            username: username,
                            updated: true
                        }, window.location.origin);
                        
                        // Close the popup
                        window.close();
                    } catch (error) {
                        // Show error in popup
                        const errorElement = document.getElementById('usernameError');
                        errorElement.textContent = error.message;
                        errorElement.style.display = 'block';
                        
                        // Reset button
                        submitButton.disabled = false;
                        submitButton.textContent = 'Try Again';
                    }
                });
            </script>
        </body>
        </html>
    `;
    
    // Open the popup
    const popup = window.open('about:blank', 'telegramUsername', `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no,location=no`);
    
    // Check if popup was blocked
    if (!popup || popup.closed || typeof popup.closed === 'undefined') {
        console.error('Popup window was blocked or failed to open');
        showError('Please allow popups for this site to use Telegram verification');
        return;
    }
    
    // Write content to the popup
    popup.document.write(popupContent);
    
    // After writing the content, pass the wallet address directly to the popup as a property
    popup.parentWalletAddress = walletAddress;
    
    // We no longer need a separate event handler as we've incorporated 
    // the telegram_username handling in the main handleOAuthCallback function.
    // The handleOAuthCallback function now takes care of processing 'telegram_username' messages.
}

function continueTelegramVerification(username) {
    if (!walletAddress) {
        showError('Wallet address is missing. Please connect to dashboard and select a wallet first.');
        return;
    }
    
    // Get the user's actual DNA nickname for verification
    let dnaNickname = '';
    
    // Try to find the user's DNA nickname from the loaded data
    if (dnaData) {
        // Check different possible data formats
        let registeredNames = {};
        
        if (dnaData.response_data && dnaData.response_data.registered_names) {
            registeredNames = dnaData.response_data.registered_names;
        } else if (dnaData.registered_names) {
            registeredNames = dnaData.registered_names;
        } else if (dnaData.data && dnaData.data.registered_names) {
            registeredNames = dnaData.data.registered_names;
        }
        
        // Get the first DNA nickname
        const nicknames = Object.keys(registeredNames);
        if (nicknames.length > 0) {
            dnaNickname = nicknames[0];
        }
    }
    
    // If we couldn't find a nickname, fall back to a generic message
    if (!dnaNickname) {
        dnaNickname = 'Your DNA Nickname';
    }
    
    // Create verification display directly in the socials tab
    const telegramProfile = document.getElementById('telegramProfile');
    const telegramVerificationStatus = document.getElementById('telegramVerificationStatus');
    const verifyTelegramButton = document.getElementById('verifyTelegramButton');
    const verifyTelegramButton2 = document.getElementById('verifyTelegramButton2');
    
    // Update the verification status
    if (telegramVerificationStatus) {
        telegramVerificationStatus.innerHTML = `
            <div class="status-circle status-pending"></div>
            <span class="status-text">Verification Pending</span>
        `;
    }
    
    // Only hide the original verify button, keep the duplicate one visible
    if (verifyTelegramButton) verifyTelegramButton.style.display = 'none';
    
    // Get the parent container of the social profile
    const socialsList = document.getElementById('socialsList');
    
    // Remove any existing verification instructions first
    const existingInstructions = document.querySelectorAll('.telegram-verification-instructions');
    existingInstructions.forEach(element => {
        element.remove();
    });
    
    // Create verification instructions
    const verificationDiv = document.createElement('div');
    verificationDiv.className = 'telegram-verification-instructions';
    verificationDiv.style.cssText = 'margin: 15px 0; padding: 15px; background-color: rgba(0, 0, 0, 0.2); border-radius: 6px; border: 1px solid var(--border-color);';
    
    verificationDiv.innerHTML = `
        <p style="font-size: 0.9em; margin-bottom: 10px;">To verify your Telegram account, you'll need to interact with our verification bot</p>
        <p style="font-size: 0.9em; margin-bottom: 10px;">Click the link to open our verification bot on Telegram</p>
        <p style="font-size: 0.9em; margin-bottom: 10px;">Send your DNA nickname to the bot when asked</p>
        
        <div style="margin-top: 20px; text-align: center;">
            <a href="https://t.me/CpunkVerifyBot" target="_blank" style="background-color: #0088cc; color: white; text-decoration: none; padding: 10px 20px; border-radius: 4px; display: inline-block; text-align: center; font-weight: bold; width: 100%; box-sizing: border-box; transition: background-color 0.2s;">
                Start Telegram Verification
            </a>
        </div>
    `;
    
    // Insert after the social profile entry for Telegram
    const telegramEntries = document.querySelectorAll('.social-summary-item');
    let telegramEntry = null;
    
    // Find the telegram entry
    for (const entry of telegramEntries) {
        if (entry.textContent.includes('Telegram')) {
            telegramEntry = entry;
            break;
        }
    }
    
    if (telegramEntry) {
        telegramEntry.insertAdjacentElement('afterend', verificationDiv);
    } else if (socialsList) {
        // If Telegram entry not found, append to the list
        socialsList.appendChild(verificationDiv);
    }
    
    // No copy button event listener needed anymore
    
    // Update hidden input if needed
    const guidValue = document.getElementById('guidValue');
    if (guidValue) guidValue.value = dnaNickname;
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

/**
 * Check for pending Telegram verification on page load and show instructions if needed
 */
function checkPendingTelegramVerification() {
    // Make sure we have DNA data
    if (!dnaData) return;
    
    // Check if user has Telegram with -unverified suffix
    let hasPendingTelegram = false;
    let telegramUsername = '';
    
    // Check different data formats
    if (dnaData.socials && dnaData.socials.telegram && dnaData.socials.telegram.profile) {
        const profile = dnaData.socials.telegram.profile;
        if (profile.endsWith('-unverified')) {
            hasPendingTelegram = true;
            telegramUsername = profile.replace('-unverified', '');
        }
    } else if (dnaData.response_data && dnaData.response_data.socials && 
               dnaData.response_data.socials.telegram && dnaData.response_data.socials.telegram.profile) {
        const profile = dnaData.response_data.socials.telegram.profile;
        if (profile.endsWith('-unverified')) {
            hasPendingTelegram = true;
            telegramUsername = profile.replace('-unverified', '');
        }
    } else if (dnaData.social_accounts && dnaData.social_accounts.telegram) {
        const profile = dnaData.social_accounts.telegram;
        if (profile.endsWith('-unverified')) {
            hasPendingTelegram = true;
            telegramUsername = profile.replace('-unverified', '');
        }
    }
    
    // If there's a pending Telegram verification, show instructions
    if (hasPendingTelegram) {
        continueTelegramVerification(telegramUsername);
    }
}

/**
 * Connect Ethereum wallet via MetaMask
 */
async function connectEthWallet() {
    const ethWalletStatus = document.getElementById('ethWalletStatus');
    const ethWalletAddress = document.getElementById('ethWalletAddress');
    const connectEthButton = document.getElementById('connectEthWallet');
    
    try {
        // Check if MetaMask is installed
        if (typeof window.ethereum === 'undefined') {
            throw new Error('MetaMask is not installed. Please install MetaMask to connect your Ethereum wallet.');
        }
        
        // Update button state
        if (connectEthButton) {
            connectEthButton.disabled = true;
            connectEthButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // Request account access
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        
        if (accounts.length > 0) {
            const address = accounts[0];
            
            // Update UI
            if (ethWalletAddress) ethWalletAddress.textContent = address;
            if (ethWalletStatus) ethWalletStatus.style.display = 'block';
            if (connectEthButton) connectEthButton.innerHTML = 'Connected to MetaMask';
            
            // Store for API submission later
            externalWallets.ETH = address;
            
            showSuccess('Ethereum wallet connected successfully!');
            
            // Update wallet counts in UI
            const walletsCount = document.getElementById('walletsCount');
            if (walletsCount) {
                const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
                walletsCount.textContent = count;
            }
            
            // Auto-save profile data when wallet is connected
            saveProfileDataSilently();
        }
    } catch (error) {
        showError('Error connecting to MetaMask: ' + error.message);
        console.error('Error connecting to MetaMask:', error);
        
        // Reset button
        if (connectEthButton) {
            connectEthButton.innerHTML = `
                <span style="display: flex; align-items: center; justify-content: center; gap: 5px;">
                    <svg width="16" height="16" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M13.9851 0L13.8093 0.596454V19.1476L13.9851 19.3233L22.5543 14.2173L13.9851 0Z" fill="white"/>
                        <path d="M13.9851 0L5.41602 14.2173L13.9851 19.3233V10.3505V0Z" fill="white" fill-opacity="0.8"/>
                        <path d="M13.9852 20.9506L13.8848 21.0725V27.6323L13.9852 27.9241L22.5602 15.8469L13.9852 20.9506Z" fill="white"/>
                        <path d="M13.9851 27.9241V20.9506L5.41602 15.8469L13.9851 27.9241Z" fill="white" fill-opacity="0.8"/>
                        <path d="M13.9851 19.3232L22.5542 14.2172L13.9851 10.3503V19.3232Z" fill="white" fill-opacity="0.9"/>
                        <path d="M5.41602 14.2172L13.9851 19.3232V10.3503L5.41602 14.2172Z" fill="white" fill-opacity="0.7"/>
                    </svg>
                    MetaMask
                </span>
            `;
        }
    } finally {
        if (connectEthButton) connectEthButton.disabled = false;
    }
}

/**
 * Connect Bitcoin wallet using Trust Wallet
 */
async function connectBtcWallet() {
    const btcWalletStatus = document.getElementById('btcWalletStatus');
    const btcWalletAddress = document.getElementById('btcWalletAddress');
    const connectBtcButton = document.getElementById('connectBtcWallet');
    
    try {
        // Update button state
        if (connectBtcButton) {
            connectBtcButton.disabled = true;
            connectBtcButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // Check if Trust Wallet is installed
        if (typeof window.trustwallet === 'undefined') {
            throw new Error('Trust Wallet is not installed. Please install Trust Wallet to connect your Bitcoin wallet.');
        }
        
        // Get the Trust Wallet provider
        const provider = window.trustwallet;
        
        try {
            // Check if Trust Wallet has any Bitcoin capability
            // Standard approach following TrustWallet's documentation
            
            // First try standard TrustWallet Bitcoin API
            if (provider.bitcoin) {
                await provider.bitcoin.request({ method: 'requestAccounts' });
                
                // Get the address
                const address = await provider.bitcoin.request({ method: 'getAccounts' });
                
                if (address && address.length > 0) {
                    const btcAddress = address[0];
                    
                    // Update UI
                    if (btcWalletAddress) btcWalletAddress.textContent = btcAddress;
                    if (btcWalletStatus) btcWalletStatus.style.display = 'block';
                    if (connectBtcButton) connectBtcButton.innerHTML = 'Connected to Trust Wallet';
                    
                    // Store for API submission later
                    externalWallets.BTC = btcAddress;
                    
                    showSuccess('Bitcoin wallet connected successfully!');
                    
                    // Update wallet counts in UI
                    const walletsCount = document.getElementById('walletsCount');
                    if (walletsCount) {
                        const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
                        walletsCount.textContent = count;
                    }
                    
                    // Auto-save profile data when wallet is connected
                    saveProfileDataSilently();
                    return;
                }
            }
            
            // TODO: Proper Bitcoin integration with Trust Wallet to be implemented later
            if (provider.request) {
                try {
                    
                    // Show message that Bitcoin connection is not supported yet
                    showError('Bitcoin wallet connection with Trust Wallet is not yet supported.');
                    
                    // Update UI to show pending status
                    if (btcWalletStatus) btcWalletStatus.style.display = 'none';
                    if (connectBtcButton) connectBtcButton.innerHTML = 'Bitcoin Wallet';
                    
                    return;
                } catch (innerError) {
                }
            }
            
            // If we reach here, no method worked
            throw new Error('Bitcoin connection method not available in this Trust Wallet version');
        } catch (err) {
            console.error('Trust Wallet Bitcoin error:', err);
            if (err.code === 4001) {
                throw new Error('User rejected the connection request');
            } else {
                throw err;
            }
        }
    } catch (error) {
        showError('Error connecting Bitcoin wallet: ' + error.message);
        console.error('Error connecting Bitcoin wallet:', error);
        
        // Reset button
        if (connectBtcButton) {
            connectBtcButton.disabled = false;
            connectBtcButton.innerHTML = 'Bitcoin Wallet';
        }
    } finally {
        if (connectBtcButton) connectBtcButton.disabled = false;
    }
}

/**
 * Connect Solana wallet using Trust Wallet
 */
async function connectSolWallet() {
    const solWalletStatus = document.getElementById('solWalletStatus');
    const solWalletAddress = document.getElementById('solWalletAddress');
    const connectSolButton = document.getElementById('connectSolWallet');
    
    try {
        // Check if Trust Wallet is installed first
        if (typeof window.trustwallet === 'undefined') {
            // Fall back to Phantom wallet if Trust Wallet is not available
            if (typeof window.solana === 'undefined') {
                throw new Error('No Solana wallet detected. Please install Trust Wallet or Phantom to connect your Solana wallet.');
            } else {
                // Use Phantom wallet as before
                return connectSolWalletWithPhantom();
            }
        }
        
        // Update button state
        if (connectSolButton) {
            connectSolButton.disabled = true;
            connectSolButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // Connect to Trust Wallet Solana
        try {
            const provider = window.trustwallet;
            
            // Check if Trust Wallet has a solana namespace
            if (!provider.solana) {
                // Use more standard Web3 provider approach that works with most wallets including Trust Wallet
                // Trust Wallet may expose Solana functionality through a different API
                
                // First try standard Solana-compatible API
                if (provider.isTrust && provider.isSolana) {
                    await provider.connect();
                    const address = provider.publicKey.toString();
                    
                    // Update UI
                    if (solWalletAddress) solWalletAddress.textContent = address;
                    if (solWalletStatus) solWalletStatus.style.display = 'block';
                    if (connectSolButton) connectSolButton.innerHTML = 'Connected to Trust Wallet';
                    
                    // Store for API submission later
                    externalWallets.SOL = address;
                    
                    showSuccess('Solana wallet connected successfully!');
                    
                    // Update wallet counts in UI
                    const walletsCount = document.getElementById('walletsCount');
                    if (walletsCount) {
                        const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
                        walletsCount.textContent = count;
                    }
                    
                    // Auto-save profile data when wallet is connected
                    saveProfileDataSilently();
                    return;
                }
                
                // Fall back to standard Solana wallet adapter approach
                if (window.solana) {
                    return connectSolWalletWithPhantom();
                }
                
                throw new Error('Solana functionality not supported in Trust Wallet on this device');
            }
            
            // Standard Trust Wallet Solana API approach
            await provider.solana.request({ method: 'connect' });
            
            // Get the address 
            const resp = await provider.solana.request({ method: 'getAccount' });
            
            // Trust Wallet Solana API returns the public key in the account property
            const address = resp.publicKey.toString();
            
            // Update UI
            if (solWalletAddress) solWalletAddress.textContent = address;
            if (solWalletStatus) solWalletStatus.style.display = 'block';
            if (connectSolButton) connectSolButton.innerHTML = 'Connected to Trust Wallet';
            
            // Store for API submission later
            externalWallets.SOL = address;
            
            showSuccess('Solana wallet connected successfully!');
            
            // Update wallet counts in UI
            const walletsCount = document.getElementById('walletsCount');
            if (walletsCount) {
                const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
                walletsCount.textContent = count;
            }
        } catch (err) {
            console.error('Trust Wallet Solana error:', err);
            if (err.code === 4001) {
                throw new Error('User rejected the connection request');
            } else {
                // Try Phantom as fallback
                if (window.solana) {
                    return connectSolWalletWithPhantom();
                }
                throw err;
            }
        }
    } catch (error) {
        showError('Error connecting to Solana wallet: ' + error.message);
        console.error('Error connecting to Solana wallet:', error);
        
        // Reset button
        if (connectSolButton) {
            connectSolButton.innerHTML = 'Solana Wallet';
        }
    } finally {
        if (connectSolButton) connectSolButton.disabled = false;
    }
}

/**
 * Connect BNB wallet using Trust Wallet
 */
async function connectBnbWallet() {
    const bnbWalletStatus = document.getElementById('bnbWalletStatus');
    const bnbWalletAddress = document.getElementById('bnbWalletAddress');
    const connectBnbButton = document.getElementById('connectBnbWallet');
    
    try {
        // Update button state
        if (connectBnbButton) {
            connectBnbButton.disabled = true;
            connectBnbButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // Check if Trust Wallet is installed
        if (typeof window.trustwallet === 'undefined') {
            throw new Error('Trust Wallet is not installed. Please install Trust Wallet to connect your BNB wallet.');
        }
        
        // Get the Trust Wallet provider
        const provider = window.trustwallet;
        
        try {
            // Use standard eth_requestAccounts to get the BNB address
            const accounts = await provider.request({ method: 'eth_requestAccounts', params: [{ chainId: '0x38' }] });
            
            if (accounts && accounts.length > 0) {
                const bnbAddress = accounts[0];
                
                // Update UI
                if (bnbWalletAddress) bnbWalletAddress.textContent = bnbAddress;
                if (bnbWalletStatus) bnbWalletStatus.style.display = 'block';
                if (connectBnbButton) connectBnbButton.innerHTML = 'Connected to Trust Wallet';
                
                // Store for API submission later
                externalWallets.BNB = bnbAddress;
                
                showSuccess('BNB wallet connected successfully!');
                
                // Update wallet counts in UI
                const walletsCount = document.getElementById('walletsCount');
                if (walletsCount) {
                    const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
                    walletsCount.textContent = count;
                }
                
                // Auto-save profile data when wallet is connected
                try {
                    saveProfileData(true);
                } catch (saveError) {
                    console.error('Error auto-saving profile after BNB connection:', saveError);
                }
                return;
            } else {
                throw new Error('No BNB accounts found');
            }
        } catch (err) {
            console.error('Trust Wallet BNB error:', err);
            if (err.code === 4001) {
                throw new Error('User rejected the connection request');
            } else {
                throw err;
            }
        }
    } catch (error) {
        showError('Error connecting to BNB wallet: ' + error.message);
        console.error('Error connecting to BNB wallet:', error);
        
        // Reset button
        if (connectBnbButton) {
            connectBnbButton.innerHTML = 'BNB Wallet';
        }
    } finally {
        if (connectBnbButton) connectBnbButton.disabled = false;
    }
}

/**
 * Connect Solana wallet with Phantom (fallback method)
 */
async function connectSolWalletWithPhantom() {
    const solWalletStatus = document.getElementById('solWalletStatus');
    const solWalletAddress = document.getElementById('solWalletAddress');
    const connectSolButton = document.getElementById('connectSolWallet');
    
    try {
        // Update button state
        if (connectSolButton) {
            connectSolButton.disabled = true;
            connectSolButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // Connect to Phantom wallet
        try {
            const resp = await window.solana.connect();
            
            const address = resp.publicKey.toString();
            
            // Update UI
            if (solWalletAddress) solWalletAddress.textContent = address;
            if (solWalletStatus) solWalletStatus.style.display = 'block';
            if (connectSolButton) connectSolButton.innerHTML = 'Connected to Phantom';
            
            // Store for API submission later
            externalWallets.SOL = address;
            
            showSuccess('Solana wallet connected successfully!');
            
            // Update wallet counts in UI
            const walletsCount = document.getElementById('walletsCount');
            if (walletsCount) {
                const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
                walletsCount.textContent = count;
            }
        } catch (err) {
            if (err.code === 4001) {
                throw new Error('User rejected the connection request');
            } else {
                throw err;
            }
        }
    } catch (error) {
        showError('Error connecting to Phantom wallet: ' + error.message);
        console.error('Error connecting to Phantom wallet:', error);
        
        // Reset button
        if (connectSolButton) {
            connectSolButton.innerHTML = 'Solana Wallet';
        }
    } finally {
        if (connectSolButton) connectSolButton.disabled = false;
    }
}

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
            // Store wallet addresses
            externalWallets = {
                BTC: data.response_data.dinosaur_wallets.BTC || '',
                ETH: data.response_data.dinosaur_wallets.ETH || '',
                SOL: data.response_data.dinosaur_wallets.SOL || '',
                QEVM: data.response_data.dinosaur_wallets.QEVM || ''
            };
            
            // Update UI for connected wallets
            updateWalletUI(data.response_data.dinosaur_wallets);
        }
    } else if (data.registered_names) {
        registeredNames = data.registered_names;
        
        // Check for dinosaur_wallets directly in data
        if (data.dinosaur_wallets) {
            externalWallets = {
                BTC: data.dinosaur_wallets.BTC || '',
                ETH: data.dinosaur_wallets.ETH || '',
                SOL: data.dinosaur_wallets.SOL || '',
                QEVM: data.dinosaur_wallets.QEVM || ''
            };
            
            // Update UI for connected wallets
            updateWalletUI(data.dinosaur_wallets);
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