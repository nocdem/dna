/**
 * CPUNK Profile & User Settings JavaScript
 * Handles dashboard connection, DNA lookup, profile editing, and social verification
 */

// API Configuration
const API_URL = 'http://localhost:8045/';
const DNA_API_URL = 'dna-proxy.php';
const TWITTER_OAUTH_URL = 'twitter_oauth.php';

// State variables
let sessionId = null;
let selectedWallet = null;
let walletAddress = null;
let dnaData = null;

// Store external wallet addresses
let externalWallets = {
    BTC: '',
    ETH: '',
    SOL: ''
};

// DOM Elements
const statusIndicator = document.getElementById('statusIndicator');
const sessionDetails = document.getElementById('sessionDetails');
const connectButton = document.getElementById('connectButton');
const connectionError = document.getElementById('connectionError');
const walletSection = document.getElementById('walletSection');
const walletsList = document.getElementById('walletsList');
const continueButton = document.getElementById('continueButton');
const walletError = document.getElementById('walletError');
const dnaSection = document.getElementById('dnaSection');
const dnaStatus = document.getElementById('dnaStatus');
const dnaError = document.getElementById('dnaError');
const dnaDetails = document.getElementById('dnaDetails');
const editButton = document.getElementById('editButton');
const editSection = document.getElementById('editSection');
const profileDescription = document.getElementById('profileDescription');
const profileImageUrl = document.getElementById('profileImageUrl');
const telegramProfile = document.getElementById('telegramProfile');
const xProfile = document.getElementById('xProfile');
const instagramProfile = document.getElementById('instagramProfile');
const facebookProfile = document.getElementById('facebookProfile');
const saveButton = document.getElementById('saveButton');
const saveSuccess = document.getElementById('saveSuccess');
const saveError = document.getElementById('saveError');

// Profile preview elements
const profileAvatar = document.getElementById('profileAvatar');
const profileNickname = document.getElementById('profileNickname');
const profileNicknames = document.getElementById('profileNicknames');
const nicknamesCount = document.getElementById('nicknamesCount');
const socialsCount = document.getElementById('socialsCount');
const walletsCount = document.getElementById('walletsCount');

// Verification UI elements
const verifyTelegramButton = document.getElementById('verifyTelegramButton');
const telegramVerificationStatus = document.getElementById('telegramVerificationStatus');
const telegramVerificationModal = document.getElementById('telegramVerificationModal');
const closeModalButton = document.getElementById('closeModalButton');
const guidDisplay = document.getElementById('guidDisplay');
const guidValue = document.getElementById('guidValue');
const copyGuidButton = document.getElementById('copyGuidButton');

// Twitter elements
const connectTwitterButton = document.getElementById('connectTwitterButton');
const twitterVerificationStatus = document.getElementById('twitterVerificationStatus');

/**
 * Dashboard API Connection Functions
 */
async function makeRequest(method, params = {}) {
    // Use CpunkUtils dashboardRequest if available
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dashboardRequest) {
        return await CpunkUtils.dashboardRequest(method, params);
    }
    
    // Fallback to direct API request if CpunkUtils is not available
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
        
        return await response.json();
    } catch (error) {
        console.error('Dashboard request error:', error);
        throw error;
    }
}

// Update dashboard status display
function updateStatus(status, message = '') {
    // Use CpunkUI if available
    if (typeof CpunkUI !== 'undefined' && CpunkUI.updateConnectionStatus) {
        CpunkUI.updateConnectionStatus(status, message);
        
        // Still need to update session details
        if (status === 'connected' && sessionId && sessionDetails) {
            sessionDetails.style.display = 'block';
            sessionDetails.textContent = `Session ID: ${sessionId}`;
        } else if (sessionDetails) {
            sessionDetails.style.display = 'none';
        }
        return;
    }
    
    // Fallback if CpunkUI is not available
    if (statusIndicator) {
        statusIndicator.className = 'status-indicator status-' + status;
        statusIndicator.textContent = message || status;
        
        if (status === 'connected' && sessionId && sessionDetails) {
            sessionDetails.style.display = 'block';
            sessionDetails.textContent = `Session ID: ${sessionId}`;
        } else if (sessionDetails) {
            sessionDetails.style.display = 'none';
        }
    }
}

// Connect to dashboard handler
async function connectToDashboard() {
    try {
        if (!connectButton) return;
        
        connectButton.disabled = true;
        connectButton.textContent = 'Connecting...';
        
        if (connectionError) {
            connectionError.style.display = 'none';
        }
        
        // Update status
        updateStatus('connecting', 'Connecting...');
        
        // Make connection request
        const response = await makeRequest('Connect');
        
        if (response.status === 'ok' && response.data && response.data.id) {
            sessionId = response.data.id;
            
            // Set session ID for transaction manager if available
            if (typeof CpunkTransaction !== 'undefined' && CpunkTransaction.setSessionId) {
                CpunkTransaction.setSessionId(sessionId);
            }
            
            // Update status and UI
            updateStatus('connected', 'Connected');
            connectButton.textContent = 'Connected';
            
            // Show wallet selection section
            if (walletSection) {
                walletSection.style.display = 'block';
            }
            
            // Load wallets
            await loadWallets();
        } else {
            throw new Error(response.errorMsg || 'Failed to connect to dashboard');
        }
    } catch (error) {
        console.error('Connection error:', error);
        updateStatus('disconnected', 'Connection failed');
        
        if (connectButton) {
            connectButton.textContent = 'Connect to Dashboard';
        }
        
        // Show error message
        if (connectionError) {
            connectionError.textContent = `Error connecting to dashboard: ${error.message}`;
            connectionError.style.display = 'block';
        }
        
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Dashboard connection failed', 'error', {
                error: error.message,
                stack: error.stack
            });
        }
    } finally {
        if (connectButton) {
            connectButton.disabled = false;
        }
    }
}

// Get wallet data from dashboard
async function getWalletData(walletName) {
    try {
        const response = await makeRequest('GetDataWallet', { 
            id: sessionId,
            walletName: walletName
        });
        
        return response;
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug(`Error fetching data for wallet ${walletName}`, 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error(`Error fetching data for wallet ${walletName}:`, error);
        }
        return null;
    }
}

// Load wallets from dashboard
async function loadWallets() {
    if (!sessionId || !walletsList) return;
    
    try {
        walletsList.innerHTML = '<div class="loading">Loading wallets...</div>';
        
        const response = await makeRequest('GetWallets', { id: sessionId });
        
        if (response.status === 'ok' && response.data && Array.isArray(response.data)) {
            const wallets = response.data;
            
            if (wallets.length === 0) {
                walletsList.innerHTML = `
                    <div style="color: var(--error); text-align: center; padding: 20px;">
                        No wallets found in your dashboard.<br>
                        Please create a wallet first.
                    </div>
                `;
                return;
            }
            
            // Clear previous content
            walletsList.innerHTML = '';
            
            // Create wallet selection items
            const walletsWithData = await Promise.all(wallets.map(async (wallet) => {
                const walletData = await getWalletData(wallet.name);
                return {
                    ...wallet,
                    details: walletData?.data || null
                };
            }));
            
            // Generate wallet items for each wallet (not per network)
            const processedWallets = new Set();
            
            walletsWithData.forEach(wallet => {
                if (!wallet.details || wallet.details.length === 0) return;
                
                // Only process each wallet once by name
                if (processedWallets.has(wallet.name)) return;
                processedWallets.add(wallet.name);
                
                // Get public key hash from the first network (should be the same for all networks)
                const firstNetworkData = wallet.details[0];
                
                // Create wallet card either using CpunkUI or fallback
                if (typeof CpunkUI !== 'undefined' && CpunkUI.createWalletCard) {
                    // Prepare wallet data for CpunkUI
                    const walletData = {
                        name: wallet.name,
                        network: firstNetworkData.network || 'Unknown',
                        address: firstNetworkData.address,
                        tokens: wallet.details.map(network => ({
                            tokenName: network.token || 'Unknown',
                            balance: network.balance || 0
                        })),
                        pubkey_hash: firstNetworkData.pubkey_hash
                    };
                    
                    // Create wallet card using CpunkUI
                    const walletCard = CpunkUI.createWalletCard(walletData, (selectedWalletData) => {
                        // Deselect all wallets
                        document.querySelectorAll('.wallet-card').forEach(card => {
                            card.classList.remove('selected');
                        });
                        
                        // Store selected wallet info
                        selectedWallet = {
                            name: selectedWalletData.name,
                            address: selectedWalletData.address,
                            pubkey_hash: firstNetworkData.pubkey_hash
                        };
                        
                        // Enable continue button
                        if (continueButton) {
                            continueButton.disabled = false;
                        }
                    });
                    
                    walletsList.appendChild(walletCard);
                } else {
                    // Only show the public key hash once per wallet (fallback implementation)
                    const walletItem = document.createElement('div');
                    walletItem.className = 'wallet-card';
                    walletItem.dataset.name = wallet.name;
                    
                    // Collect all addresses for this wallet
                    const addresses = wallet.details.map(network => network.address);
                    
                    // Store first address for DNA lookup
                    walletItem.dataset.address = addresses[0];
                    
                    walletItem.innerHTML = `
                        <div class="wallet-name">${wallet.name}</div>
                    `;
                    
                    walletItem.addEventListener('click', () => {
                        // Deselect all wallets
                        document.querySelectorAll('.wallet-card').forEach(card => {
                            card.classList.remove('selected');
                        });
                        
                        // Select this wallet
                        walletItem.classList.add('selected');
                        
                        // Store selected wallet info
                        selectedWallet = {
                            name: wallet.name,
                            address: addresses[0],
                            pubkey_hash: firstNetworkData.pubkey_hash
                        };
                        
                        // Enable continue button
                        if (continueButton) {
                            continueButton.disabled = false;
                        }
                    });
                    
                    walletsList.appendChild(walletItem);
                }
            });
            
            if (walletsList.children.length === 0) {
                walletsList.innerHTML = `
                    <div style="color: var(--error); text-align: center; padding: 20px;">
                        No wallets found in your dashboard.<br>
                        Please create a wallet first.
                    </div>
                `;
            }
        } else {
            throw new Error('Failed to load wallets');
        }
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error loading wallets', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error loading wallets:', error);
        }
        
        if (walletsList) {
            walletsList.innerHTML = `
                <div style="color: var(--error); text-align: center; padding: 20px;">
                    Error loading wallets: ${error.message}
                </div>
            `;
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && walletError) {
            CpunkUI.showError(`Error loading wallets: ${error.message}`, 'walletError');
        } else if (walletError) {
            walletError.textContent = `Error loading wallets: ${error.message}`;
            walletError.style.display = 'block';
        }
    }
}

// Continue with selected wallet handler
async function continueWithWallet() {
    if (!selectedWallet) {
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && walletError) {
            CpunkUI.showError('Please select a wallet first', 'walletError');
        } else if (walletError) {
            walletError.textContent = 'Please select a wallet first';
            walletError.style.display = 'block';
        }
        return;
    }
    
    try {
        if (walletError) {
            walletError.style.display = 'none';
        }
        
        if (continueButton) {
            continueButton.disabled = true;
            continueButton.textContent = 'Loading...';
        }
        
        // Store the wallet address for lookup
        walletAddress = selectedWallet.address;
        
        // Hide wallet selection section after successful selection
        if (walletSection) {
            walletSection.style.display = 'none';
        }
        
        // Show DNA section
        if (dnaSection) {
            dnaSection.style.display = 'block';
        }
        
        // Check for DNA registration
        await checkDnaRegistration();
        
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error processing wallet selection', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error processing wallet selection:', error);
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && walletError) {
            CpunkUI.showError(`Error: ${error.message}`, 'walletError');
        } else if (walletError) {
            walletError.textContent = `Error: ${error.message}`;
            walletError.style.display = 'block';
        }
    } finally {
        if (continueButton) {
            continueButton.disabled = false;
            continueButton.textContent = 'Continue with Selected Wallet';
        }
    }
}

/**
 * DNA Registration Functions
 */

// Check DNA registration
async function checkDnaRegistration() {
    if (!walletAddress) return;
    
    try {
        if (dnaStatus) {
            dnaStatus.style.display = 'block';
            dnaStatus.className = 'loading';
            dnaStatus.textContent = 'Checking DNA registration';
        }
        
        if (dnaError) {
            dnaError.style.display = 'none';
        }
        
        if (dnaDetails) {
            dnaDetails.style.display = 'none';
        }
        
        // Use CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.checkDnaRegistration) {
            const result = await CpunkUtils.checkDnaRegistration(walletAddress);
            
            if (result.isRegistered) {
                // Save DNA data
                dnaData = result.response.response_data;
                
                // Update DNA status
                if (dnaStatus) {
                    dnaStatus.style.display = 'none';
                }
                
                if (dnaDetails) {
                    dnaDetails.style.display = 'block';
                }
                
                // Update profile preview
                updateProfilePreview(dnaData);
            } else {
                // No DNA registration found
                if (dnaStatus) {
                    dnaStatus.className = '';
                    dnaStatus.innerHTML = `
                        <div style="color: var(--error); text-align: center; padding: 20px;">
                            No DNA registration found for this wallet.<br>
                            <button onclick="window.location.href='/register.html'" style="width: auto; margin-top: 15px; display: inline-block; padding: 10px 20px;">
                                Register DNA Now
                            </button>
                        </div>
                    `;
                }
            }
            return;
        }
        
        // Fallback implementation if CpunkUtils is not available
        const requestUrl = `${DNA_API_URL}?lookup=${encodeURIComponent(walletAddress)}`;
        const response = await fetch(requestUrl);
        const text = await response.text();
        
        try {
            // Parse as JSON
            const data = JSON.parse(text);
            
            // Check if data was found
            if (data.status_code === 0 && data.response_data) {
                // Save DNA data
                dnaData = data.response_data;
                
                // Update DNA status
                if (dnaStatus) {
                    dnaStatus.style.display = 'none';
                }
                
                if (dnaDetails) {
                    dnaDetails.style.display = 'block';
                }
                
                // Update profile preview
                updateProfilePreview(dnaData);
            } else {
                // No DNA registration found
                if (dnaStatus) {
                    dnaStatus.className = '';
                    dnaStatus.innerHTML = `
                        <div style="color: var(--error); text-align: center; padding: 20px;">
                            No DNA registration found for this wallet.<br>
                            <button onclick="window.location.href='/register.html'" style="width: auto; margin-top: 15px; display: inline-block; padding: 10px 20px;">
                                Register DNA Now
                            </button>
                        </div>
                    `;
                }
            }
        } catch (e) {
            // If not valid JSON, likely an error
            if (dnaStatus) {
                dnaStatus.className = '';
                dnaStatus.innerHTML = `
                    <div style="color: var(--error); text-align: center; padding: 20px;">
                        Error checking DNA registration.<br>
                        ${text.includes('not found') ? 
                            'No DNA registration found for this wallet.' : 
                            'Could not verify DNA registration. Please try again.'}
                        <button onclick="window.location.href='/register.html'" style="width: auto; margin-top: 15px; display: inline-block; padding: 10px 20px;">
                            Register DNA Now
                        </button>
                    </div>
                `;
            }
        }
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error checking DNA registration', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error checking DNA registration:', error);
        }
        
        if (dnaStatus) {
            dnaStatus.style.display = 'none';
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && dnaError) {
            CpunkUI.showError(`Error checking DNA registration: ${error.message}`, 'dnaError');
        } else if (dnaError) {
            dnaError.textContent = `Error checking DNA registration: ${error.message}`;
            dnaError.style.display = 'block';
        }
    }
}

// Update profile preview from DNA data
function updateProfilePreview(data) {
    if (!data) return;
    
    const registeredNames = data.registered_names || {};
    const nicknames = Object.keys(registeredNames);
    const primaryNickname = nicknames.length > 0 ? nicknames[0] : '?';
    
    // Update avatar and nickname
    if (profileAvatar) {
        profileAvatar.textContent = primaryNickname.charAt(0).toUpperCase();
    }
    
    if (profileNickname) {
        profileNickname.textContent = primaryNickname;
    }
    
    // Update nickname tags
    if (profileNicknames) {
        profileNicknames.innerHTML = '';
        nicknames.forEach((name, index) => {
            const tag = document.createElement('span');
            tag.className = `nickname-tag${index === 0 ? ' primary' : ''}`;
            tag.textContent = name;
            profileNicknames.appendChild(tag);
        });
    }
    
    // Update stats
    if (nicknamesCount) {
        nicknamesCount.textContent = nicknames.length;
    }
    
    const socials = data.socials || {};
    const activeSocialsCount = Object.values(socials).filter(s => s && s.profile && s.profile.trim() !== '').length;
    
    if (socialsCount) {
        socialsCount.textContent = activeSocialsCount;
    }
    
    const dinoWallets = data.dinosaur_wallets || {};
    const activeWalletsCount = Object.values(dinoWallets).filter(w => w && w.trim() !== '').length;
    
    if (walletsCount) {
        walletsCount.textContent = activeWalletsCount;
    }
}

// Edit profile button handler
function editProfile() {
    if (!dnaData) return;
    
    // Show edit section
    if (editSection) {
        editSection.style.display = 'block';
    }
    
    // Populate form with existing data
    populateForm(dnaData);
}

/**
 * Profile Editing Functions
 */

// Populate form fields with DNA data
function populateForm(data) {
    if (!data) return;
    
    // Set profile description and image
    if (data.profile) {
        if (profileDescription) {
            profileDescription.value = data.profile.description || '';
        }
        
        if (profileImageUrl) {
            profileImageUrl.value = data.profile.image_url || '';
        }
    }
    
    // Set public key hash, GUID, and sign ID
    const pubkeyHashInput = document.getElementById('pubkeyHash');
    const guidValueInput = document.getElementById('guidValue');
    const signIdInput = document.getElementById('signId');
    
    if (data.public_hash && pubkeyHashInput) {
        pubkeyHashInput.value = data.public_hash;
    } else if (selectedWallet && selectedWallet.pubkey_hash && pubkeyHashInput) {
        pubkeyHashInput.value = selectedWallet.pubkey_hash;
    }
    
    if (data.guuid && guidValueInput) {
        guidValueInput.value = data.guuid;
    }
    
    if (data.sign_id && signIdInput) {
        signIdInput.value = data.sign_id;
    }
    
    // Set social media profiles
    if (data.socials) {
        // For Telegram, strip the -unverified suffix for display
        if (telegramProfile) {
            const telegramName = data.socials.telegram?.profile || '';
            telegramProfile.value = telegramName.replace('-unverified', '');
        }
        
        // For Twitter/X, check if it's verified
        if (data.socials.x && data.socials.x.profile && xProfile) {
            xProfile.value = data.socials.x.profile;
            
            // Check Twitter verified status
            updateTwitterVerificationStatus(data.socials.x);
        } else if (xProfile) {
            xProfile.value = '';
        }
        
        if (instagramProfile) {
            instagramProfile.value = data.socials.instagram?.profile || '';
        }
        
        if (facebookProfile) {
            facebookProfile.value = data.socials.facebook?.profile || '';
        }
        
        // Check for verified status
        checkTelegramVerificationStatus();
    }
    
    // Set external wallets if they exist in data
    if (data.dinosaur_wallets) {
        // Store wallet addresses
        externalWallets = {
            BTC: data.dinosaur_wallets.BTC || '',
            ETH: data.dinosaur_wallets.ETH || '',
            SOL: data.dinosaur_wallets.SOL || ''
        };
        
        // Update UI for connected wallets
        if (data.dinosaur_wallets.ETH) {
            const ethWalletStatus = document.getElementById('ethWalletStatus');
            const ethWalletAddress = document.getElementById('ethWalletAddress');
            const connectEthWallet = document.getElementById('connectEthWallet');
            
            if (ethWalletAddress) {
                ethWalletAddress.textContent = data.dinosaur_wallets.ETH;
            }
            
            if (ethWalletStatus) {
                ethWalletStatus.style.display = 'block';
            }
            
            if (connectEthWallet) {
                connectEthWallet.innerHTML = 'Connected to MetaMask';
            }
        }
        
        if (data.dinosaur_wallets.BTC) {
            const btcWalletStatus = document.getElementById('btcWalletStatus');
            const btcWalletAddress = document.getElementById('btcWalletAddress');
            const connectBtcWallet = document.getElementById('connectBtcWallet');
            
            if (btcWalletAddress) {
                btcWalletAddress.textContent = data.dinosaur_wallets.BTC;
            }
            
            if (btcWalletStatus) {
                btcWalletStatus.style.display = 'block';
            }
            
            if (connectBtcWallet) {
                connectBtcWallet.innerHTML = 'Connected to Bitcoin Wallet';
            }
        }
        
        if (data.dinosaur_wallets.SOL) {
            const solWalletStatus = document.getElementById('solWalletStatus');
            const solWalletAddress = document.getElementById('solWalletAddress');
            const connectSolWallet = document.getElementById('connectSolWallet');
            
            if (solWalletAddress) {
                solWalletAddress.textContent = data.dinosaur_wallets.SOL;
            }
            
            if (solWalletStatus) {
                solWalletStatus.style.display = 'block';
            }
            
            if (connectSolWallet) {
                connectSolWallet.innerHTML = 'Connected to Solana Wallet';
            }
        }
    }
}

// Save profile changes
async function saveProfileChanges() {
    if (!dnaData || !walletAddress) {
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError('DNA data or wallet address is missing', 'saveError');
        } else if (saveError) {
            saveError.textContent = 'DNA data or wallet address is missing';
            saveError.style.display = 'block';
        }
        return;
    }
    
    try {
        if (saveButton) {
            saveButton.disabled = true;
            saveButton.innerHTML = '<span class="loading-spinner"></span>Saving changes...';
        }
        
        if (saveSuccess) {
            saveSuccess.style.display = 'none';
        }
        
        if (saveError) {
            saveError.style.display = 'none';
        }
        
        // Get current telegram username
        let telegramName = telegramProfile?.value.trim() || '';
        
        // If we already have a telegram profile with -unverified suffix in the database,
        // preserve that suffix when updating
        if (dnaData.socials && 
            dnaData.socials.telegram && 
            dnaData.socials.telegram.profile && 
            dnaData.socials.telegram.profile.endsWith('-unverified') &&
            telegramName && !telegramName.endsWith('-unverified')) {
            telegramName = `${telegramName}-unverified`;
        }
        
        // Prepare data for update
        const updateData = {
            action: 'update',
            wallet: walletAddress,
            socials: {
                telegram: { profile: telegramName },
                // Don't update Twitter/X from the form - it's managed by OAuth
                facebook: { profile: facebookProfile?.value.trim() || '' },
                instagram: { profile: instagramProfile?.value.trim() || '' }
            },
            profile: {
                description: profileDescription?.value.trim() || '',
                image_url: profileImageUrl?.value.trim() || ''
            },
            dinosaur_wallets: externalWallets
        };
        
        // Preserve verified status for Twitter if it exists
        if (dnaData.socials && dnaData.socials.x && dnaData.socials.x.verified === true) {
            updateData.socials.x = {
                profile: dnaData.socials.x.profile,
                verified: true
            };
        }
        
        // Use CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dnaPost) {
            const result = await CpunkUtils.dnaPost(updateData);
            
            let isSuccess = false;
            
            if (typeof result === 'string') {
                // Check text response for success string
                isSuccess = result.includes('success') && !result.includes('false');
            } else {
                // Check for specific success criteria
                isSuccess = result.success || result.status === 'ok' || result.status_code === 0;
            }
            
            if (isSuccess) {
                // Success
                if (saveSuccess) {
                    saveSuccess.textContent = 'Profile updated successfully!';
                    saveSuccess.style.display = 'block';
                }
                
                // Refresh DNA data
                await checkDnaRegistration();
            } else {
                // Error
                throw new Error(result.message || result.error || 'Failed to update profile');
            }
            
            return;
        }
        
        // Fallback if CpunkUtils is not available
        const response = await fetch(DNA_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(updateData)
        });
        
        const responseText = await response.text();
        
        try {
            const data = JSON.parse(responseText);
            
            if (data.success || data.status === 'ok' || data.status_code === 0) {
                // Success
                if (saveSuccess) {
                    saveSuccess.textContent = 'Profile updated successfully!';
                    saveSuccess.style.display = 'block';
                }
                
                // Refresh DNA data
                await checkDnaRegistration();
            } else {
                // Error
                throw new Error(data.message || data.error || 'Failed to update profile');
            }
        } catch (e) {
            // Either parsing error or error in response
            if (responseText.includes('success') && !responseText.includes('false')) {
                // Likely a success
                if (saveSuccess) {
                    saveSuccess.textContent = 'Profile updated successfully!';
                    saveSuccess.style.display = 'block';
                }
                
                // Refresh DNA data
                await checkDnaRegistration();
            } else {
                // Error
                throw new Error('Failed to parse response: ' + e.message);
            }
        }
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error saving profile changes', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error saving profile changes:', error);
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError(`Error: ${error.message}`, 'saveError');
        } else if (saveError) {
            saveError.textContent = `Error: ${error.message}`;
            saveError.style.display = 'block';
        }
    } finally {
        if (saveButton) {
            saveButton.disabled = false;
            saveButton.textContent = 'Save Profile Changes';
        }
    }
}

/**
 * Twitter OAuth Integration
 */

// Handle Twitter OAuth
function connectTwitterAccount() {
    if (!walletAddress) {
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError('Wallet address is missing. Please select a wallet first.', 'saveError');
        } else if (saveError) {
            saveError.textContent = 'Wallet address is missing. Please select a wallet first.';
            saveError.style.display = 'block';
        }
        return;
    }
    
    // Disable the button during OAuth
    if (connectTwitterButton) {
        connectTwitterButton.disabled = true;
        connectTwitterButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';
    }
    
    try {
        // Open a popup window for Twitter OAuth
        const width = 600;
        const height = 600;
        const left = window.screen.width / 2 - width / 2;
        const top = window.screen.height / 2 - height / 2;
        
        // Add wallet address as parameter for the callback
        const authUrl = `${TWITTER_OAUTH_URL}?request=auth&wallet=${encodeURIComponent(walletAddress)}`;
        
        const popup = window.open(
            authUrl,
            'twitterAuth',
            `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no,location=no`
        );
        
        // Check if popup was blocked
        if (!popup || popup.closed || typeof popup.closed === 'undefined') {
            throw new Error('Popup was blocked. Please allow popups for this site.');
        }
        
        // Listen for messages from the popup
        window.addEventListener('message', handleTwitterAuthCallback);
        
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error initiating Twitter OAuth', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error initiating Twitter OAuth:', error);
        }
        
        if (connectTwitterButton) {
            connectTwitterButton.disabled = false;
            connectTwitterButton.innerHTML = 'Connect Twitter';
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError(`Error connecting to Twitter: ${error.message}`, 'saveError');
        } else if (saveError) {
            saveError.textContent = `Error connecting to Twitter: ${error.message}`;
            saveError.style.display = 'block';
        }
    }
}

// Handle OAuth callback message from popup window
async function handleTwitterAuthCallback(event) {
    // We need to verify the origin to ensure it's from our Twitter OAuth page
    // In a production environment, you would check this against your domain
    
    console.log('Received message:', event.data);
    
    if (event.data.type === 'twitter_auth_success') {
        // Success - Twitter account connected
        const username = event.data.username;
        
        // Update the UI
        if (xProfile) {
            xProfile.value = username;
        }
        
        // Update verification status
        if (twitterVerificationStatus) {
            twitterVerificationStatus.innerHTML = `
                <div class="status-circle status-verified"></div>
                <span class="status-text">Verified</span>
            `;
        }
        
        // Update button
        if (connectTwitterButton) {
            connectTwitterButton.disabled = false;
            connectTwitterButton.textContent = 'Connected';
            connectTwitterButton.style.backgroundColor = '#00C851';
        }
        
        // Show success message
        if (saveSuccess) {
            saveSuccess.textContent = `Twitter account @${username} connected successfully!`;
            saveSuccess.style.display = 'block';
        }
        
        if (saveError) {
            saveError.style.display = 'none';
        }
        
        // Refresh data to get latest changes
        await checkDnaRegistration();
        
    } else if (event.data.type === 'twitter_auth_error') {
        // Error occurred during Twitter auth
        console.error('Twitter auth error:', event.data.error);
        
        // Reset button
        if (connectTwitterButton) {
            connectTwitterButton.disabled = false;
            connectTwitterButton.innerHTML = 'Connect Twitter';
        }
        
        // Show error message
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError(`Error connecting Twitter: ${event.data.error}`, 'saveError');
        } else if (saveError) {
            saveError.textContent = `Error connecting Twitter: ${event.data.error}`;
            saveError.style.display = 'block';
        }
        
        if (saveSuccess) {
            saveSuccess.style.display = 'none';
        }
    }
    
    // Clean up event listener
    window.removeEventListener('message', handleTwitterAuthCallback);
}

// Update Twitter verification status UI
function updateTwitterVerificationStatus(twitterData) {
    if (!twitterVerificationStatus) return;
    
    if (twitterData && twitterData.verified) {
        twitterVerificationStatus.innerHTML = `
            <div class="status-circle status-verified"></div>
            <span class="status-text">Verified</span>
        `;
        
        // Update button
        if (connectTwitterButton) {
            connectTwitterButton.textContent = 'Connected';
            connectTwitterButton.style.backgroundColor = '#00C851';
        }
    } else if (twitterData && twitterData.profile) {
        twitterVerificationStatus.innerHTML = `
            <div class="status-circle status-unverified"></div>
            <span class="status-text">Unverified</span>
        `;
    } else {
        twitterVerificationStatus.innerHTML = `
            <div class="status-circle status-unverified"></div>
            <span class="status-text">Not connected</span>
        `;
    }
}

/**
 * Telegram Verification Functions
 */

// Function to check if Telegram username has -unverified suffix
function checkTelegramVerificationStatus() {
    if (!dnaData || !dnaData.socials || !dnaData.socials.telegram || !telegramVerificationStatus) return;
    
    const telegramProfile = dnaData.socials.telegram.profile || '';
    
    if (telegramProfile.endsWith('-unverified')) {
        // Show pending state
        telegramVerificationStatus.innerHTML = `
            <div class="status-circle status-pending"></div>
            <span class="status-text">Pending verification</span>
        `;
        
        // Update the input field to show the username without the -unverified suffix
        const telegramInput = document.getElementById('telegramProfile');
        if (telegramInput) {
            telegramInput.value = telegramProfile.replace('-unverified', '');
        }
    } else if (telegramProfile && dnaData.socials.telegram.verified) {
        // Show verified state
        telegramVerificationStatus.innerHTML = `
            <div class="status-circle status-verified"></div>
            <span class="status-text">Verified</span>
        `;
        
        if (verifyTelegramButton) {
            verifyTelegramButton.disabled = true;
            verifyTelegramButton.textContent = "Verified";
        }
    } else if (telegramProfile) {
        // Has username but not verified
        telegramVerificationStatus.innerHTML = `
            <div class="status-circle status-unverified"></div>
            <span class="status-text">Unverified</span>
        `;
        
        if (verifyTelegramButton) {
            verifyTelegramButton.disabled = false;
        }
    } else {
        // No username
        telegramVerificationStatus.innerHTML = `
            <div class="status-circle status-unverified"></div>
            <span class="status-text">Not set</span>
        `;
        
        if (verifyTelegramButton) {
            verifyTelegramButton.disabled = true;
        }
    }
}

// Function to update Telegram username with -unverified suffix
async function updateTelegramVerification() {
    if (!dnaData || !walletAddress) {
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError('DNA data or wallet address is missing', 'saveError');
        } else if (saveError) {
            saveError.textContent = 'DNA data or wallet address is missing';
            saveError.style.display = 'block';
        }
        return false;
    }
    
    // Get telegram username from input
    const telegramUsername = telegramProfile?.value.trim() || '';
    
    if (!telegramUsername) {
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError('Please enter a Telegram username first', 'saveError');
        } else if (saveError) {
            saveError.textContent = 'Please enter a Telegram username first';
            saveError.style.display = 'block';
        }
        return false;
    }
    
    try {
        // Show loading state on verify button
        if (verifyTelegramButton) {
            verifyTelegramButton.disabled = true;
            verifyTelegramButton.innerHTML = '<span class="loading-spinner"></span>Updating...';
        }
        
        if (saveError) {
            saveError.style.display = 'none';
        }
        
        // Create a modified username with -unverified suffix
        const unverifiedUsername = `${telegramUsername}-unverified`;
        
        // Prepare data for update - only update the telegram field
        const updateData = {
            action: 'update',
            wallet: walletAddress,
            socials: {
                telegram: { profile: unverifiedUsername }
            }
        };
        
        // Use CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dnaPost) {
            const result = await CpunkUtils.dnaPost(updateData);
            
            let isSuccess = false;
            
            if (typeof result === 'string') {
                // Check text response for success string
                isSuccess = result.includes('success') && !result.includes('false');
            } else {
                // Check for specific success criteria
                isSuccess = result.success || result.status === 'ok' || result.status_code === 0;
            }
            
            if (isSuccess) {
                // Success - update local state
                if (dnaData && dnaData.socials) {
                    dnaData.socials.telegram = { 
                        profile: unverifiedUsername,
                        verified: false 
                    };
                }
                
                // Update verification status UI
                if (telegramVerificationStatus) {
                    telegramVerificationStatus.innerHTML = `
                        <div class="status-circle status-pending"></div>
                        <span class="status-text">Pending verification</span>
                    `;
                }
                
                return true;
            } else {
                // Error
                throw new Error(result.message || result.error || 'Failed to update Telegram verification status');
            }
        }
        
        // Fallback if CpunkUtils is not available
        const response = await fetch(DNA_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(updateData)
        });
        
        const responseText = await response.text();
        
        try {
            const data = JSON.parse(responseText);
            
            if (data.success || data.status === 'ok' || data.status_code === 0) {
                // Success - update local state
                if (dnaData && dnaData.socials) {
                    dnaData.socials.telegram = { 
                        profile: unverifiedUsername,
                        verified: false 
                    };
                }
                
                // Update verification status UI
                if (telegramVerificationStatus) {
                    telegramVerificationStatus.innerHTML = `
                        <div class="status-circle status-pending"></div>
                        <span class="status-text">Pending verification</span>
                    `;
                }
                
                return true;
            } else {
                // Error
                throw new Error(data.message || data.error || 'Failed to update Telegram verification status');
            }
        } catch (e) {
            // Either parsing error or error in response
            if (responseText.includes('success') && !responseText.includes('false')) {
                // Likely a success
                if (dnaData && dnaData.socials) {
                    dnaData.socials.telegram = { 
                        profile: unverifiedUsername,
                        verified: false 
                    };
                }
                
                // Update verification status UI
                if (telegramVerificationStatus) {
                    telegramVerificationStatus.innerHTML = `
                        <div class="status-circle status-pending"></div>
                        <span class="status-text">Pending verification</span>
                    `;
                }
                
                return true;
            } else {
                // Error
                throw new Error('Failed to parse response: ' + e.message);
            }
        }
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error updating Telegram verification', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error updating Telegram verification:', error);
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError(`Error: ${error.message}`, 'saveError');
        } else if (saveError) {
            saveError.textContent = `Error: ${error.message}`;
            saveError.style.display = 'block';
        }
        
        return false;
    } finally {
        if (verifyTelegramButton) {
            verifyTelegramButton.disabled = false;
            verifyTelegramButton.textContent = 'Verify';
        }
    }
}

// Modified function to handle Telegram verification
async function openTelegramVerificationModal() {
    // Ensure we have a valid username in the form
    if (!telegramProfile || !telegramProfile.value.trim()) {
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError('Please enter a Telegram username first', 'saveError');
        } else if (saveError) {
            saveError.textContent = 'Please enter a Telegram username first';
            saveError.style.display = 'block';
        }
        return;
    }
    
    // Make sure we have DNA data with registered names
    if (!dnaData || !dnaData.registered_names) {
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError('DNA registration data not found. Please save your profile first', 'saveError');
        } else if (saveError) {
            saveError.textContent = 'DNA registration data not found. Please save your profile first';
            saveError.style.display = 'block';
        }
        return;
    }
    
    // Get the primary DNA nickname
    const registeredNames = dnaData.registered_names || {};
    const nicknames = Object.keys(registeredNames);
    
    if (nicknames.length === 0) {
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError('No DNA nicknames found. Please register a DNA nickname first', 'saveError');
        } else if (saveError) {
            saveError.textContent = 'No DNA nicknames found. Please register a DNA nickname first';
            saveError.style.display = 'block';
        }
        return;
    }
    
    const primaryNickname = nicknames[0];
    
    // First update the database with unverified status
    const updateSuccess = await updateTelegramVerification();
    
    if (!updateSuccess) {
        // If update failed, don't show the modal
        return;
    }
    
    // Set the DNA nickname in the modal
    if (guidDisplay) {
        guidDisplay.textContent = primaryNickname;
    }
    
    // Open the modal
    if (telegramVerificationModal) {
        telegramVerificationModal.classList.add('active');
    }
}

// Close modal function
function closeTelegramVerificationModal() {
    if (telegramVerificationModal) {
        telegramVerificationModal.classList.remove('active');
    }
}

// Copy DNA nickname function
function copyDnaNickname() {
    if (!guidDisplay || !guidDisplay.textContent) return;
    
    // Use CpunkUtils if available
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.copyToClipboard) {
        CpunkUtils.copyToClipboard(
            guidDisplay.textContent,
            // Success callback
            () => {
                if (copyGuidButton) {
                    copyGuidButton.textContent = "Copied!";
                    
                    setTimeout(() => {
                        copyGuidButton.textContent = "Copy DNA Nickname";
                    }, 2000);
                }
            }
        );
        return;
    }
    
    // Fallback if CpunkUtils is not available
    navigator.clipboard.writeText(guidDisplay.textContent).then(() => {
        if (copyGuidButton) {
            copyGuidButton.textContent = "Copied!";
            
            setTimeout(() => {
                copyGuidButton.textContent = "Copy DNA Nickname";
            }, 2000);
        }
    });
}

/**
 * External Wallet Connection Functions
 */

// Connect ETH wallet via MetaMask
async function connectEthWallet() {
    const ethWalletStatus = document.getElementById('ethWalletStatus');
    const ethWalletAddress = document.getElementById('ethWalletAddress');
    const connectEthWallet = document.getElementById('connectEthWallet');
    
    try {
        // Check if MetaMask is installed
        if (typeof window.ethereum === 'undefined') {
            throw new Error('MetaMask is not installed. Please install MetaMask to connect your Ethereum wallet.');
        }
        
        if (connectEthWallet) {
            connectEthWallet.disabled = true;
            connectEthWallet.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // Request account access
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        
        if (accounts.length > 0) {
            const address = accounts[0];
            
            // Show the connected wallet
            if (ethWalletAddress) {
                ethWalletAddress.textContent = address;
            }
            
            if (ethWalletStatus) {
                ethWalletStatus.style.display = 'block';
            }
            
            // Update button text
            if (connectEthWallet) {
                connectEthWallet.innerHTML = 'Connected to MetaMask';
            }
            
            // Store the address for later use
            externalWallets = {
                ...externalWallets,
                ETH: address
            };
        } else {
            throw new Error('No accounts found. Please make sure you have accounts in MetaMask.');
        }
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error connecting to MetaMask', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error connecting to MetaMask:', error);
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError(`Error connecting to MetaMask: ${error.message}`, 'saveError');
        } else if (saveError) {
            saveError.textContent = `Error connecting to MetaMask: ${error.message}`;
            saveError.style.display = 'block';
        }
        
        // Reset button
        if (connectEthWallet) {
            connectEthWallet.innerHTML = '<span style="display: flex; align-items: center; justify-content: center; gap: 10px;"><svg width="20" height="20" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13.9851 0L13.8093 0.596454V19.1476L13.9851 19.3233L22.5543 14.2173L13.9851 0Z" fill="white"/><path d="M13.9851 0L5.41602 14.2173L13.9851 19.3233V10.3505V0Z" fill="white" fill-opacity="0.8"/><path d="M13.9852 20.9506L13.8848 21.0725V27.6323L13.9852 27.9241L22.5602 15.8469L13.9852 20.9506Z" fill="white"/><path d="M13.9851 27.9241V20.9506L5.41602 15.8469L13.9851 27.9241Z" fill="white" fill-opacity="0.8"/><path d="M13.9851 19.3232L22.5542 14.2172L13.9851 10.3503V19.3232Z" fill="white" fill-opacity="0.9"/><path d="M5.41602 14.2172L13.9851 19.3232V10.3503L5.41602 14.2172Z" fill="white" fill-opacity="0.7"/></svg>Connect with MetaMask</span>';
        }
    } finally {
        if (connectEthWallet) {
            connectEthWallet.disabled = false;
        }
    }
}

// Connect Solana wallet
async function connectSolWallet() {
    const solWalletStatus = document.getElementById('solWalletStatus');
    const solWalletAddress = document.getElementById('solWalletAddress');
    const connectSolWallet = document.getElementById('connectSolWallet');
    
    try {
        // Check if Phantom or Solana wallet is installed
        if (typeof window.solana === 'undefined') {
            throw new Error('Solana wallet not detected. Please install Phantom or another Solana wallet.');
        }
        
        if (connectSolWallet) {
            connectSolWallet.disabled = true;
            connectSolWallet.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // Connect to wallet
        const resp = await window.solana.connect();
        
        if (resp.publicKey) {
            const address = resp.publicKey.toString();
            
            // Show the connected wallet
            if (solWalletAddress) {
                solWalletAddress.textContent = address;
            }
            
            if (solWalletStatus) {
                solWalletStatus.style.display = 'block';
            }
            
            // Update button text
            if (connectSolWallet) {
                connectSolWallet.innerHTML = 'Connected to Solana Wallet';
            }
            
            // Store the address for later use
            externalWallets = {
                ...externalWallets,
                SOL: address
            };
        } else {
            throw new Error('Failed to get public key from Solana wallet.');
        }
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error connecting to Solana wallet', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error connecting to Solana wallet:', error);
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError(`Error connecting to Solana wallet: ${error.message}`, 'saveError');
        } else if (saveError) {
            saveError.textContent = `Error connecting to Solana wallet: ${error.message}`;
            saveError.style.display = 'block';
        }
        
        // Reset button
        if (connectSolWallet) {
            connectSolWallet.innerHTML = '<span style="display: flex; align-items: center; justify-content: center; gap: 10px;"><svg width="20" height="20" viewBox="0 0 397 311" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M64.8161 237.809L207.944 310.994C218.505 316.364 231.216 310.994 231.216 299.538V246.135C231.216 239.224 226.861 233.854 219.937 230.704L77.5271 157.519C66.9661 152.149 54.2555 157.519 54.2555 168.975V222.377C54.2555 230.704 58.6102 236.074 64.8161 237.809Z" fill="white"/><path d="M64.8161 81.6498L207.944 154.834C218.505 160.204 231.216 154.834 231.216 143.378V89.9756C231.216 83.0646 226.861 77.6947 219.937 74.5446L77.5271 1.36023C66.9661 -4.00972 54.2555 1.36023 54.2555 12.8159V66.2185C54.2555 74.5446 58.6102 79.9145 64.8161 81.6498Z" fill="white"/><path d="M342.159 171.1L199.031 97.9151C188.47 92.5453 175.76 97.9151 175.76 109.371V162.774C175.76 169.685 180.114 175.055 187.038 178.205L329.448 251.39C340.009 256.76 352.72 251.39 352.72 239.934V186.531C352.72 178.205 348.365 172.835 342.159 171.1Z" fill="white"/></svg>Connect Solana Wallet</span>';
        }
    } finally {
        if (connectSolWallet) {
            connectSolWallet.disabled = false;
        }
    }
}

// Connect BTC wallet
async function connectBtcWallet() {
    const btcWalletStatus = document.getElementById('btcWalletStatus');
    const btcWalletAddress = document.getElementById('btcWalletAddress');
    const connectBtcWallet = document.getElementById('connectBtcWallet');
    
    try {
        if (connectBtcWallet) {
            connectBtcWallet.disabled = true;
            connectBtcWallet.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        }
        
        // For demo purposes, simulate connection with a mock address
        // In a real implementation, you would use a Bitcoin wallet connector library
        setTimeout(() => {
            const mockAddress = "bc1q" + Array(40).fill(0).map(() => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join('');
            
            // Show the connected wallet
            if (btcWalletAddress) {
                btcWalletAddress.textContent = mockAddress;
            }
            
            if (btcWalletStatus) {
                btcWalletStatus.style.display = 'block';
            }
            
            // Update button text
            if (connectBtcWallet) {
                connectBtcWallet.innerHTML = 'Connected to Bitcoin Wallet';
            }
            
            // Store the address for later use
            externalWallets = {
                ...externalWallets,
                BTC: mockAddress
            };
            
            if (connectBtcWallet) {
                connectBtcWallet.disabled = false;
            }
        }, 2000);
    } catch (error) {
        // Log with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('Error connecting to Bitcoin wallet', 'error', {
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('Error connecting to Bitcoin wallet:', error);
        }
        
        // Show error
        if (typeof CpunkUI !== 'undefined' && CpunkUI.showError && saveError) {
            CpunkUI.showError(`Error connecting to Bitcoin wallet: ${error.message}`, 'saveError');
        } else if (saveError) {
            saveError.textContent = `Error connecting to Bitcoin wallet: ${error.message}`;
            saveError.style.display = 'block';
        }
        
        // Reset button
        if (connectBtcWallet) {
            connectBtcWallet.innerHTML = '<span style="display: flex; align-items: center; justify-content: center; gap: 10px;"><svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M19.3 12.35C17.9834 17.0992 13.0666 19.7867 8.31732 18.47C3.56807 17.1534 0.880572 12.2367 2.19724 7.4875C3.5139 2.73825 8.43065 0.0507484 13.1799 1.36741C17.9291 2.68408 20.6166 7.60083 19.3 12.35Z" fill="white"/><path d="M14.2516 8.70001C14.4349 7.40001 13.4599 6.72501 12.1432 6.28751L12.5599 4.77501L11.6182 4.53751L11.2132 6.00001C10.9849 5.93751 10.7449 5.87501 10.5066 5.81251L10.9149 4.33751L9.97156 4.10001L9.55656 5.61251C9.36156 5.56251 9.17156 5.51251 8.98823 5.46251L8.98989 5.45834L7.69989 5.13334L7.44989 6.13334C7.44989 6.13334 8.15823 6.28751 8.14156 6.29584C8.53323 6.38751 8.60406 6.65001 8.59573 6.85834L8.11406 8.60001C8.14739 8.60834 8.19156 8.62084 8.24156 8.64167L8.14156 8.61667L7.46656 11.1167C7.41989 11.2333 7.30823 11.4083 7.03323 11.3417C7.04156 11.3542 6.34156 11.175 6.34156 11.175L5.87656 12.25L7.09989 12.5583C7.30823 12.6167 7.51156 12.675 7.71073 12.7333L7.29156 14.2667L8.23323 14.5042L8.64989 12.9917C8.88739 13.0583 9.11656 13.1208 9.34156 13.1792L8.92656 14.6875L9.86823 14.925L10.2874 13.3958C11.9791 13.725 13.2349 13.5917 13.8016 12.0625C14.2557 10.8333 13.8391 10.125 12.9932 9.67917C13.6099 9.54167 14.0849 9.12917 14.2516 8.70001ZM11.8432 11.425C11.5182 12.6542 9.39156 11.9625 8.66656 11.7833L9.23739 9.72917C9.96239 9.90834 12.1807 10.1458 11.8432 11.425ZM12.1682 8.68334C11.8724 9.80834 10.0857 9.21667 9.47156 9.06667L9.98573 7.19167C10.5999 7.34167 12.4766 7.51667 12.1682 8.68334Z" fill="#F7931A"/></svg>Connect Bitcoin Wallet</span>';
            connectBtcWallet.disabled = false;
        }
    }
}

/**
 * Initialize Event Listeners
 */
function initEventListeners() {
    // Dashboard connection
    if (connectButton) {
        connectButton.addEventListener('click', connectToDashboard);
    }
    
    if (continueButton) {
        continueButton.addEventListener('click', continueWithWallet);
    }
    
    // Profile editing
    if (editButton) {
        editButton.addEventListener('click', editProfile);
    }
    
    if (saveButton) {
        saveButton.addEventListener('click', saveProfileChanges);
    }
    
    // Twitter OAuth
    if (connectTwitterButton) {
        connectTwitterButton.addEventListener('click', connectTwitterAccount);
    }
    
    // Telegram verification
    if (verifyTelegramButton) {
        verifyTelegramButton.addEventListener('click', openTelegramVerificationModal);
    }
    
    if (closeModalButton) {
        closeModalButton.addEventListener('click', closeTelegramVerificationModal);
    }
    
    if (copyGuidButton) {
        copyGuidButton.addEventListener('click', copyDnaNickname);
    }
    
    // Close modal on outside click
    if (telegramVerificationModal) {
        telegramVerificationModal.addEventListener('click', (e) => {
            if (e.target === telegramVerificationModal) {
                closeTelegramVerificationModal();
            }
        });
    }
    
    // External wallet connections
    const connectEthWalletBtn = document.getElementById('connectEthWallet');
    if (connectEthWalletBtn) {
        connectEthWalletBtn.addEventListener('click', connectEthWallet);
    }
    
    const connectBtcWalletBtn = document.getElementById('connectBtcWallet');
    if (connectBtcWalletBtn) {
        connectBtcWalletBtn.addEventListener('click', connectBtcWallet);
    }
    
    const connectSolWalletBtn = document.getElementById('connectSolWallet');
    if (connectSolWalletBtn) {
        connectSolWalletBtn.addEventListener('click', connectSolWallet);
    }
    
    // Form field handlers
    if (telegramProfile) {
        telegramProfile.addEventListener('input', () => {
            // Enable/disable verify button based on input
            if (verifyTelegramButton) {
                verifyTelegramButton.disabled = !telegramProfile.value.trim();
            }
        });
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
});