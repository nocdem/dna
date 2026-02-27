// Parse nickname from URL
let pathParts = window.location.pathname.split('/');
// Remove empty strings that might appear when splitting
pathParts = pathParts.filter(part => part.length > 0);
const nickname = pathParts[pathParts.length - 1];

// URLs configuration
const baseUrl = window.location.protocol + '//' + window.location.host;
document.getElementById('homeLink').href = baseUrl;
document.getElementById('lookupLink').href = baseUrl + '/lookup.html';
document.getElementById('registerLink').href = baseUrl + '/register.html';

// API endpoint - using absolute URL to match lookup page
const apiUrl = 'dna-proxy.php';
const dashboardApiUrl = 'http://localhost:8045/';

// Toggle section visibility
function toggleSection(sectionId) {
    const sectionContent = document.getElementById(sectionId);
    const toggleButton = document.querySelector(`[data-toggle="${sectionId}"]`);
    
    if (sectionContent.classList.contains('collapsed')) {
        sectionContent.classList.remove('collapsed');
        toggleButton.textContent = '−'; // Minus sign
        toggleButton.setAttribute('title', 'Collapse section');
    } else {
        sectionContent.classList.add('collapsed');
        toggleButton.textContent = '+'; // Plus sign
        toggleButton.setAttribute('title', 'Expand section');
    }
}

// Copy to clipboard function
function copyToClipboard(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = buttonElement.textContent;
        buttonElement.textContent = 'Copied!';
        setTimeout(() => {
            buttonElement.textContent = originalText;
        }, 2000);
    }).catch(err => {
        console.error('Could not copy text: ', err);
    });
}

// Get social media icon
function getSocialIcon(platform) {
    const icons = {
        'telegram': '📱',
        'x': '🐦',
        'twitter': '🐦',
        'instagram': '📸',
        'facebook': '👥',
        'github': '💻',
        'reddit': '🔴',
        'discord': '🎮',
        'linkedin': '🔗',
        'youtube': '▶️',
        'tiktok': '📱'
    };
    
    return icons[platform.toLowerCase()] || '🌐';
}

// Get cryptocurrency icon
function getCryptoIcon(chain) {
    const icons = {
        'BTC': '₿',
        'ETH': 'Ξ',
        'SOL': '◎',
        'BNB': 'B',
        'DOT': '●',
        'ADA': 'A',
        'XRP': 'X',
        'DOGE': 'D',
        'SHIB': 'S',
        'AVAX': 'A',
        'MATIC': 'M',
        'TRX': 'T'
    };
    
    return icons[chain] || '🪙';
}

// Format social media URL
function formatSocialUrl(platform, handle) {
    if (!handle) return '#';
    
    const baseUrls = {
        'telegram': 'https://t.me/',
        'x': 'https://x.com/',
        'twitter': 'https://twitter.com/',
        'instagram': 'https://instagram.com/',
        'facebook': 'https://facebook.com/',
        'github': 'https://github.com/',
        'reddit': 'https://reddit.com/user/',
        'discord': '#', // Discord doesn't have profile URLs
        'linkedin': 'https://linkedin.com/in/',
        'youtube': 'https://youtube.com/@',
        'tiktok': 'https://tiktok.com/@'
    };
    
    // If handle already includes http, return as is
    if (handle.startsWith('http')) {
        return handle;
    }
    
    // Remove @ symbol if present
    const cleanHandle = handle.startsWith('@') ? handle.substring(1) : handle;
    
    // Return formatted URL
    return (baseUrls[platform.toLowerCase()] || '#') + cleanHandle;
}

// Load profile data
async function loadProfileData() {
    try {
        // Show loading indicator
        document.getElementById('loadingIndicator').style.display = 'block';
        document.getElementById('profileContent').style.display = 'none';
        document.getElementById('notFoundContent').style.display = 'none';
        
        
        // Make the API request matching what lookup.html uses
        const reqUrl = `${apiUrl}?lookup=${encodeURIComponent(nickname)}`;
        
        const response = await fetch(reqUrl);
        const text = await response.text();
        
        // Parse the response
        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            // If not valid JSON, check if it's a meaningful error message
            if (text.includes('not found') || text.trim() === '') {
                showNotFound();
                return;
            }
            throw new Error('Invalid response format');
        }

        // Check if data was found
        if ((data.error && data.error.includes('not found')) || 
            (typeof data === 'string' && data.includes('not found'))) {
            showNotFound();
            return;
        }

        // Process and display the data
        if (data.status_code === 0 && data.response_data) {
            // New format with structured data
            renderStructuredProfile(data.response_data);
        } else if (data.wallet) {
            // Legacy format with a single wallet address
            renderLegacyProfile(data);
        } else {
            showNotFound();
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        showError(error.message);
    } finally {
        // Hide loading indicator
        document.getElementById('loadingIndicator').style.display = 'none';
    }
}

// Show not found page
function showNotFound() {
    document.getElementById('loadingIndicator').style.display = 'none';
    document.getElementById('profileContent').style.display = 'none';
    document.getElementById('notFoundContent').style.display = 'block';
    document.title = 'CPUNK - DNA Not Found';
}

// Show error message
function showError(message) {
    const profileContent = document.getElementById('profileContent');
    profileContent.innerHTML = `
        <div class="error-container">
            <div class="error-icon">⚠️</div>
            <div class="error-title">Error Loading Profile</div>
            <div class="error-message">${message}</div>
        </div>
    `;
    profileContent.style.display = 'block';
    document.getElementById('loadingIndicator').style.display = 'none';
    document.getElementById('notFoundContent').style.display = 'none';
}

// Render profile with structured data format
function renderStructuredProfile(profileData) {
    // Get the profile container
    const profileContent = document.getElementById('profileContent');
    
    // Get details from the profile data
    const registeredNames = profileData.registered_names || {};
    const nicknames = Object.keys(registeredNames);
    const primaryNickname = nicknames && nicknames.length > 0 ? nicknames[0] : nickname;
    const walletAddresses = profileData.wallet_addresses || {};
    const publicKey = profileData.public_hash || profileData.public_key;
    const socials = profileData.socials || {};
    const externalWallets = profileData.dinosaur_wallets || {};
    const profileInfo = profileData.profile || {};
    
    // Update page title
    document.title = `CPUNK - ${primaryNickname}'s Profile`;

    // Create profile HTML
    let html = `
        <div class="profile-header">
            <div class="profile-avatar">${(primaryNickname.charAt(0) || '?').toUpperCase()}</div>
            <div class="profile-info">
                <div class="profile-nickname">${primaryNickname || 'Unknown'}</div>
    `;

    // Add verification badge if this is an official account
    if (primaryNickname === 'cpunk' || primaryNickname === 'cellframe') {
        html += `<span class="verification-badge">Official</span>`;
    }

    // Add all nicknames if available
    if (nicknames && nicknames.length > 0) {
        html += `<div class="profile-nicknames">`;
        nicknames.forEach((name, index) => {
            const isActive = name === nickname; // Highlight current nickname
            const expiresOn = registeredNames[name].expires_on;
            let expiryDate = '';
            if (expiresOn) {
                try {
                    const date = new Date(expiresOn);
                    expiryDate = date.toLocaleDateString();
                } catch (e) {
                    expiryDate = expiresOn;
                }
            }
            html += `<span class="nickname-tag${index === 0 ? ' primary' : isActive ? ' active' : ''}" 
                title="Expires: ${expiryDate}">${name}</span>`;
        });
        html += `</div>`;
    }

    // Add additional profile info
    html += `
                <div class="profile-id">DNA: ${primaryNickname}</div>
            </div>
        </div>
    `;

    // Add contact button
    html += `
        <button id="contactButton" class="contact-button" onclick="openContactModal('${primaryNickname}')">
            <span class="contact-button-icon">💬</span> Contact ${primaryNickname}
        </button>
    `;

    // Add profile description if available
    if (profileInfo && profileInfo.description) {
        html += `
            <div class="profile-description">
                ${profileInfo.description}
            </div>
        `;
    }

    // Stats section
    html += `
        <div class="section">
            <div class="section-title">
                <div class="section-title-text">Profile Stats</div>
            </div>
            <div class="stats-grid">
                <div class="profile-stat">
                    <div class="stat-value">${nicknames ? nicknames.length : 1}</div>
                    <div class="stat-label">DNA Nicknames</div>
                </div>
                <div class="profile-stat">
                    <div class="stat-value">${Object.keys(walletAddresses).length}</div>
                    <div class="stat-label">Networks</div>
                </div>
                <div class="profile-stat">
                    <div class="stat-value">${Object.keys(externalWallets).filter(key => externalWallets[key]).length}</div>
                    <div class="stat-label">External Wallets</div>
                </div>
            </div>
        </div>
    `;

    // Wallet addresses section with collapsible functionality
    if (Object.keys(walletAddresses).length > 0) {
        const walletSectionId = `wallet-addresses-${Date.now()}`;
        html += `
            <div class="section">
                <div class="section-title">
                    <div class="section-title-text">Cellframe Wallet Addresses</div>
                    <button class="toggle-button" data-toggle="${walletSectionId}" onclick="toggleSection('${walletSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${walletSectionId}" class="section-content collapsed">
        `;

        // Add each network and address
        Object.entries(walletAddresses).forEach(([network, address]) => {
            html += `
                <div class="network-card">
                    <div class="network-name">
                        ${network}
                        <button class="network-copy" onclick="copyToClipboard('${address}', this)">Copy Address</button>
                    </div>
                    <div class="address-display">${address}</div>
                </div>
            `;
        });

        html += `</div></div>`;
    }

    // External crypto wallets section
    if (Object.keys(externalWallets).some(key => externalWallets[key])) {
        const externalWalletSectionId = `external-wallets-${Date.now()}`;
        html += `
            <div class="section">
                <div class="section-title">
                    <div class="section-title-text">External Blockchain Wallets</div>
                    <button class="toggle-button" data-toggle="${externalWalletSectionId}" onclick="toggleSection('${externalWalletSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${externalWalletSectionId}" class="section-content collapsed">
                    <div class="external-wallets">
        `;

        // Add each external wallet
        Object.entries(externalWallets).forEach(([chain, address]) => {
            if (address) {
                html += `
                    <div class="external-wallet-card">
                        <div class="external-wallet-icon">${getCryptoIcon(chain)}</div>
                        <div class="external-wallet-name">${chain}</div>
                        <div class="external-wallet-address">${address}</div>
                        <button class="network-copy" onclick="copyToClipboard('${address}', this)" style="margin-top: 10px;">Copy Address</button>
                    </div>
                `;
            }
        });

        html += `</div></div></div>`;
    }

    // Public key section if available - also collapsible
    if (publicKey) {
        const pubkeySectionId = `pubkey-section-${Date.now()}`;
        html += `
            <div class="section">
                <div class="section-title">
                    <div class="section-title-text">Public Key</div>
                    <button class="toggle-button" data-toggle="${pubkeySectionId}" onclick="toggleSection('${pubkeySectionId}')" title="Expand section">+</button>
                </div>
                <div id="${pubkeySectionId}" class="section-content collapsed">
                    <div class="pubkey-display">
                        <div class="pubkey-title">Public Key</div>
                        <button class="pubkey-copy" onclick="copyToClipboard('${publicKey}', this)">Copy Key</button>
                        ${publicKey}
                    </div>
                </div>
            </div>
        `;
    }

    // Social Links section
    const socialSectionId = `social-section-${Date.now()}`;
    html += `
        <div class="section">
            <div class="section-title">
                <div class="section-title-text">Social Media</div>
                <button class="toggle-button" data-toggle="${socialSectionId}" onclick="toggleSection('${socialSectionId}')" title="Expand section">+</button>
            </div>
            <div id="${socialSectionId}" class="section-content collapsed">
    `;

    // Check if there are any social media accounts
    const hasSocials = socials && Object.values(socials).some(social => social && social.profile);
    
    if (hasSocials) {
        html += `<div class="social-links">`;
        
        // Add each social media link
        Object.entries(socials).forEach(([platform, data]) => {
            if (data && data.profile) {
                const handle = data.profile;
                const url = formatSocialUrl(platform, handle);
                const displayHandle = handle.startsWith('@') ? handle : '@' + handle;
                
                html += `
                    <a href="${url}" target="_blank" class="social-link">
                        <span class="social-icon">${getSocialIcon(platform)}</span>
                        <span class="social-platform">${platform.charAt(0).toUpperCase() + platform.slice(1)}:</span>
                        <span class="social-handle">${displayHandle}</span>
                    </a>
                `;
            }
        });
        
        html += `</div>`;
    } else {
        html += `
            <div class="no-data-message">
                No social media accounts linked to this profile.
            </div>
        `;
    }
    
    html += `</div></div>`;

    // Set the HTML content
    profileContent.innerHTML = html;
    profileContent.style.display = 'block';
}

// Render profile with legacy data format
function renderLegacyProfile(profileData) {
    // Process the legacy format
    const primaryNickname = nickname;
    const walletAddress = profileData.wallet;
    
    // Update page title
    document.title = `CPUNK - ${primaryNickname}'s Profile`;

    // Create profile HTML (simplified version)
    let html = `
        <div class="profile-header">
            <div class="profile-avatar">${(primaryNickname.charAt(0) || '?').toUpperCase()}</div>
            <div class="profile-info">
                <div class="profile-nickname">${primaryNickname || 'Unknown'}</div>
                <div class="profile-nicknames">
                    <span class="nickname-tag primary">${primaryNickname}</span>
                </div>
                <div class="profile-id">DNA: ${primaryNickname}</div>
            </div>
        </div>
    `;

    // Add contact button
    html += `
        <button id="contactButton" class="contact-button" onclick="openContactModal('${primaryNickname}')">
            <span class="contact-button-icon">💬</span> Contact ${primaryNickname}
        </button>
    `;

    // Wallet address section - collapsible
    if (walletAddress) {
        const walletSectionId = `wallet-addresses-legacy-${Date.now()}`;
        html += `
            <div class="section">
                <div class="section-title">
                    <div class="section-title-text">Wallet Address</div>
                    <button class="toggle-button" data-toggle="${walletSectionId}" onclick="toggleSection('${walletSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${walletSectionId}" class="section-content collapsed">
                    <div class="network-card">
                        <div class="network-name">
                            Backbone
                            <button class="network-copy" onclick="copyToClipboard('${walletAddress}', this)">Copy Address</button>
                        </div>
                        <div class="address-display">${walletAddress}</div>
                    </div>
                </div>
            </div>
        `;
    }

    // Add stats and social media section (placeholder for legacy profiles)
    html += `
        <div class="section">
            <div class="section-title">
                <div class="section-title-text">Profile Stats</div>
            </div>
            <div class="stats-grid">
                <div class="profile-stat">
                    <div class="stat-value">1</div>
                    <div class="stat-label">DNA Nicknames</div>
                </div>
                <div class="profile-stat">
                    <div class="stat-value">1</div>
                    <div class="stat-label">Networks</div>
                </div>
                <div class="profile-stat">
                    <div class="stat-value">0</div>
                    <div class="stat-label">External Wallets</div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">
                <div class="section-title-text">Social Media</div>
            </div>
            <div class="no-data-message">
                No social media accounts linked to this profile.
            </div>
        </div>
    `;

    // Set the HTML content
    const profileContent = document.getElementById('profileContent');
    profileContent.innerHTML = html;
    profileContent.style.display = 'block';
}

// Contact modal functions
let sessionId = null;
let selectedWallet = null;
let selectedDna = null;

function openContactModal(recipientName) {
    // Set recipient name in the modal
    document.getElementById('recipientName').textContent = recipientName;
    document.getElementById('messageRecipient').textContent = recipientName;
    
    // Show the modal
    document.getElementById('contactModal').classList.add('active');
    
    // Reset modal state
    resetModalState();
}

function closeContactModal() {
    document.getElementById('contactModal').classList.remove('active');
}

function resetModalState() {
    // Reset steps
    document.querySelectorAll('.step').forEach(step => {
        step.classList.remove('active', 'completed');
    });
    document.getElementById('step1').classList.add('active');
    
    // Reset sections
    document.getElementById('connectSection').style.display = 'block';
    document.getElementById('walletSection').style.display = 'none';
    document.getElementById('dnaSection').style.display = 'none';
    document.getElementById('messageSection').style.display = 'none';
    
    // Reset session and selected values
    sessionId = null;
    selectedWallet = null;
    selectedDna = null;
    
    // Reset UI elements
    document.getElementById('statusIndicator').className = 'status-indicator status-disconnected';
    document.getElementById('statusIndicator').textContent = 'Disconnected';
    document.getElementById('sessionDetails').style.display = 'none';
    document.getElementById('connectButton').disabled = false;
    document.getElementById('connectButton').textContent = 'Connect to Dashboard';
    document.getElementById('connectionError').style.display = 'none';
    
    document.getElementById('walletsList').innerHTML = '<div class="loading">Loading wallets...</div>';
    document.getElementById('continueWalletButton').disabled = true;
    document.getElementById('walletError').style.display = 'none';
    
    document.getElementById('dnaList').innerHTML = '<div class="loading">Loading DNA nicknames...</div>';
    document.getElementById('continueDnaButton').disabled = true;
    document.getElementById('dnaError').style.display = 'none';
    
    document.getElementById('messageText').value = '';
    document.getElementById('charCount').textContent = '0/500';
    document.getElementById('messageError').style.display = 'none';
    document.getElementById('messageSuccess').style.display = 'none';
}

// Dashboard connection functions
async function makeRequest(method, params = {}) {
    const url = new URL(dashboardApiUrl);
    url.searchParams.append('method', method);
    
    for (const [key, value] of Object.entries(params)) {
        url.searchParams.append(key, value);
    }
    
    try {
        const response = await fetch(url.toString());
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Dashboard request error:', error);
        throw error;
    }
}

async function connectToDashboard() {
    try {
        // Update UI
        const connectButton = document.getElementById('connectButton');
        const statusIndicator = document.getElementById('statusIndicator');
        const connectionError = document.getElementById('connectionError');
        
        connectButton.disabled = true;
        connectButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        connectionError.style.display = 'none';
        
        // Update status
        statusIndicator.className = 'status-indicator status-connecting';
        statusIndicator.textContent = 'Connecting...';
        
        // Make the connection request
        const response = await makeRequest('Connect');
        
        if (response.status === 'ok' && response.data && response.data.id) {
            sessionId = response.data.id;
            
            // Update status
            statusIndicator.className = 'status-indicator status-connected';
            statusIndicator.textContent = 'Connected';
            
            // Show session details
            const sessionDetails = document.getElementById('sessionDetails');
            sessionDetails.textContent = `Session ID: ${sessionId}`;
            sessionDetails.style.display = 'block';
            
            // Update button
            connectButton.textContent = 'Connected';
            
            // Mark step as completed and activate next step
            document.getElementById('step1').classList.remove('active');
            document.getElementById('step1').classList.add('completed');
            document.getElementById('step2').classList.add('active');
            
            // Show wallet section
            document.getElementById('connectSection').style.display = 'none';
            document.getElementById('walletSection').style.display = 'block';
            
            // Load wallets
            await loadWallets();
        } else {
            throw new Error(response.errorMsg || 'Failed to connect to dashboard');
        }
    } catch (error) {
        console.error('Connection error:', error);
        
        // Update UI to show error
        document.getElementById('statusIndicator').className = 'status-indicator status-disconnected';
        document.getElementById('statusIndicator').textContent = 'Connection Failed';
        
        const connectionError = document.getElementById('connectionError');
        connectionError.textContent = `Error: ${error.message}`;
        connectionError.style.display = 'block';
        
        // Reset button
        const connectButton = document.getElementById('connectButton');
        connectButton.disabled = false;
        connectButton.textContent = 'Try Again';
    }
}

async function loadWallets() {
    if (!sessionId) return;
    
    try {
        const walletsList = document.getElementById('walletsList');
        walletsList.innerHTML = '<div class="loading">Loading wallets...</div>';
        
        const response = await makeRequest('GetWallets', { id: sessionId });
        
        if (response.status === 'ok' && response.data && Array.isArray(response.data)) {
            const wallets = response.data;
            
            if (wallets.length === 0) {
                walletsList.innerHTML = `
                    <div style="text-align: center; padding: 15px;">
                        No wallets found. Please create a wallet in your Cellframe dashboard.
                    </div>
                `;
                return;
            }
            
            // Get wallet data for each wallet
            const walletsWithData = await Promise.all(wallets.map(async (wallet) => {
                try {
                    const walletData = await makeRequest('GetDataWallet', { 
                        id: sessionId,
                        walletName: wallet.name
                    });
                    
                    return {
                        ...wallet,
                        details: walletData?.data || []
                    };
                } catch (error) {
                    console.error(`Error fetching data for wallet ${wallet.name}:`, error);
                    return {
                        ...wallet,
                        details: []
                    };
                }
            }));
            
            // Clear loading and create wallet list
            walletsList.innerHTML = '';
            
            // Create wallet cards
            walletsWithData.forEach(wallet => {
                if (!wallet.details || wallet.details.length === 0) return;
                
                const walletCard = document.createElement('div');
                walletCard.className = 'wallet-card';
                walletCard.dataset.name = wallet.name;
                
                // Get first address for display
                const firstNetwork = wallet.details[0];
                const address = firstNetwork ? firstNetwork.address : '';
                
                walletCard.innerHTML = `
                    <div class="wallet-name">${wallet.name}</div>
                    <div class="wallet-address">${address}</div>
                `;
                
                walletCard.addEventListener('click', () => {
                    // Deselect all wallets
                    document.querySelectorAll('.wallet-card').forEach(card => {
                        card.classList.remove('selected');
                    });
                    
                    // Select this wallet
                    walletCard.classList.add('selected');
                    
                    // Store selected wallet
                    selectedWallet = {
                        name: wallet.name,
                        address: address
                    };
                    
                    // Enable continue button
                    document.getElementById('continueWalletButton').disabled = false;
                });
                
                walletsList.appendChild(walletCard);
            });
            
            if (walletsList.children.length === 0) {
                walletsList.innerHTML = `
                    <div style="text-align: center; padding: 15px;">
                        No wallets found with addresses. Please create a wallet in your Cellframe dashboard.
                    </div>
                `;
            }
        } else {
            throw new Error(response.errorMsg || 'Failed to load wallets');
        }
    } catch (error) {
        console.error('Error loading wallets:', error);
        
        const walletsList = document.getElementById('walletsList');
        walletsList.innerHTML = `
            <div style="text-align: center; padding: 15px; color: var(--error);">
                Error loading wallets: ${error.message}
            </div>
        `;
        
        document.getElementById('walletError').textContent = `Error: ${error.message}`;
        document.getElementById('walletError').style.display = 'block';
    }
}

function continueWithWallet() {
    if (!selectedWallet) {
        document.getElementById('walletError').textContent = 'Please select a wallet first';
        document.getElementById('walletError').style.display = 'block';
        return;
    }
    
    // Mark step as completed and activate next step
    document.getElementById('step2').classList.remove('active');
    document.getElementById('step2').classList.add('completed');
    document.getElementById('step3').classList.add('active');
    
    // Show DNA section
    document.getElementById('walletSection').style.display = 'none';
    document.getElementById('dnaSection').style.display = 'block';
    
    // Load/simulate DNA nicknames
    loadDnaNicknames();
}

async function loadDnaNicknames() {
    // For the current implementation, we'll simulate loading DNA nicknames
    // In a real implementation, we would fetch the DNA nicknames associated with the wallet
    const dnaList = document.getElementById('dnaList');
    
    // Simulate loading
    setTimeout(() => {
        // Create dummy DNA list (in a real implementation, this would come from an API)
        const dummies = [
            { name: 'cpunk_user', isVerified: true },
            { name: 'cellframe_fan', isVerified: false }
        ];
        
        dnaList.innerHTML = '';
        
        if (dummies.length === 0) {
            dnaList.innerHTML = `
                <div style="text-align: center; padding: 15px;">
                    No DNA nicknames found. Please register a DNA nickname first.
                </div>
            `;
            return;
        }
        
        // Create DNA cards
        dummies.forEach(dna => {
            const dnaCard = document.createElement('div');
            dnaCard.className = 'dna-card';
            dnaCard.dataset.name = dna.name;
            
            dnaCard.innerHTML = `
                <div class="dna-name">${dna.name} ${dna.isVerified ? '<span class="verification-badge">Verified</span>' : ''}</div>
            `;
            
            dnaCard.addEventListener('click', () => {
                // Deselect all DNA cards
                document.querySelectorAll('.dna-card').forEach(card => {
                    card.classList.remove('selected');
                });
                
                // Select this DNA
                dnaCard.classList.add('selected');
                
                // Store selected DNA
                selectedDna = dna.name;
                
                // Enable continue button
                document.getElementById('continueDnaButton').disabled = false;
            });
            
            dnaList.appendChild(dnaCard);
        });
    }, 1000); // Simulate loading delay
}

function continueWithDna() {
    if (!selectedDna) {
        document.getElementById('dnaError').textContent = 'Please select a DNA nickname first';
        document.getElementById('dnaError').style.display = 'block';
        return;
    }
    
    // Mark step as completed and activate next step
    document.getElementById('step3').classList.remove('active');
    document.getElementById('step3').classList.add('completed');
    document.getElementById('step4').classList.add('active');
    
    // Show message section
    document.getElementById('dnaSection').style.display = 'none';
    document.getElementById('messageSection').style.display = 'block';
}

function updateCharCount() {
    const messageText = document.getElementById('messageText');
    const charCount = document.getElementById('charCount');
    
    const count = messageText.value.length;
    charCount.textContent = `${count}/500`;
    
    // Optional: Show warning if approaching limit
    if (count > 450) {
        charCount.style.color = '#ffbb33';
    } else {
        charCount.style.color = '';
    }
}

function sendMessage() {
    const messageText = document.getElementById('messageText');
    const messageError = document.getElementById('messageError');
    const messageSuccess = document.getElementById('messageSuccess');
    
    // Basic validation
    if (!messageText.value.trim()) {
        messageError.textContent = 'Please enter a message';
        messageError.style.display = 'block';
        return;
    }
    
    // Get required information
    const fromDna = selectedDna;
    const toDna = document.getElementById('recipientName').textContent;
    const message = messageText.value.trim();
    
    // In a real implementation, we would send the message to an API
    // For now, we'll just show the "coming soon" message
    
    // Show success message
    messageSuccess.style.display = 'block';
}

// Event listeners (to be added after DOM is loaded)
document.addEventListener('DOMContentLoaded', () => {
    // Load the profile data
    loadProfileData();
    
    // Add event listeners for contact modal
    document.getElementById('closeModalButton').addEventListener('click', closeContactModal);
    document.getElementById('contactModal').addEventListener('click', (e) => {
        if (e.target === document.getElementById('contactModal')) {
            closeContactModal();
        }
    });
    
    // Add event listeners for dashboard connection
    document.getElementById('connectButton').addEventListener('click', connectToDashboard);
    document.getElementById('continueWalletButton').addEventListener('click', continueWithWallet);
    document.getElementById('continueDnaButton').addEventListener('click', continueWithDna);
    
    // Add event listener for message composition
    document.getElementById('messageText').addEventListener('input', updateCharCount);
    document.getElementById('sendButton').addEventListener('click', sendMessage);
});

// Make functions globally available
window.openContactModal = openContactModal;
window.toggleSection = toggleSection;
window.copyToClipboard = copyToClipboard;
