// DOM Elements
const lookupForm = document.getElementById('lookupForm');
const searchButton = document.getElementById('searchButton');
const searchInput = document.getElementById('searchInput');
const loadingIndicator = document.getElementById('loading');
const resultContainer = document.getElementById('result');
const recentSearchesContainer = document.getElementById('recentSearches');
const recentSearchesList = document.getElementById('recentSearchesList');

// API URL
const apiUrl = 'dna-proxy.php';

// Recent searches storage key
const RECENT_SEARCHES_KEY = 'cpunk_recent_searches';

// Initialize page
document.addEventListener('DOMContentLoaded', initPage);

function initPage() {
    // Load recent searches
    loadRecentSearches();
    
    // Set up event listeners
    searchButton.addEventListener('click', handleSearch);
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            handleSearch(e);
        }
    });
}

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

async function handleSearch(e) {
    if (e) e.preventDefault();
    
    const query = searchInput.value.trim();
    if (!query) {
        displayError("Please enter a DNA nickname or wallet address to search");
        return;
    }
    
    // Show loading indicator
    loadingIndicator.style.display = 'block';
    resultContainer.style.display = 'none';
    
    try {
        let result;
        const apiRequestTime = new Date().toISOString();
        const apiRequestUrl = `${apiUrl}?lookup=${encodeURIComponent(query)}`;
        const apiRequestMethod = 'GET';
        
        // Log API request to console if available
        if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logRequest) {
            CpunkAPIConsole.logRequest({
                url: apiRequestUrl,
                method: apiRequestMethod,
                timestamp: apiRequestTime,
                params: { lookup: query }
            });
        }
        
        // Use CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.dnaLookup) {
            CpunkUtils.logDebug(`Looking up DNA: ${query}`, 'info');
            result = await CpunkUtils.dnaLookup('lookup', query);
            
            // Log API response to console if available
            if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logResponse) {
                CpunkAPIConsole.logResponse({
                    url: apiRequestUrl,
                    method: apiRequestMethod,
                    timestamp: new Date().toISOString(),
                    requestTime: apiRequestTime,
                    data: result,
                    status: result && result.status_code === 0 ? "success" : "error"
                });
            }
            
            // Save search to recent searches
            saveToRecentSearches(query);
            
            // Process the result
            if (typeof result === 'string') {
                // Check if text response indicates the name doesn't exist
                if (result.includes('not found') || result.trim() === '') {
                    displayError(`No DNA registration found for "${query}"`);
                } else {
                    displayError(`Error parsing response: Invalid format`);
                }
            } else if (result.status_code === 0 && result.response_data) {
                // Process structured data
                displayStructuredResult(result.response_data, query);
            } else if (result.wallet) {
                // Process legacy data
                displayLegacyResult(result, query);
            } else if (result.error) {
                // Display error
                displayError(result.error);
            } else {
                // Unknown data format
                displayError('No data found for this query.');
            }
        } else {
            // Fallback implementation if CpunkUtils is not available
            CpunkUtils.logDebug(`Direct API call for lookup: ${query}`, 'info');
            const response = await fetch(apiRequestUrl);
            const text = await response.text();
            
            try {
                // Try to parse as JSON
                const data = JSON.parse(text);
                
                // Log API response to console if available
                if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logResponse) {
                    CpunkAPIConsole.logResponse({
                        url: apiRequestUrl,
                        method: apiRequestMethod,
                        timestamp: new Date().toISOString(),
                        requestTime: apiRequestTime,
                        data: data,
                        status: data && data.status_code === 0 ? "success" : "error"
                    });
                }
                
                // Save search to recent searches
                saveToRecentSearches(query);
                
                // Process the data
                if (data.status_code === 0 && data.response_data) {
                    // Process structured data
                    displayStructuredResult(data.response_data, query);
                } else if (data.wallet) {
                    // Process legacy data
                    displayLegacyResult(data, query);
                } else if (data.error) {
                    // Display error
                    displayError(data.error);
                } else {
                    // Unknown data format
                    displayError('No data found for this query.');
                }
            } catch (parseError) {
                // Log API error response to console if available
                if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logResponse) {
                    CpunkAPIConsole.logResponse({
                        url: apiRequestUrl,
                        method: apiRequestMethod,
                        timestamp: new Date().toISOString(),
                        requestTime: apiRequestTime,
                        data: text,
                        status: "error",
                        error: parseError.message
                    });
                }
                
                // If parsing fails, check if it's a "not found" message
                if (text.includes('not found') || text.trim() === '') {
                    displayError(`No DNA registration found for "${query}"`);
                } else {
                    displayError(`Error parsing response: ${parseError.message}`);
                }
            }
        }
    } catch (error) {
        // Log the error with CpunkUtils if available
        if (typeof CpunkUtils !== 'undefined' && CpunkUtils.logDebug) {
            CpunkUtils.logDebug('DNA lookup error', 'error', {
                query: query,
                error: error.message,
                stack: error.stack
            });
        } else {
            console.error('DNA lookup error:', error);
        }
        
        // Log to API console if available
        if (typeof CpunkAPIConsole !== 'undefined' && CpunkAPIConsole.logError) {
            CpunkAPIConsole.logError({
                url: `${apiUrl}?lookup=${encodeURIComponent(query)}`,
                method: 'GET',
                timestamp: new Date().toISOString(),
                error: error.message,
                details: {
                    query: query,
                    stack: error.stack
                }
            });
        }
        
        // Network or other error
        loadingIndicator.style.display = 'none';
        displayError(`Error: ${error.message}`);
    } finally {
        // Hide loading indicator
        loadingIndicator.style.display = 'none';
    }
}

function displayStructuredResult(data, query) {
    // Get registered names
    const registeredNames = data.registered_names || {};
    const nicknames = Object.keys(registeredNames);
    const primaryNickname = nicknames.length > 0 ? nicknames[0] : 'Unknown';
    
    // Get wallet addresses
    const walletAddresses = data.wallet_addresses || {};
    
    // Get public key
    const publicKey = data.public_hash || data.public_key || '';
    
    // Get social media accounts
    const socials = data.socials || {};
    
    // Get external wallets
    const externalWallets = data.dinosaur_wallets || {};
    
    // Generate unique section IDs
    const walletSectionId = `wallet-addresses-${Date.now()}`;
    const externalWalletSectionId = `external-wallets-${Date.now()}`;
    const publickeysSectionId = `pubkey-section-${Date.now()}`;
    const socialsSectionId = `social-section-${Date.now()}`;
    
    // Build the result HTML
    let html = `
        <div class="highlight-box">
            <div class="profile-header">
                <div class="avatar">${primaryNickname.charAt(0).toUpperCase()}</div>
                <div class="profile-info">
                    <div class="profile-nickname">${primaryNickname}</div>
    `;
    
    // Add verification badge if this is an official account
    if (primaryNickname === 'cpunk' || primaryNickname === 'cellframe') {
        html += `<span class="verification-badge">Official</span>`;
    }
    
    html += `
                    <div class="profile-id">DNA: ${primaryNickname}</div>
                </div>
            </div>
        `;
    
    // Add profile description if available
    if (data.profile && data.profile.description) {
        html += `
            <div class="profile-description">
                ${data.profile.description}
            </div>
        `;
    }
    
    html += `</div>`;
    
    // Stats section
    html += `
        <div class="info-grid">
            <div class="info-item">
                <h3>DNA Nicknames</h3>
                <div class="stat-value">${nicknames ? nicknames.length : 1}</div>
            </div>
            <div class="info-item">
                <h3>Networks</h3>
                <div class="stat-value">${Object.keys(walletAddresses).length}</div>
            </div>
            <div class="info-item">
                <h3>External Wallets</h3>
                <div class="stat-value">${Object.keys(externalWallets).filter(key => externalWallets[key]).length}</div>
            </div>
        </div>
    `;
    
    // Add wallet addresses
    if (Object.keys(walletAddresses).length > 0) {
        html += `
            <div class="highlight-box">
                <div class="section-title">
                    <div class="section-title-text">Cellframe Wallet Addresses</div>
                    <button class="toggle-button" data-toggle="${walletSectionId}" onclick="toggleSection('${walletSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${walletSectionId}" class="section-content collapsed">
        `;
        
        Object.entries(walletAddresses).forEach(([network, address]) => {
            // Format the address with spaces for better readability
            let formattedAddress = formatLongAddress(address);
            
            html += `
                <div class="network-card">
                    <div class="network-name">
                        ${network}
                        <button class="copy-button" onclick="copyToClipboard('${address}', this)">Copy Address</button>
                    </div>
                    <div class="address-display">${formattedAddress}</div>
                </div>
            `;
        });
        
        html += `</div></div>`;
    }
    
    // Add external wallets if any
    const hasExternalWallets = Object.values(externalWallets).some(wallet => wallet && wallet.trim() !== '');
    if (hasExternalWallets) {
        html += `
            <div class="highlight-box">
                <div class="section-title">
                    <div class="section-title-text">External Blockchain Wallets</div>
                    <button class="toggle-button" data-toggle="${externalWalletSectionId}" onclick="toggleSection('${externalWalletSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${externalWalletSectionId}" class="section-content collapsed">
                    <div class="external-wallets">
        `;
        
        Object.entries(externalWallets).forEach(([chain, address]) => {
            if (address && address.trim() !== '') {
                const icon = getCryptoIcon(chain);
                const formattedAddress = formatLongAddress(address);
                
                html += `
                    <div class="external-wallet-card">
                        <div class="external-wallet-header">
                            <div class="external-wallet-icon">${icon}</div>
                            <div class="external-wallet-name">${chain}</div>
                        </div>
                        <div class="external-wallet-address">${formattedAddress}</div>
                        <button class="copy-button" onclick="copyToClipboard('${address}', this)">Copy Address</button>
                    </div>
                `;
            }
        });
        
        html += `</div></div></div>`;
    }
    
    // Add public key if available
    if (publicKey) {
        html += `
            <div class="highlight-box">
                <div class="section-title">
                    <div class="section-title-text">Public Key</div>
                    <button class="toggle-button" data-toggle="${publickeysSectionId}" onclick="toggleSection('${publickeysSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${publickeysSectionId}" class="section-content collapsed">
                    <div class="pubkey-container">
                        <div class="pubkey-display">${formatLongAddress(publicKey)}</div>
                        <button class="copy-button" onclick="copyToClipboard('${publicKey}', this)">Copy Public Key</button>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Add social media links if any
    const hasSocials = Object.values(socials).some(social => social && social.profile && social.profile.trim() !== '');
    if (hasSocials) {
        html += `
            <div class="highlight-box">
                <div class="section-title">
                    <div class="section-title-text">Social Media</div>
                    <button class="toggle-button" data-toggle="${socialsSectionId}" onclick="toggleSection('${socialsSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${socialsSectionId}" class="section-content collapsed">
                    <div class="social-links-grid">
        `;
        
        Object.entries(socials).forEach(([platform, data]) => {
            if (data && data.profile && data.profile.trim() !== '') {
                const handle = data.profile;

                // Only add @ for platforms that conventionally use it
                const atPlatforms = ['twitter', 'x', 'instagram', 'telegram', 'tiktok', 'reddit', 'discord'];
                const lowerPlatform = platform.toLowerCase();
                const displayHandle = handle.startsWith('@') ? handle :
                    (atPlatforms.includes(lowerPlatform) ? '@' + handle : handle);
                const icon = getSocialIcon(platform);
                const url = formatSocialUrl(platform, handle);
                
                html += `
                    <a href="${url}" target="_blank" class="social-link">
                        <span class="social-icon">${icon}</span>
                        <span class="social-platform">${capitalizeFirstLetter(platform)}</span>
                        <span class="social-handle">${displayHandle}</span>
                    </a>
                `;
            }
        });
        
        html += `</div></div></div>`;
    } else {
        html += `
            <div class="highlight-box">
                <div class="section-title">
                    <div class="section-title-text">Social Media</div>
                    <button class="toggle-button" data-toggle="${socialsSectionId}" onclick="toggleSection('${socialsSectionId}')" title="Expand section">+</button>
                </div>
                <div id="${socialsSectionId}" class="section-content collapsed">
                    <div class="no-data-message">
                        No social media accounts linked to this profile.
                    </div>
                </div>
            </div>
        `;
    }
    
    // Add link to full profile page
    if (nicknames.length > 0) {
        html += `
            <div class="help-button-container">
                <a href="/${primaryNickname}" class="help-button">View Full Profile</a>
                <div class="help-description">See all details for ${primaryNickname}</div>
            </div>
        `;
    }
    
    // Set the result content and show it
    resultContainer.className = 'result success';
    resultContainer.innerHTML = html;
    resultContainer.style.display = 'block';
}

function displayLegacyResult(data, query) {
    const nickname = typeof query === 'string' && query.indexOf('@') === -1 ? query : 'Unknown';
    const walletAddress = data.wallet || '';
    const walletSectionId = `wallet-addresses-legacy-${Date.now()}`;
    
    let html = `
        <div class="highlight-box">
            <div class="profile-header">
                <div class="avatar">${nickname.charAt(0).toUpperCase()}</div>
                <div class="profile-info">
                    <div class="profile-nickname">${nickname}</div>
                    <div class="profile-id">DNA: ${nickname}</div>
                </div>
            </div>
        </div>
        
        <div class="info-grid">
            <div class="info-item">
                <h3>DNA Nicknames</h3>
                <div class="stat-value">1</div>
            </div>
            <div class="info-item">
                <h3>Networks</h3>
                <div class="stat-value">1</div>
            </div>
            <div class="info-item">
                <h3>External Wallets</h3>
                <div class="stat-value">0</div>
            </div>
        </div>
        
        <div class="highlight-box">
            <div class="section-title">
                <div class="section-title-text">Wallet Address</div>
                <button class="toggle-button" data-toggle="${walletSectionId}" onclick="toggleSection('${walletSectionId}')" title="Expand section">+</button>
            </div>
            <div id="${walletSectionId}" class="section-content collapsed">
                <div class="network-card">
                    <div class="network-name">
                        Backbone
                        <button class="copy-button" onclick="copyToClipboard('${walletAddress}', this)">Copy Address</button>
                    </div>
                    <div class="address-display">${formatLongAddress(walletAddress)}</div>
                </div>
            </div>
        </div>
    `;
    
    // Add link to full profile page
    html += `
        <div class="help-button-container">
            <a href="/${nickname}" class="help-button">View Full Profile</a>
            <div class="help-description">See all details for ${nickname}</div>
        </div>
    `;
    
    // Set the result content and show it
    resultContainer.className = 'result success';
    resultContainer.innerHTML = html;
    resultContainer.style.display = 'block';
}

function displayError(message) {
    // Use CpunkUI if available
    if (typeof CpunkUI !== 'undefined' && CpunkUI.showError) {
        resultContainer.className = 'result error';
        resultContainer.innerHTML = '';
        
        // Show error using CpunkUI
        CpunkUI.showError(message, resultContainer.id);
        resultContainer.style.display = 'block';
        return;
    }
    
    // Fallback implementation if CpunkUI is not available
    resultContainer.className = 'result error';
    resultContainer.innerHTML = `
        <div class="highlight-box">
            <div class="error-container">
                <div class="error-icon">⚠️</div>
                <div class="error-title">Error</div>
                <div class="error-message">${message}</div>
            </div>
        </div>
    `;
    resultContainer.style.display = 'block';
}

// Save to recent searches
function saveToRecentSearches(query) {
    if (!query) return;
    
    // Get existing searches
    let searches = JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || '[]');
    
    // Check if this search already exists
    const index = searches.indexOf(query);
    if (index > -1) {
        // Remove it so we can add it to the beginning (most recent)
        searches.splice(index, 1);
    }
    
    // Add to beginning of array
    searches.unshift(query);
    
    // Limit to 5 searches
    searches = searches.slice(0, 5);
    
    // Save back to local storage
    localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(searches));
    
    // Update the UI
    loadRecentSearches();
}

// Load recent searches from localStorage
function loadRecentSearches() {
    let searches = JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || '[]');
    
    if (searches.length > 0) {
        // Clear the list
        recentSearchesList.innerHTML = '';
        
        // Add each search item
        searches.forEach(search => {
            const item = document.createElement('div');
            item.className = 'recent-search-item';
            item.textContent = search;
            item.addEventListener('click', () => {
                searchInput.value = search;
                handleSearch();
            });
            
            recentSearchesList.appendChild(item);
        });
        
        // Show the container
        recentSearchesContainer.style.display = 'block';
        
        // Add event listener to clear searches button
        const clearSearchesBtn = document.getElementById('clearSearches');
        if (clearSearchesBtn) {
            // Prevent multiple event listeners
            clearSearchesBtn.removeEventListener('click', clearRecentSearches);
            clearSearchesBtn.addEventListener('click', clearRecentSearches);
        }
    } else {
        // Hide the container if no recent searches
        recentSearchesContainer.style.display = 'none';
    }
}

// Clear all recent searches
function clearRecentSearches() {
    localStorage.removeItem(RECENT_SEARCHES_KEY);
    recentSearchesList.innerHTML = '';
    recentSearchesContainer.style.display = 'none';
}

// Utility function to copy text to clipboard
function copyToClipboard(text, buttonElement) {
    // Use CpunkUtils if available
    if (typeof CpunkUtils !== 'undefined' && CpunkUtils.copyToClipboard) {
        CpunkUtils.copyToClipboard(
            text,
            // Success callback
            () => {
                const originalText = buttonElement.textContent;
                buttonElement.textContent = 'Copied!';
                setTimeout(() => {
                    buttonElement.textContent = originalText;
                }, 2000);
            },
            // Error callback
            (err) => {
                console.error('Could not copy text: ', err);
            }
        );
        return;
    }
    
    // Fallback implementation if CpunkUtils is not available
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
        'TRX': 'T',
        'QEVM': 'Q'
    };
    
    return icons[chain] || '🪙';
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

// Capitalize first letter of a string
function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

// Format long addresses for better readability
function formatLongAddress(address) {
    if (!address) return '';
    
    // For addresses longer than 30 characters, add some formatting
    if (address.length <= 30) return address;
    
    // For very long addresses, show beginning, middle with ellipsis, and end
    if (address.length > 60) {
        const start = address.substring(0, 20);
        const middle = '...';
        const end = address.substring(address.length - 20);
        return `<span class="address-segment">${start}</span>${middle}<span class="address-segment">${end}</span>`;
    }
    
    // For moderately long addresses, just add some spacing
    const segments = [];
    for (let i = 0; i < address.length; i += 15) {
        segments.push(address.substring(i, Math.min(i + 15, address.length)));
    }
    
    return segments.map(seg => `<span class="address-segment">${seg}</span>`).join('');
}