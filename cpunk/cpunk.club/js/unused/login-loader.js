/**
 * CPUNK Login Loader
 * Efficiently loads and initializes the login page components
 */

// Main function to load the login page
async function loadLoginPage() {
    try {
        // First, attempt to load the navbar
        await loadNavbar();
        
        // Initialize connection section
        initConnectionSection();
        
        // Set up tab navigation
        initTabNavigation();
        
        // Initialize OAuth handlers
        initOAuthHandlers();
        
        // Set up any remaining event listeners
        setupEventListeners();
        
        // Log page initialization
        logInitialization();
    } catch (error) {
        console.error('Error loading login page:', error);
    }
}

// Load the navbar content
async function loadNavbar() {
    return new Promise((resolve, reject) => {
        const navbarPlaceholder = document.querySelector('.navbar-placeholder');
        if (!navbarPlaceholder) {
            resolve(); // No navbar placeholder, continue
            return;
        }
        
        fetch('navbar-template.html')
            .then(response => response.text())
            .then(html => {
                navbarPlaceholder.innerHTML = html;
                resolve();
            })
            .catch(error => {
                console.error('Failed to load navbar:', error);
                resolve(); // Continue even if navbar fails
            });
    });
}

// Initialize the dashboard connection section
function initConnectionSection() {
    const connectButton = document.getElementById('connectButton');
    if (connectButton) {
        connectButton.addEventListener('click', () => {
            if (typeof connectToDashboard === 'function') {
                connectToDashboard();
            } else {
                console.error('Dashboard connection function not available');
            }
        });
    }
}

// Initialize tab navigation
function initTabNavigation() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    if (!tabButtons.length || !tabContents.length) return;

    // Define tab switching function
    window.switchTab = function(tabId) {
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
    };

    // Add click handlers to all tab buttons
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            window.switchTab(tabId);
        });
    });
}

// Initialize OAuth handlers for social authentication
function initOAuthHandlers() {
    // Google OAuth
    setupOAuthButton('connectGoogleButton', 'google_oauth.php', 'googleAuth', handleGoogleAuthCallback);
    
    // Twitter OAuth
    setupOAuthButton('connectTwitterButton', 'twitter_oauth.php', 'twitterAuth');
    
    // LinkedIn OAuth
    setupOAuthButton('connectLinkedInButton', 'linkedin_oauth.php', 'linkedinAuth', handleLinkedInAuthCallback);
    
    // GitHub OAuth
    setupOAuthButton('connectGitHubButton', 'github_oauth.php', 'githubAuth', handleGitHubAuthCallback);
}

// Helper function to set up OAuth buttons with consistent behavior
function setupOAuthButton(buttonId, oauthUrl, windowName, callbackHandler) {
    const button = document.getElementById(buttonId);
    if (!button) return;
    
    button.addEventListener('click', function(e) {
        e.preventDefault();
        
        // Check for wallet address
        if (!walletAddress) {
            if (saveError) {
                saveError.textContent = 'Wallet address is missing. Please select a wallet first.';
                saveError.style.display = 'block';
            }
            return;
        }
        
        // Disable the button during OAuth
        const originalContent = button.innerHTML;
        button.disabled = true;
        button.innerHTML = '<span class="loading-spinner"></span>Connecting...';
        
        // Open popup for OAuth
        const width = 600;
        const height = 600;
        const left = window.screen.width / 2 - width / 2;
        const top = window.screen.height / 2 - height / 2;
        const features = `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no,location=no`;
        
        // Open the popup with wallet parameter
        const authUrl = `${oauthUrl}?request=auth&wallet=${encodeURIComponent(walletAddress)}`;
        const popup = window.open(authUrl, windowName, features);
        
        // Check if popup was blocked
        if (!popup || popup.closed || typeof popup.closed === 'undefined') {
            console.error('Popup window was blocked or failed to open');
            if (saveError) {
                saveError.textContent = `Please allow popups for this site to use ${windowName.replace('Auth', '')} authentication`;
                saveError.style.display = 'block';
            }
            
            // Reset button
            button.disabled = false;
            button.innerHTML = originalContent;
            return;
        }
        
        // Add callback handler if provided
        if (callbackHandler) {
            window.addEventListener('message', callbackHandler);
        }
    });
}

// Set up remaining event listeners
function setupEventListeners() {
    // Continue button for wallet selection
    const continueButton = document.getElementById('continueButton');
    if (continueButton) {
        continueButton.addEventListener('click', () => {
            if (typeof continueWithWallet === 'function') {
                continueWithWallet();
            }
        });
    }
    
    // Edit button for DNA section
    const editButton = document.getElementById('editButton');
    if (editButton) {
        editButton.addEventListener('click', () => {
            document.getElementById('dnaSection').style.display = 'none';
            document.getElementById('editSection').style.display = 'block';
            // Hide the edit button after clicking
            editButton.style.display = 'none';
        });
    }
    
    // Save button for profile changes
    const saveButton = document.getElementById('saveButton');
    if (saveButton) {
        saveButton.addEventListener('click', () => {
            if (typeof saveProfileChanges === 'function') {
                saveProfileChanges();
            }
        });
    }

    // Load DNA information whenever the DNA tab is clicked
    const dnaTabButton = document.querySelector('button.tab-button[data-tab="dna-tab"]');
    if (dnaTabButton) {
        dnaTabButton.addEventListener('click', loadDNAInformation);
    }
    
    // Telegram verification
    const verifyTelegramButton = document.getElementById('verifyTelegramButton');
    if (verifyTelegramButton) {
        verifyTelegramButton.addEventListener('click', () => {
            if (typeof openTelegramVerification === 'function') {
                openTelegramVerification();
            }
        });
    }
    
    // Close modal button
    const closeModalButton = document.getElementById('closeModalButton');
    if (closeModalButton) {
        closeModalButton.addEventListener('click', () => {
            document.getElementById('telegramVerificationModal').style.display = 'none';
        });
    }
    
    // Copy GUID button
    const copyGuidButton = document.getElementById('copyGuidButton');
    if (copyGuidButton) {
        copyGuidButton.addEventListener('click', () => {
            const guidValue = document.getElementById('guidValue');
            if (guidValue && guidValue.value) {
                navigator.clipboard.writeText(guidValue.value)
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
}

// Log page initialization
function logInitialization() {
    setTimeout(() => {
        if (window.logAPI) {
            window.logAPI('Login Page Initialized', { 
                source: 'login.html', 
                time: new Date().toISOString(),
                message: 'Press Ctrl+Shift+A to toggle API Console'
            });
        }
        
        // Initialize other utilities
        if (typeof CpunkUtils !== 'undefined') {
            CpunkUtils.init({
                debug: {
                    enabled: true,
                    showInConsole: true
                }
            });
        }
    }, 500);
}

// Helper function to update social count
function updateSocialCount() {
    const socialsCountElement = document.getElementById('socialsCount');
    if (socialsCountElement) {
        let verifiedCount = 0;

        // Check if Twitter/X is verified (multiple methods)
        const twitterStatusCircle = document.querySelector('#twitterVerificationStatus .status-circle');
        const twitterWrapper = document.querySelector('.twitter-wrapper');

        if ((twitterStatusCircle && twitterStatusCircle.classList.contains('status-verified')) ||
            (twitterWrapper && (twitterWrapper.textContent.includes('Verified') ||
                                twitterWrapper.textContent.includes('Connected')))) {
            verifiedCount++;
            console.log('Twitter verified - count:', verifiedCount);
        }

        // Check if Telegram is verified
        const telegramStatus = document.querySelector('#telegramVerificationStatus .status-text');
        const telegramCircle = document.querySelector('#telegramVerificationStatus .status-circle');

        if ((telegramStatus && telegramStatus.textContent === 'Verified') ||
            (telegramCircle && telegramCircle.classList.contains('status-verified'))) {
            verifiedCount++;
            console.log('Telegram verified - count:', verifiedCount);
        }

        // Check if Google is verified
        const googleStatus = document.querySelector('#googleVerificationStatus .status-text');
        const googleCircle = document.querySelector('#googleVerificationStatus .status-circle');
        const googleProfile = document.getElementById('googleProfile');

        if ((googleStatus && googleStatus.textContent === 'Verified') ||
            (googleCircle && googleCircle.classList.contains('status-verified')) ||
            (googleProfile && googleProfile.value && googleProfile.value !== 'Not connected')) {
            verifiedCount++;
            console.log('Google verified - count:', verifiedCount);
        }

        // Check if LinkedIn is verified
        const linkedinStatus = document.querySelector('#linkedinVerificationStatus .status-text');
        const linkedinCircle = document.querySelector('#linkedinVerificationStatus .status-circle');
        const linkedinProfile = document.getElementById('linkedinProfile');

        if ((linkedinStatus && linkedinStatus.textContent === 'Verified') ||
            (linkedinCircle && linkedinCircle.classList.contains('status-verified')) ||
            (linkedinProfile && linkedinProfile.value && linkedinProfile.value !== 'Not connected')) {
            verifiedCount++;
            console.log('LinkedIn verified - count:', verifiedCount);
        }

        // Check if GitHub is verified - more robust check
        const githubStatus = document.querySelector('#githubVerificationStatus .status-text');
        const githubCircle = document.querySelector('#githubVerificationStatus .status-circle');
        const githubProfile = document.getElementById('githubProfile');
        const connectGitHubButton = document.getElementById('connectGitHubButton');

        // Check for GitHub verification with multiple methods
        const githubVerifiedByUI = (githubStatus && githubStatus.textContent === 'Verified') ||
                                   (githubCircle && githubCircle.classList.contains('status-verified'));

        const githubVerifiedByInput = (githubProfile && githubProfile.value &&
                                      githubProfile.value !== 'Not connected' &&
                                      githubProfile.value !== '');

        const githubVerifiedByButton = (connectGitHubButton &&
                                       (connectGitHubButton.style.display === 'none' ||
                                        connectGitHubButton.disabled === true));

        // Check localStorage for backup verification data
        let githubVerifiedByStorage = false;
        try {
            const storedData = localStorage.getItem('github_oauth_success') || localStorage.getItem('github_oauth_backup');
            if (storedData) {
                const parsed = JSON.parse(storedData);
                if (parsed && parsed.username) {
                    githubVerifiedByStorage = true;
                    console.log('[DEBUG] GitHub verified via localStorage:', parsed.username);
                }
            }
        } catch (err) {
            console.error('[DEBUG] Error checking GitHub localStorage data:', err);
        }

        // If any verification method is true, consider GitHub verified
        if (githubVerifiedByUI || githubVerifiedByInput || githubVerifiedByButton || githubVerifiedByStorage) {
            verifiedCount++;
            console.log('GitHub verified - count:', verifiedCount);

            // Ensure UI is properly updated if verified through storage
            if (githubVerifiedByStorage && !githubVerifiedByUI && githubStatus) {
                githubStatus.innerHTML = `
                    <div class="status-circle status-verified"></div>
                    <span class="status-text">Verified</span>
                `;

                if (connectGitHubButton) {
                    connectGitHubButton.style.display = 'none';
                    connectGitHubButton.disabled = true;
                }
            }
        }

        // Update the count and log it
        socialsCountElement.textContent = verifiedCount;
        console.log('Final social count:', verifiedCount);
    }
}

// Function to show error messages
function showError(message) {
    console.log('showError called with message:', message);

    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.style.padding = '10px';
    errorElement.style.marginTop = '10px';
    errorElement.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
    errorElement.style.border = '1px solid rgba(255, 0, 0, 0.3)';
    errorElement.style.borderRadius = '4px';
    errorElement.style.color = '#ff6b6b';
    errorElement.textContent = message;

    // Find where to insert the error message
    const socialTab = document.getElementById('socials-tab');
    console.log('socialTab element:', socialTab);

    if (socialTab) {
        socialTab.appendChild(errorElement);
        console.log('Error message added to socialTab');

        // Remove the error message after 5 seconds
        setTimeout(() => {
            errorElement.remove();
        }, 5000);
    } else {
        // Fallback if socialTab doesn't exist
        console.error('socialTab element not found, showing alert instead');
        alert('Error: ' + message);
    }
}

// Google OAuth callback handler
async function handleGoogleAuthCallback(event) {
    // Verify the origin
    if (event.origin !== window.location.origin) {
        console.warn('Received message from unknown origin', event.origin);
        return;
    }

    console.log('Received Google auth callback:', event.data);

    if (event.data.type === 'google_auth_success') {
        // Success - Google account connected
        const email = event.data.email;

        // Update the UI
        const googleProfileInput = document.getElementById('googleProfile');
        if (googleProfileInput) googleProfileInput.value = email;

        // Update verification status
        const googleVerificationStatus = document.getElementById('googleVerificationStatus');
        if (googleVerificationStatus) {
            googleVerificationStatus.innerHTML = `
                <div class="status-circle status-verified"></div>
                <span class="status-text">Verified</span>
            `;
        }

        // Update button
        const connectGoogleButton = document.getElementById('connectGoogleButton');
        if (connectGoogleButton) {
            connectGoogleButton.disabled = true;
            connectGoogleButton.textContent = 'Connected';
            connectGoogleButton.style.backgroundColor = '#00C851';
        }

        // Show success message
        if (saveSuccess) {
            saveSuccess.textContent = `Google account ${email} connected successfully!`;
            saveSuccess.style.display = 'block';
        }
        if (saveError) saveError.style.display = 'none';

        // Update social count
        setTimeout(updateSocialCount, 500);

        // Refresh data to get latest changes
        if (typeof checkDnaRegistration === 'function') {
            await checkDnaRegistration();
        }

    } else if (event.data.type === 'google_auth_error') {
        // Error occurred during Google auth
        console.error('Google auth error:', event.data.error);

        // Reset button
        const connectGoogleButton = document.getElementById('connectGoogleButton');
        if (connectGoogleButton) {
            connectGoogleButton.disabled = false;
            connectGoogleButton.innerHTML = 'Connect Google';
        }

        // Show error message
        if (saveError) {
            saveError.textContent = `Error connecting Google: ${event.data.error}`;
            saveError.style.display = 'block';
        }
        if (saveSuccess) saveSuccess.style.display = 'none';
    }

    // Clean up event listener
    window.removeEventListener('message', handleGoogleAuthCallback);
}

// LinkedIn OAuth callback handler
async function handleLinkedInAuthCallback(event) {
    // Verify the origin
    if (event.origin !== window.location.origin) {
        console.warn('Received message from unknown origin', event.origin);
        return;
    }

    console.log('Received LinkedIn auth callback:', event.data);

    if (event.data.type === 'linkedin_auth_success') {
        // Success - LinkedIn account connected
        const profile = event.data.profile;
        const name = event.data.name;

        // Update the UI
        const linkedinProfileInput = document.getElementById('linkedinProfile');
        if (linkedinProfileInput) linkedinProfileInput.value = profile;

        // Update verification status
        const linkedinVerificationStatus = document.getElementById('linkedinVerificationStatus');
        if (linkedinVerificationStatus) {
            linkedinVerificationStatus.innerHTML = `
                <div class="status-circle status-verified"></div>
                <span class="status-text">Verified</span>
            `;
        }

        // Hide the connect button completely when verified
        const connectLinkedInButton = document.getElementById('connectLinkedInButton');
        if (connectLinkedInButton) {
            connectLinkedInButton.style.display = 'none';
        }

        // Hide the help text for verified accounts
        const linkedinHelpText = connectLinkedInButton ?
            connectLinkedInButton.parentElement.nextElementSibling : null;
        if (linkedinHelpText && linkedinHelpText.classList.contains('help-text')) {
            linkedinHelpText.style.display = 'none';
        }

        // Show success message
        if (saveSuccess) {
            saveSuccess.textContent = `LinkedIn profile connected successfully!`;
            saveSuccess.style.display = 'block';
        }
        if (saveError) saveError.style.display = 'none';

        // Update social count
        setTimeout(updateSocialCount, 500);

        // Refresh data to get latest changes
        if (typeof checkDnaRegistration === 'function') {
            await checkDnaRegistration();
        }

    } else if (event.data.type === 'linkedin_auth_error') {
        // Error occurred during auth
        console.error('LinkedIn auth error:', event.data.error);

        // Reset button
        const connectLinkedInButton = document.getElementById('connectLinkedInButton');
        if (connectLinkedInButton) {
            connectLinkedInButton.disabled = false;
            connectLinkedInButton.style.display = 'block';
            connectLinkedInButton.innerHTML = `
                <svg width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.32 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.79M6.88 8.56a1.68 1.68 0 0 0 1.68-1.68c0-.93-.75-1.69-1.68-1.69a1.69 1.69 0 0 0-1.69 1.69c0 .93.76 1.68 1.69 1.68m1.39 9.94v-8.37H5.5v8.37h2.77z"/>
                </svg>
                Connect LinkedIn
            `;

            // Ensure help text is visible
            const linkedinHelpText = connectLinkedInButton ?
                connectLinkedInButton.parentElement.nextElementSibling : null;
            if (linkedinHelpText && linkedinHelpText.classList.contains('help-text')) {
                linkedinHelpText.style.display = '';
            }
        }

        // Show error message
        if (saveError) {
            saveError.textContent = `Error connecting LinkedIn: ${event.data.error}`;
            saveError.style.display = 'block';
        }
        if (saveSuccess) saveSuccess.style.display = 'none';
    }

    // Clean up event listener
    window.removeEventListener('message', handleLinkedInAuthCallback);
}

// GitHub OAuth callback handler
async function handleGitHubAuthCallback(event) {
    // Verify the origin
    if (event.origin !== window.location.origin) {
        console.warn('Received message from unknown origin', event.origin);
        return;
    }

    console.log('Received GitHub auth callback:', event.data);

    if (event.data.type === 'github_auth_success') {
        // Success - GitHub account connected
        const username = event.data.username;
        const name = event.data.name || '';

        // Update the UI
        const githubProfileInput = document.getElementById('githubProfile');
        if (githubProfileInput) githubProfileInput.value = username;

        // Update verification status
        const githubVerificationStatus = document.getElementById('githubVerificationStatus');
        if (githubVerificationStatus) {
            githubVerificationStatus.innerHTML = `
                <div class="status-circle status-verified"></div>
                <span class="status-text">Verified</span>
            `;
        }

        // Hide the connect button completely when verified (like LinkedIn)
        const connectGitHubButton = document.getElementById('connectGitHubButton');
        if (connectGitHubButton) {
            connectGitHubButton.style.display = 'none';
        }

        // Hide the help text
        const githubHelpText = connectGitHubButton ?
            connectGitHubButton.parentElement.nextElementSibling : null;
        if (githubHelpText && githubHelpText.classList.contains('help-text')) {
            githubHelpText.style.display = 'none';
        }

        // Show success message
        if (saveSuccess) {
            saveSuccess.textContent = `GitHub account @${username} connected successfully!`;
            saveSuccess.style.display = 'block';
        }
        if (saveError) saveError.style.display = 'none';

        // Update social count
        setTimeout(updateSocialCount, 500);

        // Refresh data to get latest changes (same approach as LinkedIn/Google)
        if (typeof checkDnaRegistration === 'function') {
            await checkDnaRegistration();
        }

    } else if (event.data.type === 'github_auth_error') {
        // Error occurred during GitHub auth
        console.error('GitHub auth error:', event.data.error);

        // Reset button
        const connectGitHubButton = document.getElementById('connectGitHubButton');
        if (connectGitHubButton) {
            connectGitHubButton.disabled = false;
            connectGitHubButton.innerHTML = `
                <svg width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">
                    <path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                Connect GitHub
            `;
        }

        // Show error message
        if (saveError) {
            saveError.textContent = `Error connecting GitHub: ${event.data.error}`;
            saveError.style.display = 'block';
        }
        if (saveSuccess) saveSuccess.style.display = 'none';
    }

    // Clean up event listener
    window.removeEventListener('message', handleGitHubAuthCallback);
}

// Function to load DNA information for the selected wallet
async function loadDNAInformation() {
    // Access variables from global scope
    const walletAddress = window.walletAddress;
    const dnaData = window.dnaData;
    const checkDnaRegistration = window.checkDnaRegistration;
    const linkedDNAsElement = document.getElementById('linkedDNAs');
    const noDNAsElement = document.getElementById('noDNAs');

    if (!linkedDNAsElement || !noDNAsElement) return;

    // If no wallet is selected, show error
    if (!walletAddress) {
        linkedDNAsElement.style.display = 'none';
        noDNAsElement.style.display = 'block';
        noDNAsElement.innerHTML = `
            <p>No wallet selected.</p>
            <p>Please select a wallet first to view DNA information.</p>
        `;
        return;
    }

    // Show loading state
    linkedDNAsElement.style.display = 'block';
    linkedDNAsElement.innerHTML = '<div class="loading">Loading DNA information...</div>';
    noDNAsElement.style.display = 'none';

    try {
        // Check if we already have dnaData from previous loading
        let currentDnaData = dnaData;

        if (!currentDnaData) {
            // Try to load the data if we don't have it yet
            if (typeof checkDnaRegistration === 'function') {
                await checkDnaRegistration();
                // Try to get the updated dnaData from window
                currentDnaData = window.dnaData;
            }
        }

        // If we still don't have data, show no DNAs message
        if (!currentDnaData) {
            linkedDNAsElement.style.display = 'none';
            noDNAsElement.style.display = 'block';
            return;
        }

        // Get the registered names from dnaData
        const registeredNames = currentDnaData.registered_names || {};
        const nicknames = Object.keys(registeredNames);

        if (nicknames.length === 0) {
            // No registered names found
            linkedDNAsElement.style.display = 'none';
            noDNAsElement.style.display = 'block';
            return;
        }

        // We have DNA data to display
        let dnaHTML = '';

        // For each nickname/DNA, create a display card
        nicknames.forEach(nickname => {
            const registrationData = registeredNames[nickname];
            const registrationDate = new Date(registrationData.registration_date * 1000).toLocaleDateString();
            const expirationDate = registrationData.expiration_date ?
                new Date(registrationData.expiration_date * 1000).toLocaleDateString() : 'N/A';

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

                        <span style="opacity: 0.7;">DNA Type:</span>
                        <span>${registrationData.type || 'Standard'}</span>

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

    } catch (error) {
        console.error('Error loading DNA information:', error);
        linkedDNAsElement.innerHTML = `<div class="error-message" style="color: var(--error); padding: 15px;">Error loading DNA information: ${error.message}</div>`;
    }
}

// Add global references to these functions
window.updateSocialCount = updateSocialCount;
window.showError = showError;
window.handleGoogleAuthCallback = handleGoogleAuthCallback;
window.handleLinkedInAuthCallback = handleLinkedInAuthCallback;
window.handleGitHubAuthCallback = handleGitHubAuthCallback;
window.loadDNAInformation = loadDNAInformation;

// Execute on document ready
document.addEventListener('DOMContentLoaded', loadLoginPage);