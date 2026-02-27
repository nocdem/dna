// social-integration.js - Social Account Integration functionality

const SocialIntegration = (function() {
    'use strict';
    
    // Private variables
    let walletAddress = null;
    let dnaData = null;
    
    // Set wallet address for social operations
    function setWalletAddress(address) {
        walletAddress = address;
    }
    
    // Set DNA data for social operations
    function setDnaData(data) {
        dnaData = data;
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
            
            // Process old format
            processSocialAccountsOldFormat(socialAccounts, connectedProfiles);
            
            // Update social summary box
            updateSocialSummary(connectedProfiles);
            
            // Exit early as we've handled the old format
            return;
        }
        
        // Process new format with socials.platform.profile structure
        processSocialAccountsNewFormat(socials, connectedProfiles);
        
        // Update social summary box
        updateSocialSummary(connectedProfiles);
        
        // Update the social count in the profile preview
        updateSocialCount();
    }
    
    /**
     * Process social accounts in old format
     */
    function processSocialAccountsOldFormat(socialAccounts, connectedProfiles) {
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
    }
    
    /**
     * Process social accounts in new format
     */
    function processSocialAccountsNewFormat(socials, connectedProfiles) {
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
        // Use correct parameter based on the OAuth provider
        let authParam = 'request=auth'; // Default for most providers
        if (oauthUrl.includes('twitter_oauth.php')) {
            authParam = 'auth=start'; // Twitter uses 'auth=start'
        }
        
        const authUrl = `${oauthUrl}?${authParam}&wallet=${encodeURIComponent(walletAddress)}`;
        
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
            if (window.checkDnaRegistration) {
                setTimeout(() => {
                    window.checkDnaRegistration();
                }, 2000);
            }
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
    
    // Public API
    return {
        init: function() {
            setupSocialButtons();
            setupDuplicateSocialButtons();
        },
        setWalletAddress: setWalletAddress,
        setDnaData: setDnaData,
        updateSocialProfiles: updateSocialProfiles,
        checkPendingTelegramVerification: checkPendingTelegramVerification
    };
})();

// Make it available globally if needed
window.SocialIntegration = SocialIntegration;