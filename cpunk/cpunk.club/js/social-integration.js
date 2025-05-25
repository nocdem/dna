/**
 * CPUNK Social Media Integration Module
 * Handles OAuth authentication and social media profile management
 */

const SocialIntegration = (function() {
    // Social media platforms configuration
    const SOCIAL_PLATFORMS = {
        twitter: { name: 'Twitter', icon: '🐦', color: '#1DA1F2' },
        github: { name: 'GitHub', icon: '🐙', color: '#333' },
        google: { name: 'Google', icon: '🔍', color: '#4285F4' },
        linkedin: { name: 'LinkedIn', icon: '💼', color: '#0077B5' },
        telegram: { name: 'Telegram', icon: '📱', color: '#0088cc' }
    };

    // OAuth URLs
    const OAUTH_URLS = {
        twitter: 'twitter_oauth.php',
        github: 'github_oauth.php',
        google: 'google_oauth.php',
        linkedin: 'linkedin_oauth.php'
    };

    // State variables
    let currentWalletAddress = null;
    let pendingVerifications = {};
    let socialProfiles = {};

    /**
     * Initialize social integration
     */
    function init(walletAddress) {
        currentWalletAddress = walletAddress;
        setupEventListeners();
        setupOAuthListener();
    }

    /**
     * Setup event listeners for social buttons
     */
    function setupEventListeners() {
        // Setup OAuth buttons
        document.querySelectorAll('[data-oauth-platform]').forEach(button => {
            button.addEventListener('click', function() {
                const platform = this.getAttribute('data-oauth-platform');
                verifyPlatform(platform);
            });
        });

        // Setup Telegram verification
        const telegramButton = document.getElementById('verifyTelegramButton');
        if (telegramButton) {
            telegramButton.addEventListener('click', openTelegramVerification);
        }
    }

    /**
     * Setup OAuth callback listener
     */
    function setupOAuthListener() {
        window.addEventListener('message', handleOAuthCallback);
    }

    /**
     * Verify a social media platform
     */
    function verifyPlatform(platform) {
        if (!currentWalletAddress) {
            alert('Please connect your wallet first');
            return;
        }

        if (platform === 'telegram') {
            openTelegramVerification();
        } else if (OAUTH_URLS[platform]) {
            const oauthUrl = `${OAUTH_URLS[platform]}?wallet=${encodeURIComponent(currentWalletAddress)}`;
            openOAuthPopup(oauthUrl, platform, currentWalletAddress);
        }
    }

    /**
     * Open OAuth popup window
     */
    function openOAuthPopup(oauthUrl, windowName, walletAddress) {
        const width = 600;
        const height = 700;
        const left = (screen.width - width) / 2;
        const top = (screen.height - height) / 2;
        
        const popup = window.open(
            oauthUrl, 
            windowName,
            `width=${width},height=${height},left=${left},top=${top},location=no,toolbar=no,menubar=no,scrollbars=yes,resizable=yes`
        );
        
        if (!popup) {
            console.error('Popup window was blocked or failed to open');
            alert('Please allow popups for this site to verify your social media accounts.');
            return;
        }
        
        // Store pending verification
        pendingVerifications[windowName] = {
            platform: windowName,
            walletAddress: walletAddress,
            popup: popup
        };
    }

    /**
     * Handle OAuth callback messages
     */
    function handleOAuthCallback(event) {
        // Security check - only accept messages from our domain
        if (event.origin !== window.location.origin) {
            console.warn('Received message from unknown origin', event.origin);
            return;
        }
        
        // Process OAuth response
        if (event.data && event.data.type === 'oauth-callback') {
            const { platform, success, data } = event.data;
            
            if (success) {
                handlePlatformSuccess(platform, data);
            } else {
                alert(`${platform} verification failed. Please try again.`);
            }
            
            // Close the popup if it exists
            if (pendingVerifications[platform] && pendingVerifications[platform].popup) {
                pendingVerifications[platform].popup.close();
                delete pendingVerifications[platform];
            }
        }
    }

    /**
     * Handle successful platform verification
     */
    function handlePlatformSuccess(platform, data) {
        switch(platform) {
            case 'twitter':
                handleTwitterSuccess(data);
                break;
            case 'github':
                handleGitHubSuccess(data);
                break;
            case 'google':
                handleGoogleSuccess(data);
                break;
            case 'linkedin':
                handleLinkedInSuccess(data);
                break;
        }
    }

    /**
     * Handle Twitter verification success
     */
    function handleTwitterSuccess(data) {
        if (data.twitter_handle) {
            updateSocialProfile('twitter', data.twitter_handle);
            showSuccessMessage('Twitter account verified successfully!');
        }
    }

    /**
     * Handle GitHub verification success
     */
    function handleGitHubSuccess(data) {
        if (data.github_username) {
            updateSocialProfile('github', data.github_username);
            showSuccessMessage('GitHub account verified successfully!');
        }
    }

    /**
     * Handle Google verification success
     */
    function handleGoogleSuccess(data) {
        if (data.email) {
            updateSocialProfile('google', data.email);
            showSuccessMessage('Google account verified successfully!');
        }
    }

    /**
     * Handle LinkedIn verification success
     */
    function handleLinkedInSuccess(data) {
        if (data.linkedin_id) {
            updateSocialProfile('linkedin', data.name || 'Connected');
            showSuccessMessage('LinkedIn account verified successfully!');
        }
    }

    /**
     * Open Telegram verification
     */
    function openTelegramVerification() {
        const telegramModal = document.getElementById('telegramVerificationModal');
        if (telegramModal) {
            telegramModal.style.display = 'block';
            generateTelegramInstructions();
        }
    }

    /**
     * Generate Telegram verification instructions
     */
    function generateTelegramInstructions() {
        const modalContent = document.querySelector('.telegram-modal-content');
        if (!modalContent) return;

        const verificationCode = `verify ${currentWalletAddress}`;
        
        modalContent.innerHTML = `
            <h3>Telegram Verification</h3>
            <div class="telegram-instructions">
                <p>To verify your Telegram account:</p>
                <ol>
                    <li>Open Telegram and search for <strong>@cpunkverifybot</strong></li>
                    <li>Send this exact message:</li>
                    <div class="code-box">
                        <code id="telegramCode">${verificationCode}</code>
                        <button onclick="SocialIntegration.copyTelegramCode()" class="copy-button">Copy</button>
                    </div>
                    <li>Enter your Telegram username below:</li>
                    <input type="text" id="telegramUsername" placeholder="@yourusername" class="telegram-input">
                    <button onclick="SocialIntegration.continueTelegramVerification()" class="verify-button">Continue Verification</button>
                </ol>
            </div>
            <button onclick="SocialIntegration.closeTelegramModal()" class="close-button">Cancel</button>
        `;
    }

    /**
     * Copy Telegram verification code
     */
    function copyTelegramCode() {
        const codeElement = document.getElementById('telegramCode');
        if (codeElement) {
            navigator.clipboard.writeText(codeElement.textContent)
                .then(() => alert('Verification code copied!'))
                .catch(err => console.error('Failed to copy:', err));
        }
    }

    /**
     * Continue Telegram verification
     */
    function continueTelegramVerification() {
        const usernameInput = document.getElementById('telegramUsername');
        const username = usernameInput ? usernameInput.value.trim() : '';
        
        if (!username) {
            alert('Please enter your Telegram username');
            return;
        }
        
        // Store pending verification
        localStorage.setItem('pendingTelegramVerification', JSON.stringify({
            username: username,
            walletAddress: currentWalletAddress,
            timestamp: Date.now()
        }));
        
        updateSocialProfile('telegram', username);
        showPendingStatus('telegram');
        closeTelegramModal();
        
        // Show additional instructions
        showTelegramInstructions(username);
    }

    /**
     * Show Telegram verification instructions
     */
    function showTelegramInstructions(username) {
        const instructionsHtml = `
            <div class="telegram-verification-instructions">
                <h4>Complete Your Telegram Verification</h4>
                <p>Now send this message to @cpunkverifybot on Telegram:</p>
                <div class="code-box">
                    <code>verify ${currentWalletAddress}</code>
                </div>
                <p>Your verification will be processed automatically.</p>
            </div>
        `;
        
        // Add to page or show in modal
        const container = document.getElementById('socialsList');
        if (container) {
            const div = document.createElement('div');
            div.innerHTML = instructionsHtml;
            container.insertBefore(div, container.firstChild);
        }
    }

    /**
     * Close Telegram modal
     */
    function closeTelegramModal() {
        const telegramModal = document.getElementById('telegramVerificationModal');
        if (telegramModal) {
            telegramModal.style.display = 'none';
        }
    }

    /**
     * Update social profile
     */
    function updateSocialProfile(platform, value) {
        socialProfiles[platform] = value;
        
        // Update UI elements
        const elements = document.querySelectorAll(`[data-social-platform="${platform}"]`);
        elements.forEach(element => {
            element.textContent = value;
            element.classList.add('verified');
        });
        
        // Update form inputs
        const input = document.getElementById(`${platform}Profile`);
        if (input) {
            input.value = value;
        }
        
        // Trigger save if callback is set
        if (window.onSocialProfileUpdate) {
            window.onSocialProfileUpdate(platform, value);
        }
    }

    /**
     * Show success message
     */
    function showSuccessMessage(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'success-message';
        messageDiv.textContent = message;
        messageDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #4CAF50;
            color: white;
            padding: 15px 20px;
            border-radius: 5px;
            z-index: 10000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(messageDiv);
        
        setTimeout(() => {
            messageDiv.remove();
        }, 3000);
    }

    /**
     * Show pending status
     */
    function showPendingStatus(platform) {
        const statusElement = document.querySelector(`[data-social-status="${platform}"]`);
        if (statusElement) {
            statusElement.innerHTML = '<span class="pending-badge">Verification Pending</span>';
        }
    }

    /**
     * Check pending Telegram verification
     */
    function checkPendingTelegramVerification() {
        const pending = localStorage.getItem('pendingTelegramVerification');
        if (pending) {
            try {
                const data = JSON.parse(pending);
                // Check if verification is less than 24 hours old
                if (Date.now() - data.timestamp < 24 * 60 * 60 * 1000) {
                    showTelegramInstructions(data.username);
                } else {
                    // Remove expired verification
                    localStorage.removeItem('pendingTelegramVerification');
                }
            } catch (e) {
                localStorage.removeItem('pendingTelegramVerification');
            }
        }
    }

    /**
     * Update social profiles from API data
     */
    function updateFromApiData(data) {
        if (data.socials) {
            Object.keys(data.socials).forEach(platform => {
                if (data.socials[platform]) {
                    updateSocialProfile(platform, data.socials[platform]);
                }
            });
        }
    }

    /**
     * Get current social profiles
     */
    function getSocialProfiles() {
        return socialProfiles;
    }

    // Public API
    return {
        init: init,
        verifyPlatform: verifyPlatform,
        updateFromApiData: updateFromApiData,
        getSocialProfiles: getSocialProfiles,
        checkPendingTelegramVerification: checkPendingTelegramVerification,
        copyTelegramCode: copyTelegramCode,
        continueTelegramVerification: continueTelegramVerification,
        closeTelegramModal: closeTelegramModal
    };
})();

// Make it globally available
window.SocialIntegration = SocialIntegration;