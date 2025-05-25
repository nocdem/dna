// login.js - Core functionality for the login page

/**
 * Profile link update functionality
 * - Updates the profile link with the DNA nickname
 */
document.addEventListener('DOMContentLoaded', function() {
    // Will run after main user_settings.js is loaded
    const originalUpdateProfilePreview = window.updateProfilePreview || function() {};

    // Override or extend the updateProfilePreview function if it exists
    window.updateProfilePreview = function(data) {
        // Call the original function if it exists
        if (typeof originalUpdateProfilePreview === 'function') {
            originalUpdateProfilePreview(data);
        }

        // Update the profile link with DNA nickname
        const profileLink = document.getElementById('profileLink');
        if (profileLink && data) {
            const registeredNames = data.registered_names || {};
            const nicknames = Object.keys(registeredNames);
            const primaryNickname = nicknames.length > 0 ? nicknames[0] : '';

            if (primaryNickname) {
                profileLink.href = `https://cpunk.club/${primaryNickname}`;
            } else {
                profileLink.href = '#';
            }
        }
    };
});

// API hooks and initialization
(function() {
    // Wait for API Console to be available
    let apiConsoleReady = false;

    function checkAPIConsole() {
        if (window.CpunkAPIConsole) {
            // API Console is available, initialize it
            apiConsoleReady = true;
            return true;
        }
        return false;
    }

    // Check if API Console is already available
    if (!checkAPIConsole()) {
        // Set up a small interval to check for API Console
        const checkInterval = setInterval(() => {
            if (checkAPIConsole()) {
                clearInterval(checkInterval);
                monkeyPatchFetch();
            }
        }, 100);

        // Safety timeout after 2 seconds
        setTimeout(() => {
            clearInterval(checkInterval);
            if (!apiConsoleReady) {
                console.error('API Console not available after timeout');
            }
        }, 2000);
    } else {
        monkeyPatchFetch();
    }

    function monkeyPatchFetch() {
        // Store original fetch for monkey patching
        const originalFetch = window.fetch;

        // Override fetch to log requests and responses
        window.fetch = async function(...args) {
            const url = args[0];
            const options = args[1] || {};
            const requestTime = new Date().toISOString();

            // Skip tracking for non-API calls like navbar template fetch
            if (url && !url.includes('navbar-template.html') && !url.includes('.css') && !url.includes('.js')) {
                // Extract API info
                try {
                    // Log to API Console using the global logAPI function
                    if (window.logAPI) {
                        window.logAPI('API Request: ' + url, {
                            url: url,
                            method: options.method || 'GET',
                            headers: options.headers || {},
                            body: options.body || null
                        });
                    } else {
                        if (window.logAPI) window.logAPI('[API Request]', {url, options});
                    }
                } catch (err) {
                    console.error('Error logging request:', err);
                }
            }

            // Execute the original fetch
            try {
                const response = await originalFetch.apply(this, args);

                // Clone the response before reading it
                if (url && !url.includes('navbar-template.html') && !url.includes('.css') && !url.includes('.js')) {
                    const responseTime = new Date().toISOString();
                    const clonedResponse = response.clone();

                    // Handle response based on content type
                    clonedResponse.text().then(text => {
                        let responseData;

                        try {
                            // Try to parse JSON
                            responseData = JSON.parse(text);
                        } catch (e) {
                            // Not JSON, use text
                            responseData = text;
                        }

                        // Log to API Console using the global logAPI function
                        if (window.logAPI) {
                            window.logAPI('API Response: ' + url, {
                                url: url,
                                method: options.method || 'GET',
                                timestamp: responseTime,
                                data: responseData,
                                status: "success"
                            });
                        } else {
                            console.log('[API Response]', url, responseData);
                        }
                    }).catch(err => {
                        console.error('Error parsing response:', err);
                    });
                }

                return response;
            } catch (error) {
                // Log fetch errors
                if (url && !url.includes('navbar-template.html') && !url.includes('.css') && !url.includes('.js')) {
                    if (window.logAPI) {
                        window.logAPI('API Error: ' + url, {
                            url: url,
                            method: options.method || 'GET',
                            timestamp: new Date().toISOString(),
                            error: error.message
                        });
                    } else {
                        console.error('[API Error]', url, error);
                    }
                }
                throw error;
            }
        };

        console.log('Fetch successfully monkey patched for API tracking');
    }
})();

// General message handler for backward compatibility
document.addEventListener('DOMContentLoaded', function() {
    window.addEventListener('message', function(event) {
        // Always check origin for security
        if (event.origin !== window.location.origin) {
            console.warn('Received message from unknown origin', event.origin);
            return;
        }

        // Handle Twitter OAuth success
        if (event.data && event.data.type && event.data.type === 'twitter_auth_success') {
            // Handle Twitter auth success
            console.log('Twitter authentication successful:', event.data);
            // Update social count after verification
            setTimeout(updateSocialCount, 500);
        }

        // Handle GitHub OAuth success (for redundancy/backward compatibility)
        if (event.data && event.data.type && event.data.type === 'github_auth_success') {
            console.log('GitHub authentication successful (general handler):', event.data);

            // Capture GitHub data for persistence
            try {
                localStorage.setItem('github_oauth_backup', JSON.stringify({
                    timestamp: Date.now(),
                    username: event.data.username || '',
                    name: event.data.name || ''
                }));
            } catch (e) {
                console.error('[DEBUG] Error storing GitHub backup data', e);
            }

            // Update GitHub UI
            const githubProfileInput = document.getElementById('githubProfile');
            const githubVerificationStatus = document.getElementById('githubVerificationStatus');
            const connectGitHubButton = document.getElementById('connectGitHubButton');

            if (githubProfileInput) githubProfileInput.value = event.data.username || '';

            if (githubVerificationStatus) {
                githubVerificationStatus.innerHTML = `
                    <div class="status-circle status-verified"></div>
                    <span class="status-text">Verified</span>
                `;
            }

            if (connectGitHubButton) {
                connectGitHubButton.style.display = 'none';
                connectGitHubButton.disabled = true;
            }

            // Update social count
            setTimeout(updateSocialCount, 500);
        }

        // Handle Google OAuth success
        if (event.data && event.data.type && event.data.type === 'google_auth_success') {
            console.log('Google authentication successful:', event.data);

            // Update UI to show the connected Google account
            const googleProfileInput = document.getElementById('googleProfile');
            const googleVerificationStatus = document.getElementById('googleVerificationStatus');
            const email = event.data.email;

            if (googleProfileInput && email) {
                googleProfileInput.value = email;

                // Update verification status (similar to Twitter)
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
            }

            // Update social count after verification
            setTimeout(updateSocialCount, 500);

            // Refresh data to get latest changes (follow Twitter's approach)
            checkDnaRegistration();
        }

        // Handle LinkedIn OAuth success
        if (event.data && event.data.type && event.data.type === 'linkedin_auth_success') {
            console.log('LinkedIn authentication successful:', event.data);

            // Update UI to show the connected LinkedIn account
            const linkedinProfileInput = document.getElementById('linkedinProfile');
            const linkedinVerificationStatus = document.getElementById('linkedinVerificationStatus');
            const profile = event.data.profile;

            if (linkedinProfileInput && profile) {
                linkedinProfileInput.value = profile;

                // Update verification status
                if (linkedinVerificationStatus) {
                    linkedinVerificationStatus.innerHTML = `
                        <div class="status-circle status-verified"></div>
                        <span class="status-text">Verified</span>
                    `;
                }

                // Hide the LinkedIn button after successful connection
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
            }

            // Update social count after verification
            setTimeout(updateSocialCount, 500);

            // Refresh data to get latest changes
            checkDnaRegistration();
        }

        // Handle OAuth errors (Twitter, Google, LinkedIn, GitHub)
        if (event.data && event.data.type && (
            event.data.type === 'twitter_auth_error' ||
            event.data.type === 'google_auth_error' ||
            event.data.type === 'linkedin_auth_error' ||
            event.data.type === 'github_auth_error'
        )) {
            console.error('OAuth error:', event.data);

            // For LinkedIn errors, show more detailed error information
            if (event.data.type === 'linkedin_auth_error' && event.data.error_description) {
                showError('LinkedIn Auth Error: ' + event.data.error + ' - ' + event.data.error_description);
            } else {
                showError('Authentication error: ' + (event.data.error || 'Unknown error'));
            }
        }
    });
});