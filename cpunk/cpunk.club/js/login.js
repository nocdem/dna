// Login Page JavaScript - SSO Integration
(function() {
    'use strict';

    // State
    let selectedWalletData = null;
    let selectedDnaName = null;

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        // Check if already authenticated
        const sso = CpunkSSO.getInstance();
        sso.init({
            onAuthenticated: (user) => {
                // Already logged in - redirect to requested page or settings
                const redirect = new URLSearchParams(window.location.search).get('redirect') || 'settings.html';
                window.location.href = redirect;
            },
            onUnauthenticated: () => {
                // Not logged in - show login interface
                console.log('User not authenticated - showing login interface');
            },
            updateNavbar: true
        });

        // Initialize CpunkDashboard with proper configuration
        CpunkDashboard.init({
            onConnected: handleConnected,
            onWalletSelected: handleWalletSelected,
            onDnaSelected: handleDnaSelected,
            onError: handleError
        });

        // Set up login button
        const loginButton = document.getElementById('loginButton');
        if (loginButton) {
            loginButton.addEventListener('click', performLogin);
        }
    });

    // Handle successful connection
    function handleConnected(sessionId) {
        console.log('Connected to dashboard:', sessionId);
        // Wallet section will be shown automatically by dashboardConnector
    }

    // Handle wallet selection
    function handleWalletSelected(walletData) {
        console.log('Wallet selected:', walletData);
        selectedWalletData = walletData;
        // DNA section will be shown automatically by dashboardConnector
    }

    // Handle DNA selection  
    function handleDnaSelected(dnaData) {
        console.log('DNA selected:', dnaData);
        // Extract DNA name if it's an object
        if (typeof dnaData === 'object' && dnaData !== null) {
            selectedDnaName = dnaData.name || dnaData.dna || dnaData.toString();
        } else {
            selectedDnaName = dnaData;
        }
        
        // Show login button when both wallet and DNA are selected
        const loginSection = document.getElementById('loginSection');
        if (loginSection && selectedWalletData && selectedDnaName) {
            loginSection.style.display = 'block';
        }
    }

    // Handle errors
    function handleError(error) {
        console.error('Dashboard error:', error);
    }

    // Perform login
    function performLogin() {
        if (!selectedWalletData || !selectedDnaName) {
            alert('Please select both wallet and DNA');
            return;
        }

        const loginButton = document.getElementById('loginButton');
        loginButton.disabled = true;
        loginButton.textContent = 'Logging in...';

        try {
            // Get dashboard session ID
            const sessionId = sessionStorage.getItem('cpunk_dashboard_session');
            
            // Save authentication data using SSO module
            const sso = CpunkSSO.getInstance();
            sso.saveSession({
                sessionId: sessionId,
                wallet: selectedWalletData.address,
                dna: selectedDnaName,
                walletData: selectedWalletData
            });

            // Log for debugging
            console.log('Login successful, saved to SSO:', {
                wallet: selectedWalletData.address,
                dna: selectedDnaName
            });

            // Redirect to requested page or settings
            const redirect = new URLSearchParams(window.location.search).get('redirect') || 'settings.html';
            window.location.href = redirect;

        } catch (error) {
            console.error('Login error:', error);
            alert('Login failed: ' + error.message);
            loginButton.disabled = false;
            loginButton.textContent = 'Complete Login';
        }
    }

})();