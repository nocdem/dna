// wallet-integration.js - Cryptocurrency wallet integration functionality

const WalletIntegration = (function() {
    'use strict';

    // Store external wallet addresses
    let externalWallets = {
        BTC: '',
        ETH: '',
        SOL: '',
        BNB: '',
        QEVM: ''
    };

    // Callback function for when wallets are updated
    let onWalletUpdateCallback = null;

    /**
     * Initialize the wallet integration module
     */
    function init(options = {}) {
        if (options.onWalletUpdate && typeof options.onWalletUpdate === 'function') {
            onWalletUpdateCallback = options.onWalletUpdate;
        }
        
        setupWalletButtons();
    }

    /**
     * Set external wallets data
     */
    function setExternalWallets(wallets) {
        if (wallets) {
            externalWallets.BTC = wallets.BTC || '';
            externalWallets.ETH = wallets.ETH || '';
            externalWallets.SOL = wallets.SOL || '';
            externalWallets.BNB = wallets.BNB || '';
            externalWallets.QEVM = wallets.QEVM || '';
            
            updateWalletUI(wallets);
        }
    }

    /**
     * Get external wallets data
     */
    function getExternalWallets() {
        return { ...externalWallets };
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
                updateWalletCount();
                
                // Trigger callback if provided
                if (onWalletUpdateCallback) {
                    onWalletUpdateCallback(externalWallets);
                }
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
                        updateWalletCount();
                        
                        // Trigger callback if provided
                        if (onWalletUpdateCallback) {
                            onWalletUpdateCallback(externalWallets);
                        }
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
                        updateWalletCount();
                        
                        // Trigger callback if provided
                        if (onWalletUpdateCallback) {
                            onWalletUpdateCallback(externalWallets);
                        }
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
                updateWalletCount();
                
                // Trigger callback if provided
                if (onWalletUpdateCallback) {
                    onWalletUpdateCallback(externalWallets);
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
                    updateWalletCount();
                    
                    // Trigger callback if provided
                    if (onWalletUpdateCallback) {
                        onWalletUpdateCallback(externalWallets);
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
                updateWalletCount();
                
                // Trigger callback if provided
                if (onWalletUpdateCallback) {
                    onWalletUpdateCallback(externalWallets);
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
        updateWalletCount();
    }

    /**
     * Update wallet count in UI
     */
    function updateWalletCount() {
        const walletsCount = document.getElementById('walletsCount');
        if (walletsCount) {
            const count = Object.values(externalWallets).filter(w => w && w.trim() !== '').length;
            walletsCount.textContent = count;
        }
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

    // Public API
    return {
        init: init,
        setExternalWallets: setExternalWallets,
        getExternalWallets: getExternalWallets,
        updateWalletUI: updateWalletUI,
        connectEthWallet: connectEthWallet,
        connectBtcWallet: connectBtcWallet,
        connectSolWallet: connectSolWallet,
        connectBnbWallet: connectBnbWallet
    };
})();