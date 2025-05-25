/**
 * CPUNK External Wallet Integration Module
 * Handles Bitcoin, Ethereum, Solana, BNB, and other external wallet connections
 */

const WalletIntegration = (function() {
    // Supported wallet types
    const WALLET_TYPES = {
        BTC: { name: 'Bitcoin', symbol: '₿', color: '#F7931A' },
        ETH: { name: 'Ethereum', symbol: 'Ξ', color: '#627EEA' },
        SOL: { name: 'Solana', symbol: '◎', color: '#14F195' },
        BNB: { name: 'BNB Chain', symbol: 'B', color: '#F3BA2F' },
        QEVM: { name: 'QEVM', symbol: 'Q', color: '#5B21B6' }
    };

    // External wallet addresses
    let externalWallets = {
        BTC: '',
        ETH: '',
        SOL: '',
        BNB: '',
        QEVM: ''
    };

    // State variables
    let currentWalletAddress = null;
    let onWalletUpdateCallback = null;

    /**
     * Initialize wallet integration
     */
    function init(walletAddress, onUpdate) {
        currentWalletAddress = walletAddress;
        onWalletUpdateCallback = onUpdate;
        setupEventListeners();
        loadSavedWallets();
    }

    /**
     * Setup event listeners for wallet buttons
     */
    function setupEventListeners() {
        // Manual wallet connection buttons
        document.querySelectorAll('[data-wallet-type]').forEach(button => {
            button.addEventListener('click', function() {
                const walletType = this.getAttribute('data-wallet-type');
                handleManualWalletConnection(walletType);
            });
        });

        // Web3 wallet connection buttons
        setupWeb3Wallets();
    }

    /**
     * Setup Web3 wallet connections
     */
    function setupWeb3Wallets() {
        // MetaMask (Ethereum)
        const connectMetaMaskBtn = document.getElementById('connectMetaMask');
        if (connectMetaMaskBtn) {
            connectMetaMaskBtn.addEventListener('click', connectMetaMask);
        }

        // Phantom (Solana)
        const connectPhantomBtn = document.getElementById('connectPhantom');
        if (connectPhantomBtn) {
            connectPhantomBtn.addEventListener('click', connectPhantom);
        }

        // Trust Wallet
        const connectTrustBtn = document.getElementById('connectTrust');
        if (connectTrustBtn) {
            connectTrustBtn.addEventListener('click', connectTrustWallet);
        }
    }

    /**
     * Connect MetaMask wallet
     */
    async function connectMetaMask() {
        if (typeof window.ethereum === 'undefined') {
            alert('MetaMask is not installed. Please install MetaMask to connect your Ethereum wallet.');
            return;
        }

        try {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            if (accounts.length > 0) {
                const address = accounts[0];
                updateWallet('ETH', address);
                showSuccessMessage('MetaMask wallet connected successfully!');
            }
        } catch (error) {
            console.error('MetaMask connection error:', error);
            alert('Failed to connect MetaMask. Please try again.');
        }
    }

    /**
     * Connect Phantom wallet
     */
    async function connectPhantom() {
        if (!window.solana || !window.solana.isPhantom) {
            alert('Phantom wallet is not installed. Please install Phantom to connect your Solana wallet.');
            return;
        }

        try {
            const response = await window.solana.connect();
            const address = response.publicKey.toString();
            updateWallet('SOL', address);
            showSuccessMessage('Phantom wallet connected successfully!');
        } catch (error) {
            console.error('Phantom connection error:', error);
            alert('Failed to connect Phantom. Please try again.');
        }
    }

    /**
     * Connect Trust Wallet
     */
    async function connectTrustWallet() {
        // Trust Wallet can connect for multiple chains
        const modal = createWalletSelectionModal();
        document.body.appendChild(modal);
    }

    /**
     * Create wallet selection modal
     */
    function createWalletSelectionModal() {
        const modal = document.createElement('div');
        modal.className = 'wallet-modal';
        modal.innerHTML = `
            <div class="wallet-modal-content">
                <h3>Select Wallet Type</h3>
                <div class="wallet-options">
                    <button onclick="WalletIntegration.connectTrustForChain('ETH')" class="wallet-option">
                        <span class="wallet-icon">Ξ</span>
                        <span>Ethereum</span>
                    </button>
                    <button onclick="WalletIntegration.connectTrustForChain('BNB')" class="wallet-option">
                        <span class="wallet-icon">B</span>
                        <span>BNB Chain</span>
                    </button>
                    <button onclick="WalletIntegration.connectTrustForChain('SOL')" class="wallet-option">
                        <span class="wallet-icon">◎</span>
                        <span>Solana</span>
                    </button>
                </div>
                <button onclick="this.parentElement.parentElement.remove()" class="close-button">Cancel</button>
            </div>
        `;
        return modal;
    }

    /**
     * Connect Trust Wallet for specific chain
     */
    async function connectTrustForChain(chain) {
        // Close modal
        document.querySelector('.wallet-modal')?.remove();

        switch(chain) {
            case 'ETH':
            case 'BNB':
                if (window.ethereum && window.ethereum.isTrust) {
                    try {
                        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                        if (accounts.length > 0) {
                            updateWallet(chain, accounts[0]);
                            showSuccessMessage(`Trust Wallet (${chain}) connected successfully!`);
                        }
                    } catch (error) {
                        alert(`Failed to connect Trust Wallet for ${chain}`);
                    }
                } else {
                    alert('Trust Wallet is not available');
                }
                break;
            case 'SOL':
                if (window.solana && window.solana.isTrust) {
                    try {
                        const response = await window.solana.connect();
                        updateWallet('SOL', response.publicKey.toString());
                        showSuccessMessage('Trust Wallet (Solana) connected successfully!');
                    } catch (error) {
                        alert('Failed to connect Trust Wallet for Solana');
                    }
                } else {
                    handleManualWalletConnection('SOL');
                }
                break;
        }
    }

    /**
     * Handle manual wallet connection
     */
    function handleManualWalletConnection(walletType) {
        const currentAddress = externalWallets[walletType] || '';
        const walletName = WALLET_TYPES[walletType]?.name || walletType;
        
        const address = prompt(`Enter your ${walletName} wallet address:`, currentAddress);
        
        if (address && address.trim()) {
            if (validateWalletAddress(walletType, address.trim())) {
                updateWallet(walletType, address.trim());
                showSuccessMessage(`${walletName} wallet updated successfully!`);
            } else {
                alert(`Invalid ${walletName} wallet address format.`);
            }
        }
    }

    /**
     * Validate wallet address format
     */
    function validateWalletAddress(walletType, address) {
        const patterns = {
            BTC: /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/,
            ETH: /^0x[a-fA-F0-9]{40}$/,
            SOL: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
            BNB: /^0x[a-fA-F0-9]{40}$/,
            QEVM: /^0x[a-fA-F0-9]{40}$/
        };
        
        return patterns[walletType] ? patterns[walletType].test(address) : true;
    }

    /**
     * Update wallet address
     */
    function updateWallet(walletType, address) {
        externalWallets[walletType] = address;
        
        // Update UI
        updateWalletUI();
        
        // Save to localStorage
        saveWallets();
        
        // Trigger callback
        if (onWalletUpdateCallback) {
            onWalletUpdateCallback(walletType, address);
        }
    }

    /**
     * Update wallet UI
     */
    function updateWalletUI() {
        Object.keys(externalWallets).forEach(walletType => {
            const address = externalWallets[walletType];
            
            // Update display elements
            const displayElements = document.querySelectorAll(`[data-wallet-display="${walletType}"]`);
            displayElements.forEach(element => {
                if (address) {
                    element.textContent = `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
                    element.classList.add('connected');
                } else {
                    element.textContent = 'Not connected';
                    element.classList.remove('connected');
                }
            });
            
            // Update input fields
            const inputElement = document.getElementById(`${walletType.toLowerCase()}Address`);
            if (inputElement) {
                inputElement.value = address || '';
            }
            
            // Update buttons
            const connectButton = document.querySelector(`[data-wallet-connect="${walletType}"]`);
            if (connectButton) {
                connectButton.textContent = address ? 'Change' : 'Connect';
            }
        });
        
        // Update wallet count
        const connectedCount = Object.values(externalWallets).filter(addr => addr).length;
        const countElement = document.getElementById('walletsCount');
        if (countElement) {
            countElement.textContent = connectedCount;
        }
    }

    /**
     * Save wallets to localStorage
     */
    function saveWallets() {
        localStorage.setItem('cpunkExternalWallets', JSON.stringify(externalWallets));
    }

    /**
     * Load saved wallets from localStorage
     */
    function loadSavedWallets() {
        const saved = localStorage.getItem('cpunkExternalWallets');
        if (saved) {
            try {
                const wallets = JSON.parse(saved);
                Object.assign(externalWallets, wallets);
                updateWalletUI();
            } catch (e) {
                console.error('Failed to load saved wallets:', e);
            }
        }
    }

    /**
     * Update from API data
     */
    function updateFromApiData(data) {
        if (data.dinosaur_wallets) {
            Object.keys(data.dinosaur_wallets).forEach(walletType => {
                if (data.dinosaur_wallets[walletType]) {
                    externalWallets[walletType] = data.dinosaur_wallets[walletType];
                }
            });
            updateWalletUI();
        }
    }

    /**
     * Get current wallet addresses
     */
    function getWallets() {
        return { ...externalWallets };
    }

    /**
     * Clear all wallet connections
     */
    function clearAllWallets() {
        externalWallets = {
            BTC: '',
            ETH: '',
            SOL: '',
            BNB: '',
            QEVM: ''
        };
        updateWalletUI();
        saveWallets();
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

    // Public API
    return {
        init: init,
        updateWallet: updateWallet,
        getWallets: getWallets,
        updateFromApiData: updateFromApiData,
        clearAllWallets: clearAllWallets,
        connectTrustForChain: connectTrustForChain
    };
})();

// Make it globally available
window.WalletIntegration = WalletIntegration;