/**
 * CPUNK DNA Messaging System
 * A secure messaging interface for DNA users
 */

// Debug library
const CpunkDebug = {
    enabled: true,  // Enable debug messages
    
    // Simple logging methods that forward to console
    log: function(message, data) {
        if (!this.enabled) return;
        if (window.logAPI) window.logAPI('[DEBUG] ' + message, data);
    },
    
    info: function(message, data) {
        if (!this.enabled) return;
        console.info('[INFO]', message, data || '');
    },
    
    warn: function(message, data) {
        if (!this.enabled) return;
        console.warn('[WARN]', message, data || '');
    },
    
    error: function(message, data) {
        if (!this.enabled) return;
        console.error('[ERROR]', message, data || '');
    },
    
    logWallet: function(stage, walletData) {
        if (!this.enabled) return;
        if (window.logAPI) window.logAPI('[WALLET] ' + stage, walletData);
    }
};

// Config
const DNA_PROXY_URL = 'dna-proxy.php';
const REFRESH_INTERVAL = 30000; // 30 seconds refresh

// No backward compatibility needed

// State
let currentUser = {
    dna: null,
    wallet: null,
    displayName: null
};
let conversations = [];
let currentConversation = null;
let messages = [];
let refreshTimer = null;

// DOM Elements (initialized in DOMContentLoaded)
let statusIndicator;
let connectButton;
let connectionError;
let walletSection;
let walletsList;
let walletError;
let dnaSection;
let dnaList;
let dnaError;

let userAvatar;
let userName;
let contactAvatar;
let contactName;
let contactStatus;
let conversationsList;
let messagesContainer;
let messageInput;
let sendButton;
let searchInput;
let searchButton;
let placeholderMessage;
let messageInputContainer;
let chatHeader;
let recipientValidation;
let recipientDna;
let startConversationButton;
let newConversationModal;

// Wait for document to load
document.addEventListener('DOMContentLoaded', function() {
    
    // Initialize utilities
    if (typeof CpunkUtils !== 'undefined') {
        CpunkUtils.init();
    }
    
    // Initialize DOM elements - Dashboard
    statusIndicator = document.getElementById('statusIndicator');
    connectButton = document.getElementById('connectButton');
    connectionError = document.getElementById('connectionError');
    walletSection = document.getElementById('walletSection');
    walletsList = document.getElementById('walletsList');
    walletError = document.getElementById('walletError');
    dnaSection = document.getElementById('dnaSection');
    dnaList = document.getElementById('dnaList');
    dnaError = document.getElementById('dnaError');
    
    // Initialize DOM elements - Messaging
    userAvatar = document.getElementById('userAvatar');
    userName = document.getElementById('userName');
    contactAvatar = document.getElementById('contactAvatar');
    contactName = document.getElementById('contactName');
    contactStatus = document.getElementById('contactStatus');
    conversationsList = document.getElementById('conversationsList');
    messagesContainer = document.getElementById('messagesContainer');
    messageInput = document.getElementById('messageInput');
    sendButton = document.getElementById('sendButton');
    searchInput = document.getElementById('searchInput');
    searchButton = document.getElementById('searchButton');
    placeholderMessage = document.querySelector('.placeholder-message');
    messageInputContainer = document.getElementById('messageInputContainer');
    chatHeader = document.getElementById('chatHeader');
    recipientValidation = document.getElementById('recipientValidation');
    recipientDna = document.getElementById('recipientDna');
    startConversationButton = document.getElementById('startConversationButton');
    newConversationModal = document.getElementById('newConversationModal');
    
    // Initialize Dashboard connector
    initDashboard();
    
    // Set up event listeners
    setupEventListeners();
});

/**
 * Initialize dashboard connector
 */
function initDashboard() {
    if (typeof CpunkDashboard === 'undefined') {
        console.error('CpunkDashboard not found');
        showError('Dashboard connector not loaded', 'connectionError');
        return;
    }
    
    CpunkDashboard.init({
        onConnected: function(sessionId) {
            // Show wallet selection after connection
            if (walletSection) walletSection.style.display = 'block';
        },
        onWalletSelected: function(wallet) {
            // Process wallet selection
            if (wallet && wallet.address) {
            }
        },
        onDnaSelected: async function(dna) {
            CpunkDebug.info('DNA selected:', dna);
            
            // Store user information with properly formatted wallet address
            let walletAddress = dna.wallet;
            
            // Debug the incoming wallet value
            CpunkDebug.error('Raw incoming wallet from dashboardConnector:', dna.wallet);
            
            // Log initial wallet value
            CpunkDebug.logWallet('Initial wallet value', walletAddress);
            
            // If it's an object with network and address properties, extract just the address
            if (typeof walletAddress === 'object' && walletAddress !== null) {
                CpunkDebug.log('Wallet object detected, attempting to extract address');
                
                // Handle different possible wallet object formats
                if (walletAddress.address) {
                    CpunkDebug.log('Found direct address property', walletAddress.address);
                    walletAddress = walletAddress.address;
                } else if (walletAddress.data && Array.isArray(walletAddress.data) && walletAddress.data.length > 0) {
                    // Try to find an address in the wallet data array
                    CpunkDebug.log('Examining wallet.data array', walletAddress.data);
                    const firstNetwork = walletAddress.data[0];
                    if (firstNetwork && firstNetwork.address) {
                        CpunkDebug.log('Found address in first network data', firstNetwork.address);
                        walletAddress = firstNetwork.address;
                    }
                }
                
                CpunkDebug.logWallet('After object extraction', walletAddress);
            }
            
            // Ensure address is a string
            if (typeof walletAddress !== 'string') {
                CpunkDebug.warn('Wallet address is not a string, converting', typeof walletAddress);
                walletAddress = String(walletAddress);
            }
            
            // Strip any surrounding quotes
            const beforeQuoteStrip = walletAddress;
            walletAddress = walletAddress.replace(/^["'](.*)["']$/, '$1');
            if (beforeQuoteStrip !== walletAddress) {
                CpunkDebug.log('Removed surrounding quotes', {before: beforeQuoteStrip, after: walletAddress});
            }
            
            // Clean the string - remove any non-alphanumeric characters except specific allowed ones
            const beforeClean = walletAddress;
            walletAddress = walletAddress.replace(/[^\w\-:.+]/g, '');
            if (beforeClean !== walletAddress) {
                CpunkDebug.log('Cleaned wallet address', {before: beforeClean, after: walletAddress});
            }
            
            CpunkDebug.logWallet('Final wallet address', walletAddress);
            
            currentUser = {
                dna: dna.name,
                wallet: walletAddress,
                displayName: dna.name
            };
            
            // Hide wallet and DNA sections
            if (walletSection) walletSection.style.display = 'none';
            if (dnaSection) dnaSection.style.display = 'none';
            
            // Hide connection section and intro text
            const connectionSection = document.getElementById('connectionSection');
            if (connectionSection) connectionSection.style.display = 'none';
            
            // Hide info section (the explanatory text)
            const infoSection = document.querySelector('.info-section');
            if (infoSection) infoSection.style.display = 'none';
            
            // Optionally make page title smaller for more space
            const pageTitle = document.querySelector('h1');
            if (pageTitle) {
                pageTitle.style.fontSize = '1.5em';
                pageTitle.style.margin = '10px 0';
            }
            
            // Show messaging UI
            document.getElementById('messagingSection').style.display = 'block';
            
            // Update user profile
            updateUserProfile();
            
            // Load conversations
            await loadConversations();
            
            // Set up auto-refresh
            setupAutoRefresh();
        },
        onError: function(message) {
            console.error('Dashboard error:', message);
            showError(message, 'connectionError');
        }
    });
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Search functionality
    if (searchButton) {
        searchButton.addEventListener('click', searchDna);
    }
    
    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                searchDna();
            }
        });
    }
    
    // Message sending
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }
    
    if (sendButton) {
        sendButton.addEventListener('click', sendMessage);
    }
    
    // Refresh button
    const refreshButton = document.getElementById('refreshButton');
    if (refreshButton) {
        refreshButton.addEventListener('click', refreshMessages);
    }
    
    // New message button
    const newMessageButton = document.getElementById('newMessageButton');
    if (newMessageButton) {
        newMessageButton.addEventListener('click', showNewConversationModal);
    }
    
    // Modal handlers
    const modalClose = document.querySelector('.modal-close');
    if (modalClose) {
        modalClose.addEventListener('click', hideNewConversationModal);
    }
    
    if (startConversationButton) {
        startConversationButton.addEventListener('click', startConversation);
    }
    
    if (recipientDna) {
        recipientDna.addEventListener('input', validateRecipient);
    }
    
    // Close modal on click outside
    window.addEventListener('click', function(event) {
        if (event.target === newConversationModal) {
            hideNewConversationModal();
        }
    });
}

/**
 * Update user profile in UI
 */
function updateUserProfile() {
    if (!currentUser.dna) return;
    
    // Set user name
    if (userName) {
        userName.textContent = currentUser.dna;
    }
    
    // Set user avatar (first letter of DNA)
    if (userAvatar) {
        userAvatar.textContent = currentUser.dna.charAt(0).toUpperCase();
    }
    
}

/**
 * Set up auto-refresh for messages
 */
function setupAutoRefresh() {
    // Clear any existing timer
    if (refreshTimer) {
        clearInterval(refreshTimer);
    }
    
    // Set up new timer
    refreshTimer = setInterval(async () => {
        if (currentConversation) {
            await refreshMessages();
        }
    }, REFRESH_INTERVAL);
    
}

/**
 * Load conversations for the current user
 */
async function loadConversations() {
    if (!currentUser.dna) {
        CpunkDebug.warn('Cannot load conversations, user DNA not set');
        return;
    }
    
    try {
        setLoading(true);
        
        CpunkDebug.info('Loading conversations for user:', currentUser.dna);
        // Log current user state
        CpunkDebug.log('Current user state:', currentUser);
        
        // Get conversations from the DNA API
        const result = await dnaLookup('messages', currentUser.dna);
        
        // Process the result (could be string or object)
        if (typeof result === 'string') {
            if (result.includes('no messages') || result.includes('not found')) {
                conversations = [];
                CpunkDebug.log('No conversations found');
            } else {
                try {
                    // Try to parse JSON (some endpoints return JSON as string)
                    conversations = JSON.parse(result);
                    CpunkDebug.log('Conversations loaded:', conversations.length);
                } catch (e) {
                    CpunkDebug.error('Failed to parse conversations:', e);
                    conversations = [];
                }
            }
        } else if (result && typeof result === 'object') {
            CpunkDebug.log('Received conversation data:', result);
            
            // Check for messages in the result
            if (result.messages && Array.isArray(result.messages)) {
                // Store original messages for reference
                const originalMessages = [...result.messages];
                
                // Group messages by conversation partner
                const messagesMap = {};
                
                originalMessages.forEach(message => {
                    // Check for required fields
                    if (!message || !message.s_dna || !message.r_dna) {
                        CpunkDebug.warn('Skipping invalid message:', message);
                        return;
                    }
                    
                    CpunkDebug.log('Processing message for conversation grouping:', {
                        s_dna: message.s_dna,
                        r_dna: message.r_dna,
                        currentUser: currentUser.dna
                    });
                    
                    // Determine the other party 
                    let otherParty, key;
                    
                    if (message.s_dna === currentUser.dna) {
                        // Current user is the sender, so recipient is other party
                        otherParty = message.r_dna;
                        key = `${message.s_dna}:${message.r_dna}`;
                    } else if (message.r_dna === currentUser.dna) {
                        // Current user is the recipient, so sender is other party
                        otherParty = message.s_dna;
                        key = `${message.r_dna}:${message.s_dna}`;
                    } else {
                        // This message doesn't involve the current user - shouldn't happen but handle it
                        CpunkDebug.warn('Message does not involve current user, skipping:', message);
                        return;
                    }
                    
                    // Convert timestamp to a reliable date
                    let timestamp;
                    if (message.timestamp) {
                        const timestampNum = Number(message.timestamp);
                        if (!isNaN(timestampNum)) {
                            timestamp = new Date(timestampNum * 1000);
                        } else {
                            timestamp = new Date(); // Fallback to current time
                        }
                    } else {
                        timestamp = new Date(); // Fallback to current time
                    }
                    
                    // Create or update conversation entry
                    if (!messagesMap[key]) {
                        messagesMap[key] = {
                            sender: message.s_dna,
                            recipient: message.r_dna,
                            otherParty: otherParty,   // Store the computed other party
                            lastMessage: message.msg || message.message || 'No content',
                            timestamp: timestamp,
                            key,
                            messages: [message]        // Re-add the messages array
                        };
                        CpunkDebug.log(`Created new conversation entry with key: ${key}`);
                    } else {
                        // Ensure messages array exists
                        if (!messagesMap[key].messages) {
                            messagesMap[key].messages = [];
                        }
                        
                        // Add message to the conversation's message list
                        messagesMap[key].messages.push(message);
                        
                        // Update if this message is newer
                        const currentTime = messagesMap[key].timestamp;
                        
                        if (timestamp > currentTime) {
                            messagesMap[key].lastMessage = message.msg || message.message || 'No content';
                            messagesMap[key].timestamp = timestamp;
                            CpunkDebug.log(`Updated conversation ${key} with newer message`);
                        }
                    }
                });
                
                // Convert map to array
                conversations = Object.values(messagesMap);
                CpunkDebug.log('Conversations loaded from messages array:', conversations.length);
                CpunkDebug.log('Conversation details:', conversations);
                
                // Nothing additional needed here
            } else if (result.messages) {
                // Handle object format (where messages is an object, not array)
                conversations = Object.keys(result.messages).map(key => {
                    const msg = result.messages[key];
                    
                    // Convert timestamp to a reliable date
                    let timestamp;
                    if (msg.timestamp) {
                        const timestampNum = Number(msg.timestamp);
                        if (!isNaN(timestampNum)) {
                            timestamp = new Date(timestampNum * 1000);
                        } else {
                            timestamp = new Date(); // Fallback to current time
                        }
                    } else {
                        timestamp = new Date(); // Fallback to current time
                    }
                    
                    // Determine other party by simple comparison
                    let otherParty = null;
                    let conversationKey = key;
                    
                    if (msg.s_dna === currentUser.dna) {
                        otherParty = msg.r_dna;
                        conversationKey = `${msg.s_dna}:${msg.r_dna}`;
                    } else if (msg.r_dna === currentUser.dna) {
                        otherParty = msg.s_dna;
                        conversationKey = `${msg.r_dna}:${msg.s_dna}`;
                    } else if (msg.sender === currentUser.dna) {
                        otherParty = msg.recipient;
                        conversationKey = `${msg.sender}:${msg.recipient}`;
                    } else if (msg.recipient === currentUser.dna) {
                        otherParty = msg.sender;
                        conversationKey = `${msg.recipient}:${msg.sender}`;
                    }
                    
                    return {
                        sender: msg.sender || msg.s_dna,
                        recipient: msg.recipient || msg.r_dna,
                        s_dna: msg.s_dna,
                        r_dna: msg.r_dna,
                        otherParty: otherParty,
                        lastMessage: msg.msg || msg.message || 'No content',
                        timestamp: timestamp,
                        key: conversationKey,
                        messages: [msg]  // Store the message for context
                    };
                });
                CpunkDebug.log('Conversations loaded from object:', conversations.length);
            } else {
                conversations = [];
                CpunkDebug.log('No conversations found in response');
            }
        } else {
            conversations = [];
            CpunkDebug.warn('Unexpected conversation response format');
        }
        
        // Sort conversations by timestamp (newest first)
        conversations.sort((a, b) => {
            // Make sure timestamps are valid Date objects
            const timeA = a.timestamp instanceof Date ? a.timestamp.getTime() : 0;
            const timeB = b.timestamp instanceof Date ? b.timestamp.getTime() : 0;
            return timeB - timeA;
        });
        
        // Render conversations
        renderConversations();
    } catch (error) {
        console.error('Error loading conversations:', error);
        showError('Error loading conversations: ' + error.message, 'connectionError');
    } finally {
        setLoading(false);
    }
}

/**
 * Render conversations in the UI
 */
function renderConversations() {
    if (!conversationsList) return;
    
    // Clear the list
    conversationsList.innerHTML = '';
    
    // Check if we have conversations
    if (conversations.length === 0) {
        placeholderMessage = document.createElement('div');
        placeholderMessage.className = 'placeholder-message';
        placeholderMessage.textContent = 'No conversations yet';
        conversationsList.appendChild(placeholderMessage);
        return;
    }
    
    // Add each conversation
    conversations.forEach(conversation => {
        // Skip any invalid conversation data
        if (!conversation || (!conversation.sender && !conversation.s_dna) || (!conversation.recipient && !conversation.r_dna)) {
            CpunkDebug.warn('Skipping invalid conversation data:', conversation);
            return;
        }
        
        // Use the stored otherParty
        let otherParty = conversation.otherParty;
        
        // Skip if otherParty is undefined
        if (!otherParty) {
            CpunkDebug.warn('Skipping conversation with missing otherParty:', conversation);
            return;
        }
        
        // Create conversation element
        const conversationElement = document.createElement('div');
        conversationElement.className = 'conversation-item';
        conversationElement.dataset.key = conversation.key || `conv-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        conversationElement.dataset.otherParty = otherParty;
        
        // Create avatar (first letter of DNA)
        const avatar = document.createElement('div');
        avatar.className = 'conversation-avatar';
        avatar.textContent = otherParty.charAt(0).toUpperCase();
        
        // Create info container
        const info = document.createElement('div');
        info.className = 'conversation-info';
        
        // Create name element
        const name = document.createElement('div');
        name.className = 'conversation-name';
        name.textContent = otherParty;
        
        // Create preview element
        const preview = document.createElement('div');
        preview.className = 'conversation-preview';
        preview.textContent = conversation.lastMessage || 'No message';
        
        // Create time element - handle potential invalid date
        const time = document.createElement('div');
        time.className = 'conversation-time';
        
        // Make sure timestamp is valid before formatting
        let timeText = 'Unknown';
        if (conversation.timestamp) {
            try {
                // Ensure timestamp is a valid Date object
                if (conversation.timestamp instanceof Date && !isNaN(conversation.timestamp)) {
                    timeText = formatTimestamp(conversation.timestamp);
                } else {
                    // Try to create a valid date from timestamp
                    const date = new Date(conversation.timestamp);
                    if (!isNaN(date)) {
                        timeText = formatTimestamp(date);
                    }
                }
            } catch (e) {
                console.warn('Error formatting timestamp:', e);
            }
        }
        time.textContent = timeText;
        
        // Assemble conversation
        info.appendChild(name);
        info.appendChild(preview);
        conversationElement.appendChild(avatar);
        conversationElement.appendChild(info);
        conversationElement.appendChild(time);
        
        // Add click handler
        conversationElement.addEventListener('click', () => {
            openConversation(conversationElement.dataset.key, otherParty);
        });
        
        // Add to list
        conversationsList.appendChild(conversationElement);
    });
    
    CpunkDebug.info('Conversations rendered:', conversations.length);
}

/**
 * Open a conversation
 */
async function openConversation(key, otherParty) {
    try {
        // Store current conversation
        currentConversation = {
            key,
            otherParty
        };
        
        // Clear selection
        const allConversations = conversationsList.querySelectorAll('.conversation-item');
        allConversations.forEach(conv => conv.classList.remove('selected'));
        
        // Set selected
        const selectedConversation = conversationsList.querySelector(`.conversation-item[data-key="${key}"]`);
        if (selectedConversation) {
            selectedConversation.classList.add('selected');
        }
        
        // Show loading
        setLoading(true);
        
        // Update contact info
        if (contactName) {
            contactName.textContent = otherParty;
        }
        
        if (contactAvatar) {
            contactAvatar.textContent = otherParty.charAt(0).toUpperCase();
        }
        
        if (contactStatus) {
            contactStatus.textContent = 'DNA User';
        }
        
        // Enable message input
        if (messageInput) {
            messageInput.disabled = false;
        }
        
        if (sendButton) {
            sendButton.disabled = false;
        }
        
        // Load messages
        await loadMessages(key, otherParty);
    } catch (error) {
        CpunkDebug.error('Error opening conversation:', error);
        showError('Error opening conversation: ' + error.message, 'connectionError');
    } finally {
        setLoading(false);
    }
}

/**
 * Load messages for a conversation
 */
async function loadMessages(key, otherParty) {
    try {
        CpunkDebug.info('Loading messages for conversation:', { key, otherParty });
        
        if (messagesContainer) {
            messagesContainer.innerHTML = '<div class="loading">Loading messages...</div>';
        }
        
        // Store the other party in current conversation for reference
        if (currentConversation) {
            currentConversation.otherParty = otherParty;
            CpunkDebug.log('Updated currentConversation.otherParty:', otherParty);
        }
        
        // Get messages from the DNA API
        CpunkDebug.log('Fetching messages from API for:', { user: currentUser.dna, otherParty });
        
        // Get messages between the two users
        const result = await dnaLookup('messages', currentUser.dna, otherParty);
        
        // Process the result
        if (typeof result === 'string') {
            if (result.includes('no messages') || result.includes('not found')) {
                messages = [];
                CpunkDebug.log('No messages found');
            } else {
                try {
                    // Try to parse JSON
                    const data = JSON.parse(result);
                    processMessageData(data);
                } catch (e) {
                    CpunkDebug.error('Failed to parse messages:', e);
                    messages = [];
                }
            }
        } else if (result && typeof result === 'object') {
            processMessageData(result);
        } else {
            messages = [];
            CpunkDebug.warn('Unexpected message response format');
        }
        
        // Mark messages as sent by current user or not
        messages.forEach(message => {
            // CRITICAL: Make sure both sender and currentUser.dna are strings
            const messageSender = String(message.sender || message.s_dna || '');
            const currentDna = String(currentUser.dna || '');
            
            // Mark if message is from current user - case insensitive match for robustness
            message.isMine = messageSender.toLowerCase() === currentDna.toLowerCase();
            
            // Ensure timestamp is a valid Date object
            if (!(message.timestamp instanceof Date) || isNaN(message.timestamp)) {
                message.timestamp = new Date();
            }
        });
        
        // Sort messages by timestamp
        messages.sort((a, b) => {
            // Convert to milliseconds for comparison if they're Date objects
            const timeA = a.timestamp instanceof Date ? a.timestamp.getTime() : a.timestamp;
            const timeB = b.timestamp instanceof Date ? b.timestamp.getTime() : b.timestamp;
            return timeA - timeB;
        });
        
        // Render messages
        renderMessages();
    } catch (error) {
        CpunkDebug.error('Error loading messages:', error);
        
        if (messagesContainer) {
            messagesContainer.innerHTML = `
                <div class="error-message">
                    Error loading messages: ${error.message}
                </div>
            `;
        }
    }
}

/**
 * Process message data from API response
 */
function processMessageData(data) {
    if (data.messages) {
        if (Array.isArray(data.messages)) {
            // Handle array format (newer API)
            messages = data.messages.map((msg, index) => {
                // Ensure timestamp is a valid number before creating Date
                let timestamp;
                if (msg.timestamp) {
                    // Convert to number if it's a string
                    const timestampNum = Number(msg.timestamp);
                    if (!isNaN(timestampNum)) {
                        timestamp = new Date(timestampNum * 1000);
                    } else {
                        // Fallback to current time if invalid
                        timestamp = new Date();
                    }
                } else {
                    // If no timestamp, use current time
                    timestamp = new Date();
                }
                
                // Debug log to see each message
                    sender: msg.s_dna, 
                    recipient: msg.r_dna, 
                    currentUser: currentUser.dna,
                    isMine: msg.s_dna === currentUser.dna,
                    message: (msg.msg || msg.message || '').substring(0, 20) + '...'
                });
                
                // Ensure proper string comparison for isMine flag
                const senderDna = String(msg.s_dna || '').toLowerCase();
                const currentDna = String(currentUser.dna || '').toLowerCase();
                
                return {
                    id: `msg-${index}`,
                    sender: msg.s_dna,
                    recipient: msg.r_dna,
                    message: msg.msg || msg.message || '',
                    timestamp: timestamp,
                    isMine: senderDna === currentDna
                };
            });
        } else if (typeof data.messages === 'object') {
            // Handle object format (older API)
            messages = Object.keys(data.messages).map(key => {
                const msg = data.messages[key];
                
                // Ensure timestamp is a valid number before creating Date
                let timestamp;
                if (msg.timestamp) {
                    // Convert to number if it's a string
                    const timestampNum = Number(msg.timestamp);
                    if (!isNaN(timestampNum)) {
                        timestamp = new Date(timestampNum * 1000);
                    } else {
                        // Fallback to current time if invalid
                        timestamp = new Date();
                    }
                } else {
                    // If no timestamp, use current time
                    timestamp = new Date();
                }
                
                // Debug log for object format messages
                    sender: msg.sender || msg.s_dna, 
                    recipient: msg.recipient || msg.r_dna, 
                    currentUser: currentUser.dna,
                    isMine: (msg.sender || msg.s_dna) === currentUser.dna,
                    message: (msg.msg || msg.message || '').substring(0, 20) + '...'
                });
                
                // Ensure proper string comparison for isMine flag
                const senderDna = String(msg.sender || msg.s_dna || '').toLowerCase();
                const currentDna = String(currentUser.dna || '').toLowerCase();
                
                return {
                    id: key,
                    sender: msg.sender || msg.s_dna,
                    recipient: msg.recipient || msg.r_dna,
                    message: msg.msg || msg.message || '',
                    timestamp: timestamp,
                    isMine: senderDna === currentDna
                };
            });
        }
    } else {
        messages = [];
    }
}

/**
 * Render messages in the UI
 */
function renderMessages() {
    if (!messagesContainer) return;
    
    // Clear container
    messagesContainer.innerHTML = '';
    
    // If no messages, show placeholder
    if (messages.length === 0) {
        const emptyMessage = document.createElement('div');
        emptyMessage.className = 'empty-messages';
        emptyMessage.innerHTML = `
            <div class="empty-icon">💬</div>
            <p>No messages yet</p>
            <p>Start the conversation by sending a message below.</p>
        `;
        messagesContainer.appendChild(emptyMessage);
        return;
    }
    
    // Create message groups by date
    const messagesByDate = {};
    messages.forEach(message => {
        // Make sure timestamp is valid
        if (!message.timestamp || !(message.timestamp instanceof Date) || isNaN(message.timestamp)) {
            console.warn('Message with invalid timestamp:', message);
            // Create a fallback date for grouping
            message.timestamp = new Date();
        }
        
        try {
            const dateKey = message.timestamp.toDateString();
            if (!messagesByDate[dateKey]) {
                messagesByDate[dateKey] = [];
            }
            messagesByDate[dateKey].push(message);
        } catch (e) {
            console.error('Error grouping message by date:', e, message);
        }
    });
    
    // Render each date group
    Object.keys(messagesByDate).forEach(dateKey => {
        try {
            // Add date separator
            const dateSeparator = document.createElement('div');
            dateSeparator.className = 'date-separator';
            dateSeparator.textContent = formatDate(new Date(dateKey));
            messagesContainer.appendChild(dateSeparator);
            
            // Add messages for this date
            messagesByDate[dateKey].forEach(message => {
                // Add extensive console logging to debug why messages might not be displaying
                    isMine: message.isMine,
                    sender: message.sender,
                    recipient: message.recipient,
                    currentUser: currentUser.dna,
                    time: message.timestamp,
                    content: message.message ? message.message.substring(0, 30) : 'No content'
                });
                
                const messageElement = document.createElement('div');
                messageElement.className = `message ${message.isMine ? 'message-mine' : 'message-other'}`;
                
                // Add data attributes for debugging
                messageElement.dataset.sender = message.sender;
                messageElement.dataset.recipient = message.recipient;
                messageElement.dataset.isMine = message.isMine;
                
                const messageContent = document.createElement('div');
                messageContent.className = 'message-content';
                
                const messageText = document.createElement('div');
                messageText.className = 'message-text';
                messageText.textContent = message.message || 'No content';
                
                const messageTime = document.createElement('div');
                messageTime.className = 'message-time';
                messageTime.textContent = formatMessageTime(message.timestamp);
                
                messageContent.appendChild(messageText);
                messageContent.appendChild(messageTime);
                messageElement.appendChild(messageContent);
                
                messagesContainer.appendChild(messageElement);
            });
        } catch (e) {
            console.error('Error rendering message group:', e, dateKey);
        }
    });
    
    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
}

/**
 * Refresh messages for the current conversation
 */
async function refreshMessages() {
    if (!currentConversation) return;
    
    try {
        
        // Load messages without clearing the container
        await loadMessages(currentConversation.key, currentConversation.otherParty);
        
        // Also refresh conversations list to update previews
        await loadConversations();
    } catch (error) {
        console.error('Error refreshing messages:', error);
    }
}

/**
 * Send a message
 */
async function sendMessage() {
    if (!currentConversation || !currentUser.dna) {
        CpunkDebug.error('Cannot send message: missing currentConversation or user DNA');
        return;
    }
    
    const messageText = messageInput.value.trim();
    if (!messageText) {
        CpunkDebug.warn('Cannot send empty message');
        return;
    }
    
    // Ensure we have a valid otherParty
    if (!currentConversation.otherParty) {
        CpunkDebug.error('Missing conversation partner (otherParty)');
        showError('Unable to determine message recipient', 'connectionError');
        return;
    }
    
    // No confirmation popup needed
    
    try {
        // Disable input while sending
        messageInput.disabled = true;
        sendButton.disabled = true;
        
        CpunkDebug.info('Sending message to:', currentConversation.otherParty);
        CpunkDebug.log('Current user state:', currentUser);
        CpunkDebug.log('Current conversation:', currentConversation);
        
        // Make sure we have a valid wallet address
        if (!currentUser.wallet) {
            CpunkDebug.error('No wallet address available');
            throw new Error('No wallet address available for sending messages');
        }
        
        // Ensure wallet address is correctly formatted
        let walletAddress = currentUser.wallet;
        CpunkDebug.logWallet('Initial send wallet value', walletAddress);
        
        if (typeof walletAddress !== 'string') {
            CpunkDebug.warn('Wallet address is not a string:', typeof walletAddress);
            walletAddress = String(walletAddress);
            CpunkDebug.logWallet('After string conversion', walletAddress);
        }
        
        // Clean wallet address if it contains complex objects
        if (walletAddress.includes('{') || walletAddress.includes('[')) {
            CpunkDebug.log('Wallet appears to contain JSON, attempting to parse');
            try {
                // Try to parse it as JSON
                const walletObj = JSON.parse(walletAddress);
                CpunkDebug.log('Successfully parsed wallet JSON', walletObj);
                // Extract address field if it exists
                if (walletObj && walletObj.address) {
                    CpunkDebug.log('Found address field in JSON', walletObj.address);
                    walletAddress = walletObj.address;
                }
            } catch (e) {
                CpunkDebug.warn('Could not parse wallet address as JSON:', e.message);
                // Keep using the original string
            }
        }
        
        // Strip any surrounding quotes that might be causing JSON parsing issues
        const beforeQuoteStrip = walletAddress;
        walletAddress = walletAddress.replace(/^["'](.*)["']$/, '$1');
        if (beforeQuoteStrip !== walletAddress) {
            CpunkDebug.log('Removed surrounding quotes', {before: beforeQuoteStrip, after: walletAddress});
        }
        
        // Further clean the string - remove any non-alphanumeric characters except specific allowed ones
        // This helps especially with invisible characters that might be present
        const beforeClean = walletAddress;
        walletAddress = walletAddress.replace(/[^\w\-:.+]/g, '');
        if (beforeClean !== walletAddress) {
            CpunkDebug.log('Cleaned wallet address', {before: beforeClean, after: walletAddress});
        }
        
        // Log the final wallet address format
        CpunkDebug.logWallet('Final sending wallet address', walletAddress);
        
        // Create a timestamp for this message
        const timestamp = Math.floor(Date.now() / 1000);
        
        // Prepare message data with validated wallet
        const messageData = {
            action: 'update',
            wallet: walletAddress,
            messages: [
                {
                    s_dna: currentUser.dna,
                    r_dna: currentConversation.otherParty,
                    msg: messageText,
                    timestamp: timestamp
                }
            ]
        };
        
        CpunkDebug.log('Sending message data:', JSON.stringify(messageData));
        
        // Add message to local display immediately for better UX
        // Do this before the API call so user sees their message right away
        addLocalMessage(messageText, timestamp);
        
        // Send message using DNA API
        CpunkDebug.info('Making POST request to DNA API');
        const result = await dnaPost(messageData);
        
        CpunkDebug.info('Message sent response received:', result);
        
        // Check for error response
        if (result && result.status_code === -1) {
            CpunkDebug.error('API returned error response', {
                status_code: result.status_code,
                message: result.message,
                description: result.description
            });
            
            // Show error but don't throw - we've already shown the message locally
            showError(result.description || result.message || 'Message sending failed', 'connectionError');
        } else {
            CpunkDebug.info('Message sent successfully');
            
            // Clear input after successful send
            messageInput.value = '';
            
            // Update the conversation in the conversations list with the new message
            const conversationIndex = conversations.findIndex(conv => conv.key === currentConversation.key);
            if (conversationIndex !== -1) {
                conversations[conversationIndex].lastMessage = messageText;
                conversations[conversationIndex].timestamp = new Date(timestamp * 1000);
                
                // Force re-render of conversations to show updated preview
                setTimeout(() => {
                    renderConversations();
                }, 100);
            }
            
            // Refresh messages after a delay to get the server copy
            setTimeout(async () => {
                await refreshMessages();
            }, 1000);
        }
    } catch (error) {
        CpunkDebug.error('Error sending message:', error);
        showError('Error sending message: ' + error.message, 'connectionError');
    } finally {
        // Re-enable input
        messageInput.disabled = false;
        sendButton.disabled = false;
        messageInput.focus();
    }
}

/**
 * Add message to local display immediately without waiting for refresh
 * @param {string} messageText - The text of the message to add
 * @param {number} [timestamp] - Optional Unix timestamp (seconds since epoch)
 */
function addLocalMessage(messageText, timestamp) {
    if (!messagesContainer || !messageText) {
        CpunkDebug.warn('Cannot add local message: missing container or text');
        return;
    }
    
    try {
        // Create a timestamp if not provided
        const messageDate = timestamp ? new Date(timestamp * 1000) : new Date();
        
        // Create a new message object
        const newMessage = {
            id: `local-${Date.now()}`,
            sender: currentUser.dna,
            recipient: currentConversation.otherParty,
            s_dna: currentUser.dna,           // Add modern field names too
            r_dna: currentConversation.otherParty,
            message: messageText,
            msg: messageText,                  // Add both message formats
            timestamp: messageDate,
            isMine: true
        };
        
        CpunkDebug.log('Adding local message to display:', {
            text: messageText.substring(0, 30) + (messageText.length > 30 ? '...' : ''),
            timestamp: messageDate
        });
        
        // Add to messages array
        messages.push(newMessage);
        
        // Check if we need to add a new date separator
        const dateKey = messageDate.toDateString();
        const lastDateSeparator = messagesContainer.querySelector('.date-separator:last-child');
        const needsDateSeparator = !lastDateSeparator || 
                                 lastDateSeparator.textContent !== formatDate(messageDate);
        
        // Add date separator if needed
        if (needsDateSeparator) {
            const dateSeparator = document.createElement('div');
            dateSeparator.className = 'date-separator';
            dateSeparator.textContent = formatDate(messageDate);
            messagesContainer.appendChild(dateSeparator);
        }
        
        // Create message element
        const messageElement = document.createElement('div');
        messageElement.className = 'message message-mine';
        messageElement.dataset.id = newMessage.id;
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        
        const messageTextElement = document.createElement('div');
        messageTextElement.className = 'message-text';
        messageTextElement.textContent = messageText;
        
        const messageTime = document.createElement('div');
        messageTime.className = 'message-time';
        messageTime.textContent = formatMessageTime(messageDate);
        
        messageContent.appendChild(messageTextElement);
        messageContent.appendChild(messageTime);
        messageElement.appendChild(messageContent);
        
        // Add to container
        messagesContainer.appendChild(messageElement);
        
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    } catch (e) {
        CpunkDebug.error('Error adding local message:', e);
    }
}

/**
 * Search for a DNA user
 */
async function searchDna() {
    const query = searchInput.value.trim();
    if (!query) {
        CpunkDebug.warn('Empty search query');
        return;
    }
    
    try {
        CpunkDebug.info('Searching for DNA:', query);
        
        // Check if the query is a valid DNA format
        if (!isValidNicknameFormat(query)) {
            CpunkDebug.warn('Invalid DNA format:', query);
            showError('Invalid DNA format. Please enter a valid DNA nickname.', 'connectionError');
            return;
        }
        
        // Check if DNA exists
        CpunkDebug.log('Verifying DNA exists in system:', query);
        const result = await dnaLookup('lookup', query);
        
        // Check for errors or invalid results
        if (typeof result === 'string') {
            if (result.includes('not found') || result.trim() === '') {
                CpunkDebug.warn(`DNA nickname "${query}" not found in system`);
                showError(`DNA nickname "${query}" not found.`, 'connectionError');
                return;
            }
        } else if (result && typeof result === 'object') {
            // Check for error status code
            if (result.status_code && result.status_code !== 0) {
                CpunkDebug.warn('API returned error for DNA lookup:', result);
                showError(result.message || `DNA nickname "${query}" not found.`, 'connectionError');
                return;
            }
            
            // Check for empty response data
            if (!result.response_data || Object.keys(result.response_data).length === 0) {
                CpunkDebug.warn('API returned empty data for DNA lookup:', result);
                showError(`DNA nickname "${query}" not found.`, 'connectionError');
                return;
            }
            
            CpunkDebug.log('DNA user found:', query);
        }
        
        // Clear search input after successful search
        searchInput.value = '';
        
        // Start conversation with this DNA
        validateAndStartConversation(query);
    } catch (error) {
        CpunkDebug.error('Error searching DNA:', error);
        showError('Error searching for DNA: ' + error.message, 'connectionError');
    }
}

/**
 * Show the new conversation modal
 */
function showNewConversationModal() {
    // Clear previous input and validation
    recipientDna.value = '';
    recipientValidation.textContent = '';
    recipientValidation.className = 'validation-message';
    recipientValidation.style.display = 'none';
    
    // Disable start button initially
    startConversationButton.disabled = true;
    
    // Show modal
    newConversationModal.style.display = 'block';
    
    // Focus input
    recipientDna.focus();
    
}

/**
 * Hide the new conversation modal
 */
function hideNewConversationModal() {
    newConversationModal.style.display = 'none';
}

/**
 * Validate recipient DNA input
 */
async function validateRecipient() {
    const dna = recipientDna.value.trim();
    
    // Clear previous validation
    recipientValidation.textContent = '';
    recipientValidation.className = 'validation-message';
    recipientValidation.style.display = 'none';
    
    // Disable start button by default
    startConversationButton.disabled = true;
    
    if (!dna) return;
    
    try {
        // Check if valid DNA format
        if (!isValidNicknameFormat(dna)) {
            recipientValidation.textContent = 'Invalid DNA format';
            recipientValidation.className = 'validation-message validation-error';
            recipientValidation.style.display = 'block';
            return;
        }
        
        // Check if same as current user
        if (dna === currentUser.dna) {
            recipientValidation.textContent = 'You cannot message yourself';
            recipientValidation.className = 'validation-message validation-error';
            recipientValidation.style.display = 'block';
            return;
        }
        
        // Check if DNA exists
        const result = await dnaLookup('lookup', dna);
        
        if (typeof result === 'string' && (result.includes('not found') || result.trim() === '')) {
            recipientValidation.textContent = `DNA nickname "${dna}" not found`;
            recipientValidation.className = 'validation-message validation-error';
            recipientValidation.style.display = 'block';
            return;
        }
        
        // DNA exists and is valid
        recipientValidation.textContent = `✓ Valid DNA user`;
        recipientValidation.className = 'validation-message validation-success';
        recipientValidation.style.display = 'block';
        
        // Enable start button
        startConversationButton.disabled = false;
    } catch (error) {
        console.error('Error validating recipient:', error);
        
        recipientValidation.textContent = `Error checking DNA: ${error.message}`;
        recipientValidation.className = 'validation-message validation-warning';
        recipientValidation.style.display = 'block';
    }
}

/**
 * Start a new conversation
 */
function startConversation() {
    const dna = recipientDna.value.trim();
    if (!dna) return;
    
    validateAndStartConversation(dna);
}

/**
 * Validate and start a conversation with a DNA user
 */
async function validateAndStartConversation(dna) {
    try {        
        // Check if valid DNA format
        if (!isValidNicknameFormat(dna)) {
            showError('Invalid DNA format', 'connectionError');
            return;
        }
        
        // Check if same as current user
        if (dna === currentUser.dna) {
            showError('You cannot message yourself', 'connectionError');
            return;
        }
        
        // Hide modal if open
        hideNewConversationModal();
        
        // Show loading
        setLoading(true);
        
        // Check if conversation already exists
        const existingConversation = conversations.find(conv => 
            (conv.sender === dna && conv.recipient === currentUser.dna) ||
            (conv.sender === currentUser.dna && conv.recipient === dna) ||
            (conv.s_dna === dna && conv.r_dna === currentUser.dna) ||
            (conv.s_dna === currentUser.dna && conv.r_dna === dna) ||
            (conv.otherParty === dna)
        );
        
        if (existingConversation) {
            // Open existing conversation
            openConversation(existingConversation.key, dna);
            return;
        }
        
        // Create a new "empty" conversation UI
        currentConversation = {
            key: `${currentUser.dna}:${dna}`,
            otherParty: dna
        };
        
        // Update contact info
        if (contactName) {
            contactName.textContent = dna;
        }
        
        if (contactAvatar) {
            contactAvatar.textContent = dna.charAt(0).toUpperCase();
        }
        
        if (contactStatus) {
            contactStatus.textContent = `DNA User`;
        }
        
        // Enable message input
        if (messageInput) {
            messageInput.disabled = false;
        }
        
        if (sendButton) {
            sendButton.disabled = false;
        }
        
        // Clear messages container and show empty state
        if (messagesContainer) {
            messagesContainer.innerHTML = '';
            const emptyMessage = document.createElement('div');
            emptyMessage.className = 'empty-messages';
            emptyMessage.innerHTML = `
                <div class="empty-icon">💬</div>
                <p>Start a conversation with ${dna}</p>
                <p>Send a message to begin chatting.</p>
            `;
            messagesContainer.appendChild(emptyMessage);
        }
        
        // Focus on message input
        if (messageInput) {
            messageInput.focus();
        }
        
        CpunkDebug.info('New conversation started with:', dna);
    } catch (error) {
        CpunkDebug.error('Error starting conversation:', error);
        showError('Error starting conversation: ' + error.message, 'connectionError');
    } finally {
        setLoading(false);
    }
}

/**
 * Call the DNA proxy API for lookups
 */
async function dnaLookup(action, query, conversationPartner = null) {
    try {
        let url;
        
        // Handle different actions with the correct endpoint format
        if (action === 'messages') {
            // Make sure the parameters are correctly encoded in the URL
            const encodedDna = encodeURIComponent(query);
            url = `${DNA_PROXY_URL}?get_messages=${encodedDna}`;
            
            // Add conversation partner as a separate parameter
            if (conversationPartner) {
                const encodedPartner = encodeURIComponent(conversationPartner);
                url += `&conversation_with=${encodedPartner}`;
            }
        } else if (action === 'lookup') {
            url = `${DNA_PROXY_URL}?lookup=${encodeURIComponent(query)}`;
        } else {
            url = `${DNA_PROXY_URL}?lookup=${encodeURIComponent(query)}`;
        }
        
        
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`Error in DNA lookup for ${action}:`, error);
        throw error;
    }
}

/**
 * Post data to the DNA proxy API
 */
async function dnaPost(data) {
    try {
        CpunkDebug.log('POST request to DNA API:', DNA_PROXY_URL);
        CpunkDebug.log('Request data:', JSON.stringify(data));
        
        // Extra validation for wallet address before sending
        if (data.wallet) {
            CpunkDebug.logWallet('dnaPost wallet check', data.wallet);
            
            // Force all wallet addresses to be clean strings before sending
            if (typeof data.wallet !== 'string') {
                CpunkDebug.warn('Converting wallet to string in POST request');
                data.wallet = String(data.wallet);
            }
            
            // Final cleanup
            data.wallet = data.wallet.replace(/^["'](.*)["']$/, '$1').replace(/[^\w\-:.+]/g, '');
            CpunkDebug.log('Final wallet value in POST request:', data.wallet);
        }
        
        const response = await fetch(DNA_PROXY_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        CpunkDebug.log('Response status:', response.status);
        
        // Get response text first to log it
        const responseText = await response.text();
        CpunkDebug.log('Response text:', responseText);
        
        // Try to parse as JSON
        let responseData;
        try {
            responseData = JSON.parse(responseText);
            CpunkDebug.log('Parsed response data:', responseData);
        } catch (e) {
            CpunkDebug.error('Error parsing response as JSON:', e.message);
            CpunkDebug.error('Raw response text:', responseText);
            throw new Error(`Invalid JSON response: ${responseText}`);
        }
        
        // Check for error response
        if (!response.ok) {
            const errorMessage = responseData?.error || responseData?.message || `HTTP error ${response.status}`;
            CpunkDebug.error('HTTP error response:', {status: response.status, error: errorMessage});
            throw new Error(errorMessage);
        }
        
        // Check for API error in the response
        if (responseData && responseData.status_code === -1) {
            const errorMessage = responseData.description || responseData.message || 'API error';
            CpunkDebug.error('API returned error:', {
                status_code: responseData.status_code,
                message: errorMessage,
                data: responseData
            });
            // Still return the response data so the caller can handle it
        }
        
        return responseData;
    } catch (error) {
        CpunkDebug.error('Exception in DNA post:', error.message);
        throw error;
    }
}

/**
 * Show error message
 */
function showError(message, elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.style.display = 'block';
    }
}

/**
 * Set loading state
 */
function setLoading(isLoading) {
    // You can implement loading indicator as needed
}

/**
 * Check if a string is a valid DNA nickname format
 */
function isValidNicknameFormat(nickname) {
    // Simple pattern matching, can be adjusted as needed
    return /^[a-zA-Z0-9_]{3,30}$/.test(nickname);
}

/**
 * Format timestamp for conversation list
 */
function formatTimestamp(date) {
    // Validate date before using it
    if (!date || !(date instanceof Date) || isNaN(date)) {
        console.warn('Invalid date passed to formatTimestamp:', date);
        return '';
    }
    
    try {
        const now = new Date();
        const yesterday = new Date(now);
        yesterday.setDate(now.getDate() - 1);
        
        if (date.toDateString() === now.toDateString()) {
            // Today - show time
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else if (date.toDateString() === yesterday.toDateString()) {
            // Yesterday
            return 'Yesterday';
        } else if (now.getTime() - date.getTime() < 7 * 24 * 60 * 60 * 1000) {
            // Within a week - show day name
            return date.toLocaleDateString([], { weekday: 'short' });
        } else {
            // Older - show date
            return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        }
    } catch (e) {
        console.error('Error in formatTimestamp:', e);
        return '';
    }
}

/**
 * Format date for message groups
 */
function formatDate(date) {
    // Validate date before using it
    if (!date || !(date instanceof Date) || isNaN(date)) {
        console.warn('Invalid date passed to formatDate:', date);
        return 'Unknown Date';
    }
    
    try {
        const now = new Date();
        const yesterday = new Date(now);
        yesterday.setDate(now.getDate() - 1);
        
        if (date.toDateString() === now.toDateString()) {
            return 'Today';
        } else if (date.toDateString() === yesterday.toDateString()) {
            return 'Yesterday';
        } else {
            return date.toLocaleDateString([], { 
                weekday: 'short', 
                month: 'short', 
                day: 'numeric',
                year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined 
            });
        }
    } catch (e) {
        console.error('Error in formatDate:', e);
        return 'Invalid Date';
    }
}

/**
 * Format time for message display
 */
function formatMessageTime(date) {
    // Validate date before using it
    if (!date || !(date instanceof Date) || isNaN(date)) {
        console.warn('Invalid date passed to formatMessageTime:', date);
        return '';
    }
    
    try {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
        console.error('Error in formatMessageTime:', e);
        return '';
    }
}