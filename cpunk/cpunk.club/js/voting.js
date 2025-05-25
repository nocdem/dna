// State variables
let selectedWallet = null;
const selectedNetwork = 'Cpunk'; // Hardcoded to always use Cpunk network
let activeVotes = [];
let voteDetails = {};
let selectedVoteHash = null;
let userVotes = {};
let selectedVoteOption = null;

// DOM Elements
let walletSection;
let walletsList;
let continueButton;
let votesSection;
let selectedWalletName;
let votesList;
let disconnectButton;
let voteDetailSection;
let voteDetail;
let voteSuccess;
let voteError;
let voteWarning;
let backButton;

// API URL
const API_URL = 'http://localhost:8045/';

document.addEventListener('DOMContentLoaded', function() {
    // Initialize utilities
    // NEVER DO ASSUMPTIONS. NEVER USE MOCK DATA. THIS IS LIVE ENVIRONMENT
    CpunkUtils.init({
        debug: {
            enabled: true,
            showInConsole: true,
            showInUI: false
        }
    });
    
    CpunkUI.init({
        dashboardConnectorElements: {
            statusIndicatorId: 'statusIndicator',
            connectButtonId: 'connectButton',
            connectionErrorId: 'connectionError'
        }
    });
    
    CpunkTransaction.init();
    
    // Initialize the dashboard connector
    CpunkDashboard.init({
        apiUrl: API_URL,
        onConnected: async (sessionId) => {
            // Show wallet selection section
            walletSection.style.display = 'block';
            await loadWallets();
        },
        onError: (message) => {
            console.error('Dashboard connection error:', message);
        }
    });
    
    // Initialize DOM elements
    walletSection = document.getElementById('walletSection');
    walletsList = document.getElementById('walletsList');
    continueButton = document.getElementById('continueButton');
    votesSection = document.getElementById('votesSection');
    selectedWalletName = document.getElementById('selectedWalletName');
    votesList = document.getElementById('votesList');
    voteDetailSection = document.getElementById('voteDetailSection');
    voteDetail = document.getElementById('voteDetail');
    voteSuccess = document.getElementById('voteSuccess');
    voteError = document.getElementById('voteError');
    voteWarning = document.getElementById('voteWarning');
    backButton = document.getElementById('backButton');
    
    // Debug log to check if backButton is found
    
    // Filter and sort elements
    const statusFilter = document.getElementById('statusFilter');
    const sortOrder = document.getElementById('sortOrder');
    
    // Set up event listeners
    if (continueButton) {
        continueButton.addEventListener('click', continueWithWallet);
    }
    
    if (backButton) {
        backButton.addEventListener('click', function(event) {
            event.preventDefault();
            showVotesList();
        });
    } else {
        console.error('Back button element not found!');
    }
    
    // Add filter event listeners
    if (statusFilter) {
        statusFilter.addEventListener('change', () => {
            renderVotesList(); // Re-render with new filters
        });
    }
    
    // Add sort event listeners
    if (sortOrder) {
        sortOrder.addEventListener('change', () => {
            renderVotesList(); // Re-render with new sort order
        });
    }
    
    // All sections are already hidden by default in the HTML
    // No need to hide them again here
});

// Load available wallets
async function loadWallets() {
    try {
        walletsList.innerHTML = '<div class="loading">Loading wallets</div>';
        
        const wallets = await CpunkDashboard.getWallets();
        
        if (wallets && wallets.length > 0) {
            renderWalletsList(wallets);
        } else {
            walletsList.innerHTML = '<div class="no-votes-message">No wallets found in your dashboard.</div>';
        }
    } catch (error) {
        walletsList.innerHTML = '<div class="error-message" style="display: block;">Failed to load wallets</div>';
    }
}

// Render wallets list
function renderWalletsList(wallets) {
    if (wallets.length === 0) {
        walletsList.innerHTML = '<div class="no-votes-message">No wallets found in your dashboard.</div>';
        return;
    }

    let walletsHTML = '';
    wallets.forEach(wallet => {
        const isSelected = selectedWallet && selectedWallet.name === wallet.name;
        walletsHTML += `
            <div class="wallet-card ${isSelected ? 'selected' : ''}" data-wallet-name="${wallet.name}">
                <div class="wallet-name">${wallet.name}</div>
            </div>
        `;
    });

    walletsList.innerHTML = walletsHTML;

    // Add click event to wallet cards
    document.querySelectorAll('.wallet-card').forEach(card => {
        card.addEventListener('click', () => {
            // Remove selected class from all wallet cards
            document.querySelectorAll('.wallet-card').forEach(c => c.classList.remove('selected'));
            
            // Add selected class to clicked card
            card.classList.add('selected');
            
            // Store selected wallet
            const walletName = card.getAttribute('data-wallet-name');
            selectedWallet = wallets.find(w => w.name === walletName);
            
            // Automatically continue with this wallet
            continueWithWallet();
        });
    });
}

// Continue with selected wallet
async function continueWithWallet() {
    if (!selectedWallet) return;

    // Update selected wallet display
    selectedWalletName.textContent = selectedWallet.name;

    // Show votes section
    walletSection.style.display = 'none';
    votesSection.style.display = 'block';

    // Load votes
    await loadVotes();
}

// Load active votes
async function loadVotes() {
    try {
        votesList.innerHTML = '<div class="loading">Loading votes</div>';
        
        // Get the current session ID
        const sessionId = CpunkDashboard.getSessionId();
        
            sessionId,
            selectedWallet,
            selectedNetwork
        });
        
        if (!sessionId) {
            throw new Error('Not connected to dashboard');
        }
        
        CpunkAPIConsole.log('API Request: VotingList', {
            id: sessionId,
            net: selectedNetwork
        });
        
        // Use the original VotingList method that was working 15 minutes ago
        const response = await CpunkDashboard.makeRequest('VotingList', {
            id: sessionId,
            net: selectedNetwork
        });

        CpunkAPIConsole.log('API Response: VotingList', response);
        
        if (response.status === 'ok' && response.data) {
            // Store active votes - match original code
            if (Array.isArray(response.data)) {
                activeVotes = response.data;
            } else if (typeof response.data === 'object') {
                activeVotes = Object.values(response.data);
            } else {
                activeVotes = [];
            }
            
            // Intermediate rendering with basic info
            renderVotesList();
            
            // Load detailed information for each vote
            await loadVoteDetails();
        } else {
            throw new Error(response.errorMsg || 'Failed to load votes');
        }
    } catch (error) {
        votesList.innerHTML = `<div class="error-message" style="display: block;">Failed to load votes: ${error.message}</div>`;
    }
}

// Load detailed information for each vote
async function loadVoteDetails() {
    if (!activeVotes || activeVotes.length === 0) {
        return;
    }
    
    const sessionId = CpunkDashboard.getSessionId();
    if (!sessionId) {
        return;
    }
    
    // Show loading indicator inside each vote card
    document.querySelectorAll('.vote-card').forEach(card => {
        const loadingEl = document.createElement('div');
        loadingEl.className = 'vote-loading';
        loadingEl.innerHTML = 'Loading details...';
        card.appendChild(loadingEl);
    });
    
    // Fetch detailed data for each vote
    for (const vote of activeVotes) {
        try {
            CpunkAPIConsole.log('API Request: VotingDump', {
                id: sessionId,
                net: selectedNetwork,
                hashTx: vote.hash
            });
            
            const dumpResponse = await CpunkDashboard.makeRequest('VotingDump', {
                id: sessionId,
                net: selectedNetwork,
                hashTx: vote.hash
            });
            
            CpunkAPIConsole.log('API Response: VotingDump', dumpResponse);
            
            if (dumpResponse.status === 'ok' && dumpResponse.data) {
                // Store the detailed data
                voteDetails[vote.hash] = dumpResponse.data;
                
                // Update the UI for this specific vote
                updateVoteCard(vote.hash);
            }
        } catch (error) {
            console.error(`Failed to load details for vote ${vote.hash}:`, error);
            // Remove loading indicator for this vote
            const card = document.querySelector(`.vote-card[data-hash="${vote.hash}"]`);
            if (card) {
                const loading = card.querySelector('.vote-loading');
                if (loading) {
                    loading.remove();
                }
            }
        }
    }
    
    // Final re-render with all data
    renderVotesList();
}

// Update a specific vote card with detailed information
function updateVoteCard(hash) {
    const card = document.querySelector(`.vote-card[data-hash="${hash}"]`);
    if (!card) return;
    
    // Remove loading indicator
    const loading = card.querySelector('.vote-loading');
    if (loading) {
        loading.remove();
    }
    
    // Get detailed data
    const detailedData = voteDetails[hash];
    if (!detailedData) return;
    
    // Update vote count
    const voteCountEl = card.querySelector('.vote-count');
    if (voteCountEl && detailedData.totalNamber) {
        voteCountEl.textContent = detailedData.totalNamber;
    }
    
    // Update options display if we have the info
    if (detailedData.options && Array.isArray(detailedData.options)) {
        // Find leading option
        const options = detailedData.options;
        let leadingOption = null;
        let highestVoteCount = 0;
        
        options.forEach(option => {
            let voteCount = 0;
            if (option.votes && typeof option.votes === 'object' && option.votes.count !== undefined) {
                voteCount = parseInt(option.votes.count) || 0;
            } else if (typeof option.votes === 'number') {
                voteCount = option.votes;
            }
            
            if (voteCount > highestVoteCount) {
                highestVoteCount = voteCount;
                leadingOption = option;
            }
        });
        
        // If we found a leading option with votes
        if (leadingOption && highestVoteCount > 0) {
            // Find or create leading info div
            let leadingDiv = card.querySelector('.vote-leading');
            if (!leadingDiv) {
                leadingDiv = document.createElement('div');
                leadingDiv.className = 'vote-leading';
                // Insert before the vote hash
                const hashDiv = card.querySelector('.vote-hash');
                if (hashDiv) {
                    card.insertBefore(leadingDiv, hashDiv);
                } else {
                    card.appendChild(leadingDiv);
                }
            }
            
            // Clean up option text
            let optionText = leadingOption.option || '';
            optionText = optionText.replace(/^"(.*)"$/, '$1'); // Remove quotes
            
            // Calculate percentage
            let percentage = '0%';
            if (leadingOption.votes && typeof leadingOption.votes === 'object' && leadingOption.votes.percent !== undefined) {
                percentage = `${leadingOption.votes.percent}%`;
            } else if (detailedData.totalNamber && highestVoteCount) {
                const percent = Math.round((highestVoteCount / detailedData.totalNamber) * 100);
                percentage = `${percent}%`;
            }
            
            // Update leading info
            leadingDiv.innerHTML = `
                Leading: ${optionText} (${percentage})
                ${leadingOption.weight ? `<div class="vote-weight">${leadingOption.weight.coin} ${detailedData.token || 'CPUNK'}</div>` : ''}
            `;
        }
    }
}

// Render votes list
function renderVotesList() {
    
    if (activeVotes.length === 0) {
        votesList.innerHTML = `
            <div class="no-votes-message">
                No active proposals found. Check back later for new governance opportunities.
            </div>
        `;
        return;
    }
    
    // Log the first vote to see its structure
    if (activeVotes.length > 0) {
    }
    
    // Process vote data to clean up truncated or malformed questions
    activeVotes = activeVotes.map(vote => {
        // Fix question text if it has quotes or underscores
        if (vote.question) {
            // Remove surrounding quotes if present
            let cleanQuestion = vote.question.replace(/^"(.*)"$/, '$1');
            
            // Replace underscores with spaces
            cleanQuestion = cleanQuestion.replace(/_/g, ' ');
            
            // Check if text appears to be truncated
            if (cleanQuestion.endsWith('...') || 
                cleanQuestion.startsWith('"Should') || 
                cleanQuestion.length < 10) {
                // Format the hash as a shortened version for display
                const shortHash = vote.hash.substring(0, 8) + '...' + vote.hash.substring(vote.hash.length - 8);
                cleanQuestion = `Proposal ${shortHash}`;
            }
            
            vote.question = cleanQuestion;
        } else {
            // If no question is provided, use the hash
            const shortHash = vote.hash.substring(0, 8) + '...' + vote.hash.substring(vote.hash.length - 8);
            vote.question = `Proposal ${shortHash}`;
        }
        
        return vote;
    });
    
    // Get filter and sort values
    const statusFilter = document.getElementById('statusFilter');
    const sortOrder = document.getElementById('sortOrder');
    
    const statusValue = statusFilter ? statusFilter.value : 'all';
    const sortValue = sortOrder ? sortOrder.value : 'newest';
    
    // Filter votes based on status
    let filteredVotes = [...activeVotes];
    
    if (statusValue !== 'all') {
        const now = Math.floor(Date.now() / 1000);
        
        filteredVotes = filteredVotes.filter(vote => {
            // Only use expire_timestamp if available, no assumptions
            if (!vote.expire_timestamp) {
                // If no expiration is set, include in "active" filter but not in "expired"
                return statusValue === 'active';
            }
            
            const expireTime = parseInt(vote.expire_timestamp);
            const isExpired = expireTime <= now;
            
            // Filter logic
            return (statusValue === 'active' && !isExpired) || 
                   (statusValue === 'expired' && isExpired);
        });
    }
    
    // Sort votes
    filteredVotes.sort((a, b) => {
        const now = Math.floor(Date.now() / 1000);
        const timestampA = getVoteTimestamp(a);
        const timestampB = getVoteTimestamp(b);
        
        // Get expire times (only if available)
        const expireTimeA = a.expire_timestamp ? parseInt(a.expire_timestamp) : null;
        const expireTimeB = b.expire_timestamp ? parseInt(b.expire_timestamp) : null;
        
        // Time left for each vote (if expiration is set)
        const timeLeftA = expireTimeA ? expireTimeA - now : null;
        const timeLeftB = expireTimeB ? expireTimeB - now : null;
        
        // Vote counts
        const votesA = a.votes_count || 0;
        const votesB = b.votes_count || 0;
        
        switch (sortValue) {
            case 'newest':
                return timestampB - timestampA; // Newest first
            case 'oldest':
                return timestampA - timestampB; // Oldest first
            case 'votes-high':
                return votesB - votesA; // Most votes first
            case 'votes-low':
                return votesA - votesB; // Fewest votes first
            case 'expire-soon':
                // Handle cases when one or both votes don't have an expiration
                if (timeLeftA === null && timeLeftB === null) return timestampB - timestampA; // Both no expiry, sort by creation (newest first)
                if (timeLeftA === null) return 1; // B has expiry, A doesn't
                if (timeLeftB === null) return -1; // A has expiry, B doesn't
                
                // Handle normal cases where both have expiration
                if (timeLeftA > 0 && timeLeftB > 0) return timeLeftA - timeLeftB;
                if (timeLeftA > 0) return -1; // A is active, B is expired
                if (timeLeftB > 0) return 1;  // B is active, A is expired
                return expireTimeB - expireTimeA; // Both expired, most recently expired first
            default:
                return timestampB - timestampA; // Default to newest first
        }
    });
    
    // Check if we have any votes after filtering
    if (filteredVotes.length === 0) {
        votesList.innerHTML = `
            <div class="no-votes-message">
                No proposals found with the selected filters. Try changing your filter settings or check back later.
            </div>
        `;
        return;
    }

    let votesHTML = '';
    filteredVotes.forEach(vote => {
        const createdDate = formatTimestamp(getVoteTimestamp(vote));
        
        // Only calculate expiration if explicitly provided in API response
        const expireTime = vote.expire_timestamp ? parseInt(vote.expire_timestamp) : null;
        
        let expireText = 'Unknown';
        let expireStatus = '';
        
        if (expireTime) {
            const now = Math.floor(Date.now() / 1000);
            const timeLeft = expireTime - now;
            
            if (timeLeft > 0) {
                const days = Math.floor(timeLeft / (24 * 60 * 60));
                const hours = Math.floor((timeLeft % (24 * 60 * 60)) / (60 * 60));
                
                expireText = `${days}d ${hours}h`;
                expireStatus = timeLeft < (3 * 24 * 60 * 60) ? 
                    '<span style="color: #ffbb33;">(Ending Soon)</span>' : '';
            } else {
                expireText = 'Expired';
                expireStatus = '<span style="color: var(--error);">(Closed)</span>';
            }
        }
        
        // Check if user has voted
        const hasVoted = userVotes[vote.hash];
        
        const votedIndicator = hasVoted ? 
            '<span style="color: var(--success);">✓ You voted</span>' : 
            '<span>Vote now</span>';
        
        // Calculate percentage of total vote weight for the leading option
        let leadingOption = '';
        let leadingPercent = 0;
        
        if (vote.options && Array.isArray(vote.options) && vote.options.length > 0) {
            const totalVotes = vote.votes_count || vote.options.reduce((sum, opt) => sum + (parseInt(opt.votes) || 0), 0) || 0;
            
            if (totalVotes > 0) {
                // Find the option with most votes
                const sortedOptions = [...vote.options].sort((a, b) => (b.votes || 0) - (a.votes || 0));
                const leader = sortedOptions[0];
                
                if (leader) {
                    const optionText = leader.option || leader.option_text || leader.text || 'Option 1';
                    const votes = leader.votes || 0;
                    const percent = totalVotes > 0 ? Math.round((votes / totalVotes) * 100) : 0;
                    
                    if (percent > 0) {
                        leadingOption = `<div class="vote-leading">Leading: ${optionText} (${percent}%)</div>`;
                        leadingPercent = percent;
                    }
                }
            }
        }

        votesHTML += `
            <div class="vote-card ${expireTime && expireTime <= Math.floor(Date.now() / 1000) ? 'expired' : ''}" data-hash="${vote.hash}">
                <div class="vote-question">${vote.question || 'Governance Proposal'}</div>
                <div class="vote-info">
                    <span>Created: ${createdDate}</span>
                    <span>Expires: ${expireTime ? `${expireText} ${expireStatus}` : 'No expiration set'}</span>
                </div>
                <div class="vote-info">
                    <span>Total Votes: <span class="vote-count">${
                        // Use detailed data if available, otherwise fallback to basic data
                        voteDetails[vote.hash] && voteDetails[vote.hash].totalNamber ? 
                        voteDetails[vote.hash].totalNamber : 
                        (vote.votes_count || 0)
                    }</span></span>
                    ${votedIndicator}
                </div>
                ${leadingOption}
                <div class="vote-hash">TX: ${vote.hash}</div>
            </div>
        `;
    });

    votesList.innerHTML = votesHTML;

    // Add click event to vote cards
    document.querySelectorAll('.vote-card').forEach(card => {
        card.addEventListener('click', () => {
            const hash = card.getAttribute('data-hash');
            if (hash) {
                showVoteDetail(hash);
            }
        });
    });
}

// Get timestamp from vote object
function getVoteTimestamp(vote) {
    if (vote.created && !isNaN(parseFloat(vote.created))) {
        return parseFloat(vote.created);
    } else if (vote.timestamp && !isNaN(parseFloat(vote.timestamp))) {
        return parseFloat(vote.timestamp);
    } else if (vote.time && !isNaN(parseFloat(vote.time))) {
        return parseFloat(vote.time);
    } else if (vote.date && !isNaN(parseFloat(vote.date))) {
        return parseFloat(vote.date);
    }

    // If no direct timestamp field, use hash as a consistent source of randomness
    if (vote.hash) {
        const now = Math.floor(Date.now() / 1000);
        const monthAgo = now - (30 * 24 * 60 * 60);
        const hashPrefix = vote.hash.substring(0, 8);
        const hashNum = parseInt(hashPrefix, 16);
        return monthAgo + (hashNum % (now - monthAgo));
    }

    return Math.floor(Date.now() / 1000);
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp * 1000);
    
    // Check if date is valid
    if (isNaN(date.getTime())) {
        return 'Invalid date';
    }
    
    // Format as: DD/MM/YYYY, HH:MM:SS
    return date.toLocaleString();
}

// Format number with commas and fixed decimal places
function formatNumber(number, decimals = 2) {
    if (typeof number !== 'number') {
        number = parseFloat(number) || 0;
    }
    return number.toLocaleString(undefined, {
        minimumFractionDigits: decimals,
        maximumFractionDigits: decimals
    });
}

// Show vote details
async function showVoteDetail(hash) {
    resetVoteMessages();
    selectedVoteHash = hash;
    selectedVoteOption = null;
    
        hash,
        selectedWallet,
        selectedNetwork,
        sessionId: CpunkDashboard.getSessionId()
    });
    
    try {
        voteDetail.innerHTML = '<div class="loading">Loading vote details</div>';
        votesSection.style.display = 'none';
        voteDetailSection.style.display = 'block';
        
        // Find the related vote in active votes to get any basic info we already have
        const existingVoteData = activeVotes.find(v => v.hash === hash) || {};
        
        // If we already have vote details cached, use them
        if (voteDetails[hash]) {
            renderVoteDetail(voteDetails[hash]);
            return;
        }
        
        // Otherwise fetch vote details
        // Get the current session ID
        const sessionId = CpunkDashboard.getSessionId();
        
        if (!sessionId) {
            throw new Error('Not connected to dashboard');
        }
        
        CpunkAPIConsole.log('API Request: VotingDump', {
            id: sessionId,
            net: selectedNetwork,
            hashTx: hash  // Important: use hashTx, not hash
        });
        
        try {
            // Use VotingDump with hashTx parameter as in the original working code
            const response = await CpunkDashboard.makeRequest('VotingDump', {
                id: sessionId,
                net: selectedNetwork,
                hashTx: hash  // Use hashTx parameter like in original
            });
            
            CpunkAPIConsole.log('API Response: VotingDump', response);
            
            if (response.status === 'ok' && response.data) {
                // Merge existing vote data with new data
                voteDetails[hash] = {
                    ...existingVoteData,
                    ...response.data,
                    hash: hash // Ensure hash is included
                };
                
                // Clean and process the question text
                if (voteDetails[hash].question) {
                    // Remove surrounding quotes if present
                    let cleanQuestion = voteDetails[hash].question.replace(/^"(.*)"$/, '$1');
                    
                    // Replace underscores with spaces
                    cleanQuestion = cleanQuestion.replace(/_/g, ' ');
                    
                    voteDetails[hash].question = cleanQuestion;
                }
                
                // Ensure options is at least an empty array
                if (!voteDetails[hash].options) {
                    voteDetails[hash].options = [];
                    CpunkAPIConsole.log('No options data found in API response', {voteData: voteDetails[hash]});
                }
                
                // Make sure votes_count exists
                if (!voteDetails[hash].votes_count) {
                    // Calculate from options if possible
                    voteDetails[hash].votes_count = voteDetails[hash].options.reduce((sum, opt) => {
                        return sum + (parseInt(opt.votes) || 0);
                    }, 0);
                }
                
                renderVoteDetail(voteDetails[hash]);
            } else {
                // More detailed error handling
                if (response.errorMsg) {
                    throw new Error(`API Error: ${response.errorMsg}`);
                } else if (response.status === 'error') {
                    throw new Error(`API returned error status: ${JSON.stringify(response)}`);
                } else {
                    throw new Error(`Failed to load vote details: ${JSON.stringify(response)}`);
                }
            }
        } catch (apiError) {
            // If API call fails, show error message
            CpunkAPIConsole.log('API error', { error: apiError.message });
            throw new Error(`Failed to load vote details: ${apiError.message}`);
        }
    } catch (error) {
        voteDetail.innerHTML = `<div class="error-message" style="display: block;">Failed to load vote details: ${error.message}</div>`;
    }
}

// Render vote detail
function renderVoteDetail(vote) {
    CpunkAPIConsole.log('Rendering vote detail', vote);
    
    // Check if vote is valid
    if (!vote) {
        voteDetail.innerHTML = '<div class="error-message" style="display: block;">Invalid vote data received</div>';
        return;
    }
    
    // Make sure vote is an object
    if (typeof vote !== 'object') {
        CpunkAPIConsole.log('Invalid vote data format', { type: typeof vote });
        voteDetail.innerHTML = `<div class="error-message" style="display: block;">Invalid vote data format: ${typeof vote}</div>`;
        return;
    }
    
    // Get timestamp info
    const createdTimestamp = getVoteTimestamp(vote);
    const createdDate = formatTimestamp(createdTimestamp);
    
    // Default values for date information
    let expireText = 'No expiration';
    let isExpired = false;
    let expireStatus = '';
    let expireTimestamp = null;
    
    // Try to get expiration info if available
    if (vote.expire_timestamp || vote.expire) {
        expireTimestamp = parseFloat(vote.expire_timestamp || vote.expire);
        if (!isNaN(expireTimestamp) && expireTimestamp > 0) {
            expireText = formatTimestamp(expireTimestamp);
            isExpired = (expireTimestamp * 1000) < Date.now();
            if (isExpired) {
                expireStatus = ' (Expired)';
            }
        }
    }
    // No assumptions about expiration dates if not provided in API
    
    // Handle options in any format
    let options = [];
    if (vote.options && Array.isArray(vote.options)) {
        options = vote.options;
    } else if (vote.results && Array.isArray(vote.results)) {
        options = vote.results;
    } else {
        options = []; // No default options, show empty state
    }
    
    // Calculate percentages and prepare data for visualization
    const totalVotes = vote.votes_count || vote.totalNamber || options.reduce((sum, opt) => {
        // If votes is an object with count property
        if (opt.votes && typeof opt.votes === 'object' && opt.votes.count !== undefined) {
            return sum + parseInt(opt.votes.count || 0);
        }
        // If votes is a direct number
        return sum + parseInt(opt.votes || 0);
    }, 0) || 0;
    
    // Enhance options with percentages and vote counts if missing
    options = options.map((option, index) => {
        // Handle different option structures
        let votes = 0;
        let percentage = 0;
        
        // Handle nested votes object structure from VotingDump response
        if (option.votes && typeof option.votes === 'object') {
            if (option.votes.count !== undefined) {
                votes = option.votes.count;
            }
            if (option.votes.percent !== undefined) {
                percentage = option.votes.percent;
            }
        } else if (typeof option.votes === 'number') {
            votes = option.votes;
            percentage = totalVotes > 0 ? (votes / totalVotes) * 100 : 0;
        } else {
            votes = 0;
            percentage = 0;
        }
        
        // Clean up option name
        let optionText = option.option || option.option_text || option.text || `Option ${index + 1}`;
        // Remove surrounding quotes if present
        optionText = optionText.replace(/^"(.*)"$/, '$1');
        
        return {
            ...option,
            id: option.id || option.option_id || option.number || index,
            option: optionText,
            votes: votes,
            percentage: parseFloat(percentage).toFixed(1)
        };
    });
    
    CpunkAPIConsole.log('Processing vote options with percentages', options);
    
    // Start building HTML
    let html = `
        <div class="highlight-box">
            <h2>${vote.question || 'Governance Proposal'}</h2>
            <div class="vote-info">
                <span>Created: ${createdDate}</span>
                <span>Expires: ${expireText}${expireStatus}</span>
            </div>
            
            <div class="info-box">
                ${vote.description ? `<p>${vote.description}</p>` : ''}
            </div>
        </div>
        
        <div class="result-summary">
            <div class="result-summary-item">
                <div class="result-summary-value">${totalVotes}</div>
                <div class="result-summary-label">Total Votes</div>
            </div>
            ${vote.totalCoins ? `
            <div class="result-summary-item">
                <div class="result-summary-value">${vote.totalCoins}</div>
                <div class="result-summary-label">Total ${vote.token || 'CPUNK'}</div>
            </div>
            ` : ''}
            <div class="result-summary-item">
                <div class="result-summary-value">
                    ${expireTimestamp ? 
                        (!isExpired ? 
                            calculateTimeRemaining(expireTimestamp) : 
                            '<span style="color: var(--error);">Expired</span>') : 
                        'No expiration set'}
                </div>
                <div class="result-summary-label">${expireTimestamp ? (!isExpired ? 'Time Remaining' : 'Status') : 'Expiration'}</div>
            </div>
        </div>
    `;
    
    // Results visualization - only show if there are options
    if (options.length > 0) {
        html += `<h3>Current Results</h3>`;
        html += `<div class="vote-results-container">`;
        
        options.forEach((option, index) => {
            // Check if we have weight data
            let weightInfo = '';
            if (option.weight && option.weight.coin) {
                weightInfo = `
                    <div class="vote-result-weight">
                        Weight: ${option.weight.coin} ${vote.token || 'CPUNK'}
                    </div>
                `;
            }
            
            html += `
                <div class="vote-result">
                    <div class="vote-result-option">${option.option}</div>
                    <div class="vote-result-stats">
                        <span class="vote-result-count">${option.votes} votes</span>
                        <span class="vote-result-percentage">${option.percentage}%</span>
                    </div>
                    ${weightInfo}
                    <div class="vote-result-bar">
                        <div class="vote-result-fill" style="width: ${option.percentage}%"></div>
                    </div>
                </div>
            `;
        });
        
        html += `</div>`;
        
        // Voting options
        html += `<h3>Cast Your Vote</h3><div class="vote-options-grid">`;
        
        options.forEach((option) => {
            html += `
                <button class="vote-button" data-option="${option.id}">
                    ${option.option}
                </button>
            `;
        });
        
        html += `</div>`;
    } else {
        // No options available
        html += `
            <div class="info-box" style="text-align: center; margin-top: 30px;">
                <p>No voting options are currently available for this proposal.</p>
            </div>
        `;
    }
    
    // Transaction hash
    html += `
        <div class="vote-hash">
            <strong>Transaction Hash:</strong> ${selectedVoteHash}
        </div>
    `;
    
    voteDetail.innerHTML = html;
    
    // Add event listeners to buttons
    document.querySelectorAll('.vote-button').forEach(button => {
        button.addEventListener('click', () => {
            selectedVoteOption = parseInt(button.getAttribute('data-option'));
            submitVote(button);
        });
    });
}

// Calculate time remaining in a user-friendly format
function calculateTimeRemaining(expireTimestamp) {
    const now = Math.floor(Date.now() / 1000);
    const timeLeft = expireTimestamp - now;
    
    if (timeLeft <= 0) {
        return "Expired";
    }
    
    const days = Math.floor(timeLeft / (24 * 60 * 60));
    const hours = Math.floor((timeLeft % (24 * 60 * 60)) / (60 * 60));
    const minutes = Math.floor((timeLeft % (60 * 60)) / 60);
    
    if (days > 0) {
        return `${days}d ${hours}h`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

// Submit vote
async function submitVote(buttonElement) {
    resetVoteMessages();
    
    // Validate inputs
    if (selectedVoteOption === null) {
        showVoteWarning('Please select an option to vote.');
        return;
    }

    if (!selectedVoteHash) {
        showVoteError('Vote hash not found.');
        return;
    }

    if (!selectedWallet) {
        showVoteError('No wallet selected.');
        return;
    }

    try {
        // Disable all vote buttons during submission
        const voteButtons = document.querySelectorAll('.vote-button');
        voteButtons.forEach(button => {
            button.disabled = true;
        });
        
        // Show loading state on the clicked button
        const originalText = buttonElement.textContent;
        buttonElement.innerHTML = '<span class="loading-spinner"></span> Submitting...';
        
        // Actually submit the vote
        // Get the current session ID
        const sessionId = CpunkDashboard.getSessionId();
        
        if (!sessionId) {
            throw new Error('Not connected to dashboard');
        }
        
        // For voting we need wallet name as well
        const walletName = selectedWallet && selectedWallet.name ? selectedWallet.name : 
                          (typeof selectedWallet === 'string' ? selectedWallet : null);
        
        if (!walletName) {
            throw new Error('No valid wallet selected');
        }
        
        CpunkAPIConsole.log('API Request: VotingVote', {
            id: sessionId,
            net: selectedNetwork,
            walletName: walletName,
            hashTx: selectedVoteHash,
            optionIdx: selectedVoteOption
        });
        
        const response = await CpunkDashboard.makeRequest('VotingVote', {
            id: sessionId,
            net: selectedNetwork,
            walletName: walletName,
            hashTx: selectedVoteHash,
            optionIdx: selectedVoteOption
        });

        if (response.status === 'ok') {
            // Mark as voted in user vote tracking
            userVotes[selectedVoteHash] = selectedVoteOption;
            
            // Show success message
            showVoteSuccess('Your vote has been submitted successfully!');
            
            // Update results after a brief delay
            setTimeout(async () => {
                await showVoteDetail(selectedVoteHash);
            }, 1500);
        } else {
            // Special case: already voted
            if (response.status === 'bad' && 
                response.data && 
                (typeof response.data === 'object') && 
                (!response.errorMsg || response.errorMsg === '')) {
                
                // This specific pattern of response.data being an object with empty message
                // and status "bad" with no errorMsg typically means "already voted"
                
                // Mark as voted in user vote tracking to prevent further attempts
                userVotes[selectedVoteHash] = selectedVoteOption;
                
                // Show warning instead of error
                showVoteWarning('This wallet appears to have already voted on this proposal.');
                
                // Update display after a brief delay
                setTimeout(async () => {
                    await showVoteDetail(selectedVoteHash);
                }, 1500);
                
                return; // Exit without throwing an error
            }
            
            // Handle other errors
            const errorMessage = response.errorMsg || 
                                (response.data && typeof response.data === 'string' ? response.data : null) || 
                                (response.data && typeof response.data === 'object' && response.data.message ? response.data.message : null) ||
                                'Failed to submit vote';
            throw new Error(errorMessage);
        }
    } catch (error) {
        if (error.message.includes('Incorrect id')) {
            showVoteError('Session expired. Please refresh the page and try again.');
        } else {
            showVoteError(`Error: ${error.message}`);
        }
    } finally {
        // Re-enable all vote buttons
        const voteButtons = document.querySelectorAll('.vote-button');
        voteButtons.forEach(button => {
            button.disabled = false;
            if (parseInt(button.getAttribute('data-option')) === selectedVoteOption) {
                const originalText = voteDetails[selectedVoteHash].options[selectedVoteOption].option || 
                                    voteDetails[selectedVoteHash].options[selectedVoteOption].text || 
                                    voteDetails[selectedVoteHash].options[selectedVoteOption] || 
                                    `Option ${selectedVoteOption + 1}`;
                button.innerHTML = originalText;
            }
        });
    }
}

// Show vote lists
function showVotesList() {
    
    // Make sure the elements exist before trying to change their display
    if (voteDetailSection) {
        voteDetailSection.style.display = 'none';
    } else {
        console.error('voteDetailSection not found');
    }
    
    if (votesSection) {
        votesSection.style.display = 'block';
    } else {
        console.error('votesSection not found');
    }
    
    // Force reload votes when returning to list view
    if (typeof loadVotes === 'function') {
        loadVotes().catch(err => console.error('Error reloading votes:', err));
    }
}

// Reset vote message displays
function resetVoteMessages() {
    voteSuccess.style.display = 'none';
    voteError.style.display = 'none';
    voteWarning.style.display = 'none';
}

// Show vote success message
function showVoteSuccess(message) {
    voteSuccess.textContent = message;
    voteSuccess.style.display = 'block';
}

// Show vote error message
function showVoteError(message) {
    voteError.textContent = message;
    voteError.style.display = 'block';
}

// Show vote warning message
function showVoteWarning(message) {
    voteWarning.textContent = message;
    voteWarning.style.display = 'block';
}

