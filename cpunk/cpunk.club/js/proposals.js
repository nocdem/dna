// State variables
let walletAddress = null;
let currentDna = null;
const selectedNetwork = 'Cpunk'; // Hardcoded to always use Cpunk network
let activeProposals = [];
let proposalDetails = {};
let selectedProposalId = null;
let userVotes = {};
let selectedVoteOption = null;

// DOM Elements
let walletSection;
let walletsList;
let proposalsSection;
let selectedWalletName;
let proposalsList;
let proposalDetailSection;
let proposalDetail;
let voteControls;
let voteOptionsGrid;
let voteSuccess;
let voteError;
let voteWarning;
let backButton;

// API URL
const API_URL = 'http://localhost:8045/';

// Sample proposals data (until API integration)
const sampleProposals = [
    {
        id: "cip-1",
        number: 1,
        title: "Migration to $CPUNK Parachain",
        status: "draft",
        type: "Network Infrastructure",
        category: "Governance and Blockchain Development",
        created: Math.floor(Date.now() / 1000),
        votingStart: null,
        votingEnd: null,
        abstract: "We propose migrating the $CPUNK ecosystem from the Cellframe Backbone Network to our own parachain: $CPUNK Parachain. The primary objective is to migrate the DNA system to the new parachain, enhancing data control and security.",
        content: `
# $CPUNK Improvement Proposal (CIP) #1: Migration to $CPUNK Parachain

## Title: Migration from Cellframe Backbone Network to $CPUNK Parachain
**Status:** Draft
**Type:** Network Infrastructure
**Category:** Governance and Blockchain Development
**Voting Period:** [Start Date - End Date]

## Abstract:
We propose migrating the $CPUNK ecosystem from the Cellframe Backbone Network to our own parachain: $CPUNK Parachain. The primary objective is to migrate the DNA system to the new parachain, enhancing data control and security. The Global Database (GDB) will be repurposed as a cache for DNA data, significantly improving performance. Additionally, the migration will enable the integration of advanced features like native NFT support and custom on-chain data.

## Motivation:
The DNA system is the backbone of $CPUNK, crucial for identity management and user authentication. Currently, DNA is hosted on the Cellframe Backbone Network, which limits our control and flexibility. Migrating the DNA system to the $CPUNK Parachain will provide full autonomy, faster data retrieval, and seamless integration within the ecosystem.

Moreover, having our own parachain will allow us to build features that are currently impossible on Backbone, such as NFTs and custom on-chain data. This move will make $CPUNK more self-sufficient and enable a wider range of community-driven applications.

## Details of the Migration:
### 1. DNA Migration and GDB Caching:

Move the DNA system from Cellframe Backbone to the $CPUNK Parachain.

Use the Global Database (GDB) as a cache for DNA data, ensuring fast access while maintaining on-chain integrity.

DNA on the parachain will be the primary source of truth, with GDB synchronizing regularly.

This approach ensures faster data retrieval while minimizing blockchain bloat.

### 2. Parachain Establishment:

Set up the $CPUNK Parachain, prioritizing DNA integration and stability.

Introduce native support for NFTs and custom data once DNA migration is completed.

Implement a governance module to facilitate community-driven decision-making.

### 3. Validator Structure:

Validators must hold at least 10 million $CPUNK to participate.

Validators will secure the network, validate transactions, and maintain network stability.

No transaction fees for standard transactions, particularly DNA-related ones.

Transactions involving custom data or NFTs will have fees to prevent spam and support maintenance.

### 4. Validator Rewards and Funding:

Allocate 100 million $CPUNK from the treasury to support the migration and reward validators.

Reward Distribution:

Year 1: 50 million $CPUNK, distributed based on validator weight.

Year 2: 25 million $CPUNK

Year 3: 12.5 million $CPUNK

Halving rewards each subsequent year ensures sustainability.

## Benefits:
- Full control over the DNA system, enhancing identity management and data consistency.
- Faster data access by leveraging GDB as a cache.
- Advanced functionality with NFTs and custom on-chain data.
- Free DNA-related transactions, promoting adoption.
- Sustainable validator incentives with a gradual decrease in rewards.
- Complete autonomy over the network, independent of the Cellframe Backbone.

## Next Steps:
1. Collect feedback from the community and the $CPUNK Council.
2. Refine the technical implementation plan based on feedback.
3. Schedule the first governance vote to approve the migration proposal.

## Conclusion:
This migration to the $CPUNK Parachain will secure the future of $CPUNK by giving us full control over our DNA system and enabling advanced features. By leveraging GDB as a caching layer, we maintain fast and reliable access to essential data while reducing blockchain congestion. This transition will position $CPUNK as a more independent, efficient, and feature-rich ecosystem.

We invite all Council members and community stakeholders to participate in the discussion and share their insights. Your input is crucial for making this historic decision for the future of $CPUNK.
`
    }
];

document.addEventListener('DOMContentLoaded', function() {
    // Initialize utilities
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
    
    // Initialize SSO and check authentication
    if (typeof CpunkSSO !== 'undefined') {
        CpunkSSO.getInstance().init({
            requireAuth: false, // Don't require auth for viewing proposals
            onAuthenticated: function(userData) {
                // User is authenticated
                console.log('User authenticated:', userData);
                
                // Store wallet and DNA info
                walletAddress = userData.wallet;
                currentDna = userData.dna;
                
                // Update selected wallet display with DNA name
                if (selectedWalletName) selectedWalletName.textContent = currentDna;
            },
            onUnauthenticated: function() {
                // User is not authenticated - that's ok for viewing proposals
                console.log('User not authenticated - view-only mode');
            }
        });
    } else {
        console.error('CpunkSSO not found. Make sure sso.js is loaded.');
    }
    
    // Initialize DOM elements
    walletSection = document.getElementById('walletSection');
    walletsList = document.getElementById('walletsList');
    proposalsSection = document.getElementById('proposalsSection');
    selectedWalletName = document.getElementById('selectedWalletName');
    proposalsList = document.getElementById('proposalsList');
    proposalDetailSection = document.getElementById('proposalDetailSection');
    proposalDetail = document.getElementById('proposalDetail');
    voteControls = document.getElementById('voteControls');
    voteOptionsGrid = document.getElementById('voteOptionsGrid');
    voteSuccess = document.getElementById('voteSuccess');
    voteError = document.getElementById('voteError');
    voteWarning = document.getElementById('voteWarning');
    backButton = document.getElementById('backButton');
    
    // Filter and sort elements
    const statusFilter = document.getElementById('statusFilter');
    const sortOrder = document.getElementById('sortOrder');
    
    // Set up event listeners
    if (backButton) {
        backButton.addEventListener('click', function(event) {
            event.preventDefault();
            showProposalsList();
        });
    }
    
    // Add filter event listeners
    if (statusFilter) {
        statusFilter.addEventListener('change', () => {
            renderProposalsList(); // Re-render with new filters
        });
    }
    
    // Add sort event listeners
    if (sortOrder) {
        sortOrder.addEventListener('change', () => {
            renderProposalsList(); // Re-render with new sort order
        });
    }
    
    // Hide wallet section since authentication is handled by SSO
    if (walletSection) walletSection.style.display = 'none';
    
    // Show the proposals list immediately without requiring authentication
    proposalsSection.style.display = 'block';
    loadProposals();
    
    // Remove connect button handler as it's no longer needed
    const connectButton = document.getElementById('connectButton');
    if (connectButton) {
        connectButton.style.display = 'none';
    }
});

// These wallet-related functions are no longer needed as authentication is handled by SSO
// Wallet selection UI has been removed from the proposals page

// Load active proposals
async function loadProposals() {
    try {
        proposalsList.innerHTML = '<div class="loading">Loading proposals</div>';
        
        // This is where you would normally fetch proposals from the API
        // For now, using sample data
        activeProposals = [...sampleProposals];
        
        renderProposalsList();
            
    } catch (error) {
        proposalsList.innerHTML = `<div class="error-message" style="display: block;">Failed to load proposals: ${error.message}</div>`;
    }
}

// Render proposals list
function renderProposalsList() {
    if (activeProposals.length === 0) {
        proposalsList.innerHTML = `
            <div class="no-proposals-message">
                No proposals found. Check back later for new improvement proposals.
            </div>
        `;
        return;
    }
    
    // Get filter and sort values
    const statusFilter = document.getElementById('statusFilter');
    const sortOrder = document.getElementById('sortOrder');
    
    const statusValue = statusFilter ? statusFilter.value : 'all';
    const sortValue = sortOrder ? sortOrder.value : 'newest';
    
    // Filter proposals based on status
    let filteredProposals = [...activeProposals];
    
    if (statusValue !== 'all') {
        filteredProposals = filteredProposals.filter(proposal => proposal.status === statusValue);
    }
    
    // Sort proposals
    filteredProposals.sort((a, b) => {
        switch (sortValue) {
            case 'newest':
                return b.created - a.created; // Newest first
            case 'oldest':
                return a.created - b.created; // Oldest first
            case 'number-asc':
                return a.number - b.number; // Lowest number first
            case 'number-desc':
                return b.number - a.number; // Highest number first
            default:
                return b.created - a.created; // Default to newest first
        }
    });
    
    // Check if we have any proposals after filtering
    if (filteredProposals.length === 0) {
        proposalsList.innerHTML = `
            <div class="no-proposals-message">
                No proposals found with the selected filters. Try changing your filter settings.
            </div>
        `;
        return;
    }

    let proposalsHTML = '';
    filteredProposals.forEach(proposal => {
        const createdDate = formatTimestamp(proposal.created);
        
        let votingPeriod = '';
        if (proposal.votingStart && proposal.votingEnd) {
            votingPeriod = `${formatTimestamp(proposal.votingStart)} - ${formatTimestamp(proposal.votingEnd)}`;
        } else {
            votingPeriod = 'Not scheduled';
        }
        
        proposalsHTML += `
            <div class="proposal-card ${proposal.status}" data-id="${proposal.id}">
                <div class="proposal-number">CIP-${proposal.number}</div>
                <div class="proposal-status ${proposal.status}">${capitalizeFirstLetter(proposal.status)}</div>
                <div class="proposal-title">${proposal.title}</div>
                <div class="proposal-type">${proposal.type}</div>
                <div class="proposal-category">${proposal.category}</div>
                <div class="proposal-info">
                    <span>Created: ${createdDate}</span>
                    <span>Vote: ${votingPeriod}</span>
                </div>
                <div class="proposal-abstract">${proposal.abstract}</div>
            </div>
        `;
    });

    proposalsList.innerHTML = proposalsHTML;

    // Add click event to proposal cards
    document.querySelectorAll('.proposal-card').forEach(card => {
        card.addEventListener('click', () => {
            const id = card.getAttribute('data-id');
            if (id) {
                showProposalDetail(id);
            }
        });
    });
}

// Show proposal details
function showProposalDetail(id) {
    selectedProposalId = id;
    
    try {
        proposalDetail.innerHTML = '<div class="loading">Loading proposal details</div>';
        proposalsSection.style.display = 'none';
        proposalDetailSection.style.display = 'block';
        
        // Find the proposal in our active proposals
        const proposal = activeProposals.find(p => p.id === id);
        if (!proposal) {
            throw new Error('Proposal not found');
        }
        
        renderProposalDetail(proposal);
        
    } catch (error) {
        proposalDetail.innerHTML = `<div class="error-message" style="display: block;">Failed to load proposal details: ${error.message}</div>`;
    }
}

// Render proposal detail
function renderProposalDetail(proposal) {
    // Format the content from markdown to HTML (simplified version)
    const formattedContent = formatMarkdown(proposal.content);
    
    // Build the header with metadata
    let html = `
        <div class="proposal-detail-header">
            <h1 class="proposal-detail-title">
                <span class="proposal-detail-number">CIP-${proposal.number}</span>
                ${proposal.title}
            </h1>
            <div class="proposal-detail-status ${proposal.status}">${capitalizeFirstLetter(proposal.status)}</div>
        </div>
        
        <div class="proposal-meta">
            <div class="proposal-meta-item">
                <span>Type:</span> ${proposal.type}
            </div>
            <div class="proposal-meta-item">
                <span>Category:</span> ${proposal.category}
            </div>
            <div class="proposal-meta-item">
                <span>Created:</span> ${formatTimestamp(proposal.created)}
            </div>
            <div class="proposal-meta-item">
                <span>Voting Period:</span> ${proposal.votingStart && proposal.votingEnd ? 
                    `${formatTimestamp(proposal.votingStart)} - ${formatTimestamp(proposal.votingEnd)}` : 
                    'Not scheduled'}
            </div>
        </div>
    `;
    
    // Add the formatted content
    html += `<div class="proposal-content">${formattedContent}</div>`;
    
    // If the proposal is in voting stage, show vote controls based on connection status
    if (proposal.status === 'voting') {
        if (selectedWallet && CpunkDashboard.isConnected()) {
            // User is connected and has selected a wallet - show voting controls
            voteControls.style.display = 'block';
            voteOptionsGrid.innerHTML = `
                <button class="vote-button" data-option="support">Support</button>
                <button class="vote-button" data-option="oppose">Oppose</button>
                <button class="vote-button" data-option="abstain">Abstain</button>
            `;
            
            // Add event listeners to vote buttons
            document.querySelectorAll('.vote-button').forEach(button => {
                button.addEventListener('click', () => {
                    selectedVoteOption = button.getAttribute('data-option');
                    submitVote(button);
                });
            });
        } else {
            // User is not connected or hasn't selected a wallet - show connect prompt
            voteControls.style.display = 'block';
            voteOptionsGrid.innerHTML = `
                <div class="connect-prompt">
                    <p>To vote on this proposal, please connect to the dashboard and select a wallet.</p>
                    <button id="detailConnectButton" class="help-button">Connect to Dashboard</button>
                </div>
            `;
            
            // Add event listener to connect button
            const detailConnectButton = document.getElementById('detailConnectButton');
            if (detailConnectButton) {
                detailConnectButton.addEventListener('click', () => {
                    // First connect to dashboard if not connected
                    if (!CpunkDashboard.isConnected()) {
                        const mainConnectButton = document.getElementById('connectButton');
                        if (mainConnectButton) {
                            mainConnectButton.click();
                        }
                    } else {
                        // If already connected, show wallet selection
                        walletSection.style.display = 'block';
                        proposalsSection.style.display = 'none';
                        proposalDetailSection.style.display = 'none';
                        loadWallets();
                    }
                });
            }
        }
    } else {
        voteControls.style.display = 'none';
    }
    
    proposalDetail.innerHTML = html;
}

// Format markdown to HTML (simplified)
function formatMarkdown(markdown) {
    // This is a very simplified markdown formatter
    // In a real implementation, you'd use a proper markdown library
    
    // Split into lines
    const lines = markdown.split('\n');
    
    let html = '';
    let inList = false;
    let listType = '';
    
    for (let line of lines) {
        // Heading 1
        if (line.startsWith('# ')) {
            if (inList) {
                html += `</${listType}>`;
                inList = false;
            }
            html += `<h2>${line.substring(2)}</h2>`;
        }
        // Heading 2
        else if (line.startsWith('## ')) {
            if (inList) {
                html += `</${listType}>`;
                inList = false;
            }
            html += `<h3>${line.substring(3)}</h3>`;
        }
        // Heading 3
        else if (line.startsWith('### ')) {
            if (inList) {
                html += `</${listType}>`;
                inList = false;
            }
            html += `<h4>${line.substring(4)}</h4>`;
        }
        // Unordered list
        else if (line.trim().startsWith('- ')) {
            if (!inList) {
                html += '<ul>';
                inList = true;
                listType = 'ul';
            }
            if (listType === 'ul') {
                html += `<li>${line.trim().substring(2)}</li>`;
            } else {
                html += `</ol><ul><li>${line.trim().substring(2)}</li>`;
                listType = 'ul';
            }
        }
        // Ordered list
        else if (/^\d+\.\s/.test(line.trim())) {
            if (!inList) {
                html += '<ol>';
                inList = true;
                listType = 'ol';
            }
            if (listType === 'ol') {
                html += `<li>${line.trim().replace(/^\d+\.\s/, '')}</li>`;
            } else {
                html += `</ul><ol><li>${line.trim().replace(/^\d+\.\s/, '')}</li>`;
                listType = 'ol';
            }
        }
        // Bold text
        else if (line.includes('**')) {
            if (inList) {
                html += `</${listType}>`;
                inList = false;
            }
            let processed = line.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
            if (processed.trim()) {
                html += `<p>${processed}</p>`;
            } else {
                html += '<br>';
            }
        }
        // Regular paragraph
        else if (line.trim()) {
            if (inList) {
                html += `</${listType}>`;
                inList = false;
            }
            html += `<p>${line}</p>`;
        }
        // Empty line
        else {
            if (inList) {
                html += `</${listType}>`;
                inList = false;
            }
            html += '<br>';
        }
    }
    
    // Close any open list
    if (inList) {
        html += `</${listType}>`;
    }
    
    return html;
}

// Submit vote
async function submitVote(buttonElement) {
    resetVoteMessages();
    
    // Validate inputs
    if (!selectedVoteOption) {
        showVoteWarning('Please select an option to vote.');
        return;
    }

    if (!selectedProposalId) {
        showVoteError('Proposal ID not found.');
        return;
    }

    // Check if user is authenticated
    if (!CpunkSSO.getInstance().isUserAuthenticated()) {
        showVoteError('Please login to vote on proposals.');
        // Redirect to login after a short delay
        setTimeout(() => {
            CpunkSSO.getInstance().login();
        }, 2000);
        return;
    }
    
    // Get authenticated user info
    const userInfo = CpunkSSO.getInstance().getCurrentUser();
    if (!userInfo || !userInfo.wallet) {
        showVoteError('Authentication error. Please try logging in again.');
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
        
        // This is where you would submit the vote to the API
        // For now, just simulate a successful vote
        
        // Simulate API call delay
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // Mark as voted in user vote tracking
        userVotes[selectedProposalId] = selectedVoteOption;
        
        // Show success message
        showVoteSuccess('Your vote has been submitted successfully!');
        
    } catch (error) {
        showVoteError(`Error: ${error.message}`);
    } finally {
        // Re-enable all vote buttons
        const voteButtons = document.querySelectorAll('.vote-button');
        voteButtons.forEach(button => {
            button.disabled = false;
            if (button.getAttribute('data-option') === selectedVoteOption) {
                button.innerHTML = originalText || button.getAttribute('data-option');
            }
        });
    }
}

// Show proposals list
function showProposalsList() {
    proposalDetailSection.style.display = 'none';
    proposalsSection.style.display = 'block';
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

// Capitalize first letter
function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}