/**
 * Network Statistics Page JavaScript
 * Handles fetching and displaying CPUNK network and token statistics
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the stats page
    initNetworkStats();
});

// Set refresh intervals (in milliseconds)
const PRICE_REFRESH_INTERVAL = 30000; // 30 seconds
const NETWORK_REFRESH_INTERVAL = 60000; // 1 minute
const TREASURY_REFRESH_INTERVAL = 120000; // 2 minutes
const SOCIAL_REFRESH_INTERVAL = 300000; // 5 minutes

/**
 * Initialize network statistics page
 */
function initNetworkStats() {
    // Fetch all initial data
    fetchTokenPrice();
    fetchNetworkHealth();
    fetchTreasuryData();
    fetchDelegationStats();
    fetchRecentTransactions();
    fetchDnaStats();
    fetchSocialStats();
    
    // Update the last refresh time
    updateRefreshTime();
    
    // Set up refresh intervals
    setInterval(fetchTokenPrice, PRICE_REFRESH_INTERVAL);
    setInterval(fetchNetworkHealth, NETWORK_REFRESH_INTERVAL);
    setInterval(fetchTreasuryData, TREASURY_REFRESH_INTERVAL);
    setInterval(fetchDelegationStats, TREASURY_REFRESH_INTERVAL);
    setInterval(fetchRecentTransactions, NETWORK_REFRESH_INTERVAL);
    setInterval(fetchDnaStats, TREASURY_REFRESH_INTERVAL);
    setInterval(fetchSocialStats, SOCIAL_REFRESH_INTERVAL);
    
    // Update refresh time every minute
    setInterval(updateRefreshTime, 60000);
}

/**
 * Update the last refresh timestamp
 */
function updateRefreshTime() {
    const now = new Date();
    document.getElementById('last-refresh-time').textContent = now.toLocaleTimeString();
}

/**
 * Format number for display
 * @param {number} number - Number to format
 * @param {number} decimals - Maximum decimal places
 * @returns {string} - Formatted number string
 */
function formatNumber(number, decimals = 6) {
    if (number < 0.0001) {
        // For very small numbers, use more decimal places
        return number.toFixed(8);
    }
    return new Intl.NumberFormat('en-US', {
        minimumFractionDigits: 0,
        maximumFractionDigits: decimals
    }).format(number);
}

/**
 * Fetch token price and market data from exchange API
 */
async function fetchTokenPrice() {
    try {
        // Log API request if console is available
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log('CEX price API request', { 
                endpoint: 'https://api.bitcointry.com/api/v2/ticker',
                params: { pair: 'CPUNK_USDT' },
                type: 'external_api' 
            });
        }
        
        const apiResponse = await fetch('https://api.bitcointry.com/api/v2/ticker?pair=CPUNK_USDT');
        const data = await apiResponse.json();

        if (data && data.CPUNK_USDT) {
            const ticker = data.CPUNK_USDT;
            const lastPrice = parseFloat(ticker.last_price);
            const priceChange = parseFloat(ticker.price_change_percent_24h);
            const high24h = parseFloat(ticker.highest_price_24h);
            const low24h = parseFloat(ticker.lowest_price_24h);
            const quoteVolume = parseFloat(ticker.quote_volume);

            // Calculate market cap (price * circulating supply)
            const circulatingSupply = 1000000000; // 1 billion, update this if the actual value is different
            const marketCap = lastPrice * circulatingSupply;
            
            // Log API response if console is available
            if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
                CpunkAPIConsole.log('CEX price API response', { 
                    lastPrice,
                    priceChange,
                    high24h,
                    low24h,
                    quoteVolume,
                    marketCap
                });
            }

            // Update token price display
            document.getElementById('token-price').textContent = `${formatNumber(lastPrice)} USDT`;
            
            // Format price change with + sign and color
            const priceChangeFormatted = priceChange >= 0 ? `+${priceChange}%` : `${priceChange}%`;
            const priceChangeElement = document.getElementById('price-change');
            priceChangeElement.textContent = priceChangeFormatted;
            priceChangeElement.className = `stat-value ${priceChange >= 0 ? 'price-up' : 'price-down'}`;
            
            // Update other market metrics
            document.getElementById('market-cap').textContent = `$${formatNumber(marketCap, 2)}`;
            document.getElementById('trading-volume').textContent = `${formatNumber(quoteVolume, 2)} USDT`;
            document.getElementById('circulating-supply').textContent = `${formatNumber(circulatingSupply, 0)} CPUNK`;
        } else {
            throw new Error('Invalid API response format');
        }
    } catch (error) {
        console.error('Error fetching token price:', error);
        document.getElementById('token-price').textContent = 'Data unavailable';
        document.getElementById('price-change').textContent = 'Data unavailable';
        document.getElementById('market-cap').textContent = 'Data unavailable';
        document.getElementById('trading-volume').textContent = 'Data unavailable';
    }
}

/**
 * Fetch network health data
 */
async function fetchNetworkHealth() {
    try {
        // Fetch data from netstats.txt file
        const response = await fetch('netstats.txt');
        const text = await response.text();
        
        // Set all values to Coming Soon
        let activeNodes = 'Coming Soon';
        let blockHeight = 'Coming Soon';
        let networkStatus = 'Coming Soon';
        
        // Update network health display
        document.getElementById('active-nodes').textContent = activeNodes;
        document.getElementById('block-height').textContent = blockHeight;
        document.getElementById('network-status').textContent = networkStatus;
    } catch (error) {
        console.error('Error fetching network health:', error);
        document.getElementById('active-nodes').textContent = 'Coming Soon';
        document.getElementById('block-height').textContent = 'Coming Soon';
        document.getElementById('network-status').textContent = 'Coming Soon';
    }
}

/**
 * Fetch treasury data
 */
async function fetchTreasuryData() {
    try {
        // Log API request if console is available
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log('Treasury data request', { endpoint: 'data.txt', type: 'local_file' });
        }
        
        // Fetch data from local file for treasury info
        const response = await fetch('data.txt');
        const text = await response.text();
        const lines = text.split('\n');

        // Parse values using specific patterns
        const parseValue = (line, prefix) => {
            const match = line.match(new RegExp(`${prefix}:\\s*([\\d.]+)`));
            return match ? parseFloat(match[1]) : 0;
        };

        const parseTimestamp = (line) => {
            const match = line.match(/Timestamp:\s*(.*)/);
            return match ? match[1] : '';
        };

        const timestamp = parseTimestamp(lines[0]);
        const cellBalance = parseValue(lines[1], 'CELL balance');
        const cpunkBalance = parseValue(lines[2], 'CPUNK balance');
        const stakeValue = parseValue(lines[3], 'Stake value');
        
        // Log the parsed data response
        if (window.CpunkAPIConsole && CpunkAPIConsole.log) {
            CpunkAPIConsole.log('Treasury data response', {
                timestamp,
                cellBalance,
                cpunkBalance,
                stakeValue
            });
        }

        // Update treasury display
        document.getElementById('treasury-cell').textContent = formatNumber(cellBalance);
        document.getElementById('treasury-cpunk').textContent = formatNumber(cpunkBalance);
        document.getElementById('treasury-staked').textContent = `${formatNumber(stakeValue)} MCELL`;
        document.getElementById('treasury-updated').textContent = `Last updated: ${timestamp}`;
    } catch (error) {
        console.error('Error fetching treasury data:', error);
        document.getElementById('treasury-cell').textContent = 'Data unavailable';
        document.getElementById('treasury-cpunk').textContent = 'Data unavailable';
        document.getElementById('treasury-staked').textContent = 'Data unavailable';
        document.getElementById('treasury-updated').textContent = 'Last updated: Unable to load data';
    }
}

/**
 * Fetch delegation statistics
 */
async function fetchDelegationStats() {
    try {
        // Display "Coming Soon" instead of mock data
        document.getElementById('active-delegations').textContent = 'Coming Soon';
        document.getElementById('total-staked').textContent = 'Coming Soon';
        document.getElementById('total-rewards').textContent = 'Coming Soon';
        document.getElementById('average-apy').textContent = 'Coming Soon';
    } catch (error) {
        console.error('Error fetching delegation stats:', error);
        document.getElementById('active-delegations').textContent = 'Data unavailable';
        document.getElementById('total-staked').textContent = 'Data unavailable';
        document.getElementById('total-rewards').textContent = 'Data unavailable';
        document.getElementById('average-apy').textContent = 'Data unavailable';
    }
}

/**
 * Fetch top CPUNK holders
 */
async function fetchRecentTransactions() {
    try {
        // Fetch data from netstats.txt file
        const response = await fetch('netstats.txt');
        const text = await response.text();
        const transactionsContainer = document.getElementById('transactions-list');
        
        // Also fetch static addresses for known addresses
        const staticAddressesResponse = await fetch('static_addresses.txt');
        let staticAddresses = new Map();
        
        if (staticAddressesResponse.ok) {
            const staticText = await staticAddressesResponse.text();
            const staticLines = staticText.split('\n');
            
            // Parse static addresses
            staticLines.forEach(line => {
                if (line.trim()) {
                    const [address, name] = line.split(':');
                    if (address && name) {
                        staticAddresses.set(address.trim(), name.trim());
                    }
                }
            });
            
            console.log("Loaded static addresses:", staticAddresses.size);
        }
        
        // Parse the netstats.txt file for top holder information
        if (text) {
            // Extract top holders section
            const topHolders = [];
            const lines = text.split('\n');
            
            // Look for HOLDER: prefix in each line
            for (const line of lines) {
                if (line.startsWith('HOLDER')) {
                    const parts = line.split(':');
                    if (parts.length >= 3) {
                        // Extract position from "HOLDER{position}"
                        const position = parts[0].substring(6);
                        const address = parts[1];
                        const balance = parts[2];
                        
                        // Check if this is a known static address
                        let displayName = address;
                        if (staticAddresses.has(address)) {
                            displayName = staticAddresses.get(address);
                        }
                        
                        topHolders.push({ position, address, balance, displayName });
                    }
                }
            }
            
            if (topHolders.length > 0) {
                // Only show the top 10 holders
                const top10Holders = topHolders.slice(0, 10);
                console.log("Showing top 10 holders:", top10Holders);
                
                // Create HTML for top holders display
                const holdersList = top10Holders.map(holder => {
                    // Determine if this is a static/known address
                    const isKnownAddress = holder.address !== holder.displayName;
                    
                    // For display purposes - abbreviate long addresses
                    // Always show abbreviated address format for regular addresses
                    const displayAddress = isKnownAddress 
                        ? holder.displayName
                        : `${holder.address.substring(0, 12)}...${holder.address.substring(holder.address.length - 6)}`;
                    
                    return `
                        <div class="holder-item">
                            <div class="holder-rank">#${holder.position}</div>
                            <div class="holder-info">
                                <div class="holder-identity ${isKnownAddress ? 'known-address' : ''}" 
                                     title="${holder.address}" id="address-${holder.position}">
                                    ${displayAddress}
                                </div>
                                <div class="dna-names" id="dna-${holder.position}" data-address="${holder.address}" style="${isKnownAddress ? 'display: none;' : ''}">
                                    <div class="dna-loading">Loading DNA...</div>
                                </div>
                                <div class="holder-balance">${formatNumber(holder.balance)} CPUNK</div>
                            </div>
                        </div>
                    `;
                }).join('');
                
                transactionsContainer.innerHTML = holdersList || '<div class="loading-message">No holder data available</div>';
                
                // After displaying the holders, fetch DNA information for each
                setTimeout(() => {
                    fetchDnaForTopHolders(top10Holders, staticAddresses);
                }, 500);
                
                return;
            }
        }
        
        // If we get here, we couldn't parse the data
        transactionsContainer.innerHTML = '<div class="loading-message">Holder data being collected...</div>';
    } catch (error) {
        console.error('Error fetching holders:', error);
        document.getElementById('transactions-list').innerHTML = 
            '<div class="loading-message">Error loading holder data</div>';
    }
}

/**
 * Fetch CPUNK circulation statistics
 */
async function fetchDnaStats() {
    try {
        // Fetch data from netstats.txt file
        const response = await fetch('netstats.txt');
        const text = await response.text();
        
        let totalRegistrations = 'Data unavailable';
        let registryRevenue = 'Data unavailable';
        
        // Parse the netstats.txt file for CPUNK ledger information
        if (text) {
            // Extract data from netstats.txt
            const lines = text.split('\n');
            for (const line of lines) {
                // Get NumberOfAddresses for total addresses with CPUNK
                if (line.startsWith('NumberOfAddresses:')) {
                    const parts = line.split(':');
                    if (parts.length >= 2) {
                        totalRegistrations = parts[1].trim();
                    }
                } 
                // Get Circulation for total CPUNK
                else if (line.startsWith('Circulation:')) {
                    const parts = line.split(':');
                    if (parts.length >= 2) {
                        const cpunkValue = parts[1].trim();
                        registryRevenue = `${formatNumber(cpunkValue)} CPUNK`;
                    }
                }
                // Get TotalDNACount if available
                else if (line.startsWith('TotalDNACount:')) {
                    // Not displayed currently, but could be added later
                }
            }
        }
        
        // Update the DNA stats display
        document.getElementById('total-registrations').textContent = totalRegistrations;
        document.getElementById('registry-revenue').textContent = registryRevenue;
    } catch (error) {
        console.error('Error fetching CPUNK stats:', error);
        document.getElementById('total-registrations').textContent = 'Data unavailable';
        document.getElementById('registry-revenue').textContent = 'Data unavailable';
    }
}

/**
 * Fetch DNA information for top token holders
 * @param {Array} holders - Array of holder objects with position and address
 * @param {Map} staticAddresses - Map of known static addresses
 */
async function fetchDnaForTopHolders(holders, staticAddresses = new Map()) {
    try {
        // Fetch the cached DNA names from the server
        const response = await fetch('dna_names.txt');
        if (!response.ok) {
            throw new Error(`Failed to fetch DNA data: ${response.status} ${response.statusText}`);
        }
        
        const text = await response.text();
        console.log(`Loaded DNA cache data: ${text.length} bytes`);
        
        // Parse the DNA data
        const dnaMap = new Map();
        const lines = text.split('\n');
        
        lines.forEach(line => {
            if (line.startsWith('DNA:')) {
                const parts = line.split(':');
                if (parts.length >= 4) {
                    const position = parts[1];
                    const address = parts[2];
                    const dnaNames = parts[3] || '';
                    
                    // Store in map by both position and address for flexibility
                    dnaMap.set(position, { address, dnaNames });
                    dnaMap.set(address.toLowerCase(), { position, dnaNames });
                }
            }
        });
        
        // Update the UI with the DNA data
        holders.forEach(holder => {
            const position = holder.position;
            const address = holder.address.toLowerCase();
            
            // Check if this is a known static address
            const isKnownAddress = staticAddresses.has(holder.address);
            
            // Get DOM elements
            const dnaElement = document.getElementById(`dna-${position}`);
            const addressElement = document.getElementById(`address-${position}`);
            
            if (dnaElement && addressElement) {
                // If it's a known address, we already displayed the proper name
                if (isKnownAddress) {
                    // Hide the DNA element
                    dnaElement.style.display = 'none';
                    
                    // Style the address element as a known address
                    addressElement.classList.add('known-address');
                    addressElement.style.flex = '1 1 auto';
                    return;
                }
                
                // Try to get DNA data by position first, then by address as fallback
                let dnaData = dnaMap.get(position);
                if (!dnaData) {
                    dnaData = dnaMap.get(address);
                }
                
                let dnaNames = '';
                
                // If we have DNA data for this holder
                if (dnaData && dnaData.dnaNames) {
                    dnaNames = dnaData.dnaNames;
                }
                
                // Format multiple DNA names if needed
                const dnaNamesList = dnaNames.split(',').filter(name => name.trim() !== '');
                
                // If we have DNA names, show them properly and hide address
                if (dnaNamesList.length > 0) {
                    // Show DNA names
                    dnaElement.classList.add('has-dna');
                    
                    // If multiple names, join them nicely
                    if (dnaNamesList.length > 1) {
                        dnaElement.innerHTML = dnaNamesList[0] + 
                            ` <span class="dna-count">+${dnaNamesList.length - 1}</span>`;
                        dnaElement.title = dnaNamesList.join(', ');
                    } else {
                        dnaElement.innerHTML = dnaNamesList[0];
                        dnaElement.title = dnaNamesList[0];
                    }
                    
                    dnaElement.style.flex = '1 1 auto';
                    
                    // Hide address completely
                    addressElement.style.display = 'none';
                } else {
                    // No DNA, hide the DNA element
                    dnaElement.style.display = 'none';
                    
                    // Make address more prominent
                    addressElement.style.flex = '1 1 auto';
                    addressElement.style.color = 'var(--text-primary)';
                    addressElement.style.fontWeight = '500';
                }
            }
        });
    } catch (error) {
        console.error('Error fetching cached DNA data:', error);
        
        // On error, hide all DNA elements and show addresses
        holders.forEach(holder => {
            const dnaElement = document.getElementById(`dna-${holder.position}`);
            const addressElement = document.getElementById(`address-${holder.position}`);
            
            if (dnaElement && addressElement) {
                // Hide DNA element
                dnaElement.style.display = 'none';
                
                // Make address more prominent
                addressElement.style.flex = '1 1 auto';
                addressElement.style.color = 'var(--text-primary)';
                addressElement.style.fontWeight = '500';
            }
        });
    }
}

/**
 * Fetch social media and community statistics
 */
async function fetchSocialStats() {
    try {
        // Display "Coming Soon" instead of mock data
        document.getElementById('telegram-members').textContent = 'Coming Soon';
        document.getElementById('twitter-followers').textContent = 'Coming Soon';
        document.getElementById('community-growth').textContent = 'Coming Soon';
    } catch (error) {
        console.error('Error fetching social stats:', error);
        document.getElementById('telegram-members').textContent = 'Data unavailable';
        document.getElementById('twitter-followers').textContent = 'Data unavailable';
        document.getElementById('community-growth').textContent = 'Data unavailable';
    }
}