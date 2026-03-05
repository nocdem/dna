// Delegation Stats JavaScript - CPUNK.IO Complete Version with Cache-Busting
class DelegationStats {
    constructor() {
        this.data = null;
        this.selectedNode = null;
        this.isLoading = false;
        this.autoRefreshInterval = null;
        this.lastUpdateTime = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadData();
        this.startAutoRefresh();
    }

    setupEventListeners() {
        // Refresh button handler
        const refreshBtn = document.getElementById('refresh-data-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.manualRefresh();
            });
        }

        // Modal close handlers
        const closeBtn = document.querySelector('.modal .close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                this.closeModal();
            });
        }

        const modal = document.getElementById('node-modal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target.id === 'node-modal') {
                    this.closeModal();
                }
            });
        }

        // Escape key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });
    }

    async loadData() {
        // Prevent multiple simultaneous requests
        if (this.isLoading) {
            console.log('🔄 Data loading already in progress, skipping...');
            return;
        }

        this.isLoading = true;
        this.setRefreshButtonState(true);

        try {
            console.log('🔄 Loading delegation data...');
            this.showLoading();
            
            // Create cache-busting parameter
            const cacheBuster = `?t=${Date.now()}&r=${Math.random().toString(36).substr(2, 9)}`;
            
            // Use same approach as cpunk.club - direct local fetch
            console.log('📡 Fetching from local stats...');
            const response = await fetch('/stats/node-status-report.json');

            const data = await response.json();
            
            if (!data || !data.report_metadata) {
                throw new Error('Invalid data structure received');
            }

            console.log('📊 Data loaded successfully:', {
                totalNodes: data.report_metadata.total_nodes,
                generatedAt: data.report_metadata.generated_at
            });

            this.data = data;
            this.lastUpdateTime = new Date();
            this.updateLastRefreshTime();
            this.updateOverview();
            this.renderNodesGrid();
            
        } catch (error) {
            console.error('❌ Error loading delegation data:', error);
            this.showError(`Failed to load data: ${error.message}`);
        } finally {
            this.isLoading = false;
            this.setRefreshButtonState(false);
        }
    }

    // Manual refresh triggered by user
    async manualRefresh() {
        console.log('🔄 Manual refresh triggered');
        await this.loadData();
    }

    // Auto-refresh functionality
    startAutoRefresh() {
        // Auto-refresh every 5 minutes (300000ms)
        this.autoRefreshInterval = setInterval(() => {
            console.log('🔄 Auto-refresh triggered');
            this.loadData();
        }, 300000);
        
        console.log('⏰ Auto-refresh started (5 minute intervals)');
    }

    stopAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
            this.autoRefreshInterval = null;
            console.log('⏰ Auto-refresh stopped');
        }
    }

    // Update refresh button state
    setRefreshButtonState(isLoading) {
        const refreshBtn = document.getElementById('refresh-data-btn');
        if (refreshBtn) {
            if (isLoading) {
                refreshBtn.classList.add('loading');
                refreshBtn.innerHTML = '<span>🔄</span> Refreshing...';
                refreshBtn.disabled = true;
            } else {
                refreshBtn.classList.remove('loading');
                refreshBtn.innerHTML = '🔄 Refresh Data';
                refreshBtn.disabled = false;
            }
        }
    }

    // Update last refresh timestamp
    updateLastRefreshTime() {
        const lastUpdatedElement = document.getElementById('last-updated-time');
        if (lastUpdatedElement && this.lastUpdateTime) {
            const timeString = this.lastUpdateTime.toLocaleTimeString();
            const dateString = this.lastUpdateTime.toLocaleDateString();
            lastUpdatedElement.textContent = `${dateString} at ${timeString}`;
        }
        
        // Also show server generation time if available
        if (this.data?.report_metadata?.generated_at) {
            const serverTime = this.data.report_metadata.generated_at;
            console.log(`📅 Server data generated: ${serverTime}`);
        }
    }

    showLoading() {
        document.getElementById('nodes-grid').innerHTML = '<div class="loading">🔄 Loading network nodes...</div>';
    }

    showError(message) {
        document.getElementById('nodes-grid').innerHTML = `<div class="error">${message}</div>`;
    }

    updateOverview() {
        if (!this.data) return;

        const metadata = this.data.report_metadata;
        const income = this.data.income_summary;
        const pending = this.data.autocollect_fleet_summary;
        const nodes = Object.values(this.data.nodes);

        // Network status - exactly like cpunk.club
        document.getElementById('total-nodes').textContent = metadata.total_nodes;
        document.getElementById('reachable-nodes').textContent = metadata.nodes_reachable;
        document.getElementById('unreachable-nodes').textContent = metadata.nodes_unreachable;

        // Income analytics - distributed tokens (exactly like cpunk.club)
        document.getElementById('total-cell-distributed').textContent = income.total_backbone_income.toFixed(2);
        document.getElementById('total-kel-distributed').textContent = income.total_kelvpn_income.toFixed(2);

        // Pending rewards - exactly like cpunk.club
        const cellPending = parseFloat(pending.total_rewards_pending.cell);
        const kelPending = parseFloat(pending.total_rewards_pending.kel);
        
        document.getElementById('pending-cell').textContent = cellPending.toFixed(2);
        document.getElementById('pending-kel').textContent = kelPending.toFixed(2);
        
        // Calculate active delegations - exactly like cpunk.club
        const backboneActive = nodes.filter(node => 
            node.phase5_delegations?.backbone?.status === 'active'
        ).length;
        const kelvpnActive = nodes.filter(node => 
            node.phase5_delegations?.kelvpn?.status === 'active'
        ).length;
        const totalActive = backboneActive + kelvpnActive;
        
        document.getElementById('active-delegations').textContent = totalActive;
    }


    renderNodesGrid() {
        if (!this.data) return;

        const container = document.getElementById('nodes-grid');
        if (!container) return;

        const nodes = Object.entries(this.data.nodes);

        container.innerHTML = nodes.map(([nodeId, node]) => 
            this.createNodeCard(nodeId, node)
        ).join('');

        // Add click handlers to all node cards
        container.querySelectorAll('.node-card').forEach(card => {
            card.addEventListener('click', () => {
                const nodeId = card.dataset.nodeId;
                this.showNodeDetails(nodeId);
            });
        });
    }

    createNodeCard(nodeId, node) {
        const isOnline = node.phase1_connection?.service_status === 'running';
        const nodeAddress = node.phase8_version?.node_address || 'N/A';
        
        const uptime = node.phase1_connection?.uptime_duration || 'N/A';
        const formattedUptime = uptime !== 'N/A' ? this.formatUptime(uptime) : 'N/A';
        const lastChecked = node.last_checked || 'N/A';
        const formattedLastChecked = this.formatTimeAgo(lastChecked);

        return `
            <div class="node-card ${isOnline ? 'online' : 'offline'}" data-node-id="${nodeId}">
                <div class="node-header">
                    <div class="node-name">${nodeAddress}</div>
                    <div class="node-status">
                        <span class="status-badge status-${isOnline ? 'online' : 'offline'}">
                            ${isOnline ? '🟢 Online' : '🔴 Offline'}
                        </span>
                    </div>
                </div>
                
                <div class="node-quick-info">
                    <div class="quick-stat">
                        <span class="stat-text">Uptime: ${formattedUptime}</span>
                    </div>
                    <div class="quick-stat">
                        <span class="stat-text">Updated: ${formattedLastChecked}</span>
                    </div>
                </div>
                
                <div class="click-hint">Click for details →</div>
            </div>
        `;
    }

    showNodeDetails(nodeId) {
        const node = this.data.nodes[nodeId];
        if (!node) return;

        this.selectedNode = nodeId;
        
        // Hide the main content
        const statsGrid = document.querySelector('.stats-grid');
        const nodesSection = document.querySelector('.nodes-section');
        const sectionHeaders = document.querySelectorAll('.section-header');
        
        if (statsGrid) statsGrid.style.display = 'none';
        if (nodesSection) nodesSection.style.display = 'none';
        sectionHeaders.forEach(header => header.style.display = 'none');
        
        // Show node details in main area
        const container = document.querySelector('.container');
        const detailsContainer = document.createElement('div');
        detailsContainer.id = 'node-details-container';
        detailsContainer.innerHTML = this.generateFullPageNodeDetails(nodeId, node);
        
        container.appendChild(detailsContainer);
        
        // Load RPC data progressively
        this.loadNodeRPCData(nodeId, node);
    }

    async loadNodeRPCData(nodeId, node) {
        const wallets = node.phase4_wallets || {};
        const backboneAddr = wallets.backbone_address;
        const kelvpnAddr = wallets.kelvpn_address;
        
        // Check delegation status
        const backboneDelegation = node.phase5_delegations?.backbone || {};
        const kelvpnDelegation = node.phase5_delegations?.kelvpn || {};
        
        try {
            // Load backbone earnings only if delegation is active
            if (backboneAddr && backboneAddr !== 'N/A' && 
                backboneDelegation.status === 'active') {
                console.log(`📊 Loading Backbone earnings for ${nodeId} (delegation active)`);
                const taxRate = parseFloat(backboneDelegation.tax_rate) || 0;
                console.log(`🔢 Backbone tax rate: ${taxRate}%`);
                const backboneEarnings = await this.fetchWalletEarnings(backboneAddr, 'backbone');
                const nodeIncome = this.calculateNodeIncome(backboneEarnings, taxRate);
                this.updateFinancialData(nodeId, 'backbone', nodeIncome);
                this.createEarningsChart(nodeId, 'backbone', nodeIncome, 'CELL');
            } else {
                console.log(`⏭️ Skipping Backbone earnings for ${nodeId} (no active delegation)`);
            }
            
            // Load KelVPN earnings only if delegation is active
            if (kelvpnAddr && kelvpnAddr !== 'N/A' && 
                kelvpnDelegation.status === 'active') {
                console.log(`📊 Loading KelVPN earnings for ${nodeId} (delegation active)`);
                const taxRate = parseFloat(kelvpnDelegation.tax_rate) || 0;
                console.log(`🔢 KelVPN tax rate: ${taxRate}%`);
                const kelvpnEarnings = await this.fetchWalletEarnings(kelvpnAddr, 'kelvpn');
                const nodeIncome = this.calculateNodeIncome(kelvpnEarnings, taxRate);
                this.updateFinancialData(nodeId, 'kelvpn', nodeIncome);
                this.createEarningsChart(nodeId, 'kelvpn', nodeIncome, 'KEL');
            } else {
                console.log(`⏭️ Skipping KelVPN earnings for ${nodeId} (no active delegation)`);
            }
            
            // Hide loading indicators
            const loadingIndicator = document.getElementById('financial-loading');
            if (loadingIndicator) loadingIndicator.style.display = 'none';
            
            const chartLoading = document.getElementById(`chart-loading-${nodeId}`);
            if (chartLoading) chartLoading.style.display = 'none';
            
        } catch (error) {
            console.error('Error loading RPC data:', error);
            this.showRPCError(nodeId);
        }
    }

    async fetchWalletEarnings(walletAddress, network) {
        const networkName = network === 'backbone' ? 'Backbone' : 'KelVPN';
        
        const response = await fetch('/cellframe-rpc-proxy.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            },
            body: JSON.stringify({
                method: 'tx_history',
                subcommand: '',
                arguments: {
                    net: networkName,
                    addr: walletAddress,
                    limit: '15000'
                },
                id: `${network}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        return this.processEarningsData(data, network);
    }

    calculateNodeIncome(commissionEarnings, taxRate) {
        // Commission rate is (100 - taxRate)%
        const commissionRate = 100 - taxRate;
        console.log(`🔢 Tax rate: ${taxRate}%, Commission rate: ${commissionRate}%`);
        
        if (commissionRate <= 0) {
            console.log('⚠️ Invalid commission rate, returning original earnings');
            return commissionEarnings;
        }

        const nodeIncome = {
            total: (commissionEarnings.total * 100) / commissionRate,
            transactions: commissionEarnings.transactions,
            dailyData: commissionEarnings.dailyData.map(day => ({
                date: day.date,
                earnings: (day.earnings * 100) / commissionRate
            })),
            recentTxs: commissionEarnings.recentTxs.map(tx => ({
                ...tx,
                amount: (tx.amount * 100) / commissionRate,
                originalCommission: tx.amount
            }))
        };

        console.log(`💰 Commission earnings: ${commissionEarnings.total.toFixed(6)}`);
        console.log(`🏛️ Total node income: ${nodeIncome.total.toFixed(6)}`);
        
        return nodeIncome;
    }

    processEarningsData(rpcData, network) {
        console.log('🔍 RPC Data received:', rpcData);
        console.log('🔍 Network:', network);
        
        if (!rpcData.result || !Array.isArray(rpcData.result)) {
            console.log('❌ No result or result not array');
            return { total: 0, transactions: 0, dailyData: [], recentTxs: [] };
        }
        
        // Find the transactions array from the result
        const transactions = rpcData.result.find(item => Array.isArray(item) && item.length > 0 && item.some(tx => tx.status));
        
        if (!transactions) {
            console.log('❌ No transactions found in result');
            return { total: 0, transactions: 0, dailyData: [], recentTxs: [] };
        }
        
        console.log('✅ Found transactions array with', transactions.length, 'items');

        // Calculate date threshold for 30 days
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - 30);

        let totalRewards = 0;
        const rewardTransactions = [];
        const dailyEarnings = {};

        // Filter and process reward transactions
        let processedCount = 0;
        let rewardCount = 0;
        
        for (const tx of transactions) {
            processedCount++;
            
            if (!tx.status || !tx.tx_created || !tx.data) {
                continue;
            }
            
            // Check if transaction is accepted
            if (tx.status !== 'ACCEPTED') {
                continue;
            }
            
            // Check if it's a block reward
            if (tx.service !== 'block_reward') {
                continue;
            }
            
            // Parse transaction date
            const txDate = new Date(tx.tx_created);
            
            // Skip if older than 30 days
            if (txDate < cutoffDate) {
                continue;
            }
            
            // Find reward amount from transaction data
            const rewardData = tx.data.find(d => 
                d.tx_type === 'recv' && 
                d.source_address === 'reward collecting'
            );
            
            if (rewardData && rewardData.recv_coins) {
                const rewardAmount = parseFloat(rewardData.recv_coins);
                console.log('✅ Found reward:', rewardAmount);
                rewardCount++;
                totalRewards += rewardAmount;
                
                rewardTransactions.push({
                    date: txDate,
                    amount: rewardAmount,
                    hash: tx.hash,
                    formattedDate: txDate.toLocaleDateString(),
                    formattedTime: txDate.toLocaleTimeString()
                });

                // Track daily earnings for chart
                const dateStr = txDate.toISOString().split('T')[0];
                dailyEarnings[dateStr] = (dailyEarnings[dateStr] || 0) + rewardAmount;
            }
        }
        
        console.log(`📊 Summary: Processed ${processedCount} transactions, found ${rewardCount} rewards, total: ${totalRewards}`);

        // Create daily data array for chart (last 30 days, excluding today)
        const dailyData = [];
        const now = new Date();
        for (let i = 30; i >= 1; i--) {
            const date = new Date(now - (i * 24 * 60 * 60 * 1000));
            const dateStr = date.toISOString().split('T')[0];
            dailyData.push({
                date: dateStr,
                earnings: dailyEarnings[dateStr] || 0
            });
        }

        return {
            total: totalRewards,
            transactions: rewardTransactions.length,
            dailyData: dailyData,
            recentTxs: rewardTransactions.slice(0, 10)
        };
    }

    updateFinancialData(nodeId, network, earnings) {
        const earningsDataDiv = document.getElementById('rpc-earnings-data');
        if (!earningsDataDiv) return;
        
        const currency = network === 'backbone' ? 'CELL' : 'KEL';
        const networkName = network === 'backbone' ? 'Backbone' : 'KelVPN';
        
        earningsDataDiv.innerHTML += `
            <div class="financial-network-section">
                <div class="financial-network-header">
                    <h5>
                        <span>${networkName}</span>
                        <span>(Reward TX: ${earnings.transactions})</span>
                    </h5>
                </div>
                <div class="financial-metrics">
                    <div class="financial-metric">
                        <span class="metric-label">Total Node Income:</span>
                        <span class="metric-value">${earnings.total.toFixed(4)} ${currency}</span>
                    </div>
                    <div class="financial-metric">
                        <span class="metric-label">Daily Avg Income:</span>
                        <span class="metric-value">${(earnings.total / 30).toFixed(4)} ${currency}</span>
                    </div>
                </div>
            </div>
        `;
    }

    createEarningsChart(nodeId, network, earnings, currency) {
        const chartsContainer = document.getElementById(`earnings-charts-container-${nodeId}`);
        if (!chartsContainer) return;
        
        // Create chart card for this network
        const networkName = network === 'backbone' ? 'Backbone' : 'KelVPN';
        const chartCard = document.createElement('div');
        chartCard.className = 'identity-card chart-card-wide';
        chartCard.id = `chart-card-${nodeId}-${network}`;
        
        chartCard.innerHTML = `
            <div class="card-header">
                <h4>📈 ${networkName} Earnings Over Time (30 Days)</h4>
            </div>
            <div class="card-content chart-responsive-container">
                <canvas id="earningsChart-${nodeId}-${network}"></canvas>
            </div>
        `;
        
        chartsContainer.appendChild(chartCard);
        
        // Create the chart
        const canvas = document.getElementById(`earningsChart-${nodeId}-${network}`);
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const labels = earnings.dailyData.map(d => new Date(d.date).toLocaleDateString());
        const data = earnings.dailyData.map(d => d.earnings);
        
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: `${networkName} ${currency} Node Income`,
                    data: data,
                    borderColor: currency === 'CELL' ? '#00ffcc' : '#0088ff',
                    backgroundColor: currency === 'CELL' ? 'rgba(0, 255, 204, 0.1)' : 'rgba(0, 136, 255, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: currency === 'CELL' ? '#00ffcc' : '#0088ff',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { 
                            color: '#ffffff',
                            font: { family: 'Inter', size: 12 }
                        }
                    },
                    title: {
                        display: true,
                        text: `${networkName} Network - Daily Node Income`,
                        color: '#00ffcc',
                        font: { family: 'Inter', size: 16, weight: 'bold' }
                    }
                },
                scales: {
                    x: { 
                        ticks: { 
                            color: '#ffffff', 
                            maxTicksLimit: 15,
                            font: { family: 'Inter', size: 11 }
                        },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    y: { 
                        ticks: { 
                            color: '#ffffff',
                            font: { family: 'Inter', size: 11 }
                        },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                }
            }
        });
    }

    showRPCError(nodeId) {
        const earningsDataDiv = document.getElementById('rpc-earnings-data');
        if (earningsDataDiv) {
            earningsDataDiv.innerHTML = '<div class="rpc-error">❌ Failed to load earnings data</div>';
        }
        
        const chartLoading = document.getElementById(`chart-loading-${nodeId}`);
        if (chartLoading) {
            chartLoading.innerHTML = '❌ Failed to load chart data';
        }
        
        const loadingIndicator = document.getElementById('financial-loading');
        if (loadingIndicator) loadingIndicator.style.display = 'none';
    }

    closeModal() {
        // Remove node details container and show main content
        const detailsContainer = document.getElementById('node-details-container');
        if (detailsContainer) {
            detailsContainer.remove();
        }
        
        // Show the hidden elements
        const statsGrid = document.querySelector('.stats-grid');
        const nodesSection = document.querySelector('.nodes-section');
        const sectionHeaders = document.querySelectorAll('.section-header');
        
        if (statsGrid) statsGrid.style.display = 'block';
        if (nodesSection) nodesSection.style.display = 'block';
        sectionHeaders.forEach(header => header.style.display = 'block');
        
        this.selectedNode = null;
    }

    generateFullPageNodeDetails(nodeId, node) {
        const nodeAddress = node.phase8_version?.node_address || nodeId;

        return `
            <div class="full-page-node-details">
                <div class="node-details-header">
                    <h2>${nodeAddress} - Node Details</h2>
                    <button class="back-button" onclick="delegationStats.closeModal()">← Back to All Nodes</button>
                </div>
                
                <div class="node-details-content">
                    ${this.generateNodeDetailsCardsHTML(nodeId, node)}
                </div>
            </div>
        `;
    }

    generateNodeDetailsCardsHTML(nodeId, node) {
        const connection = node.phase1_connection || {};
        const networks = node.phase2_networks || {};
        const delegations = node.phase5_delegations || {};
        const system = node.phase7_system || {};
        const version = node.phase8_version || {};

        return `
            <div class="node-cards-container">
                <div class="main-cards-grid">
                    <!-- Connection Details Card -->
                    <div class="identity-card">
                        <div class="card-header">
                            <h4>🔌 Connection & System</h4>
                        </div>
                        <div class="card-content">
                            <div class="network-details">
                                <div class="network-detail-item">
                                    <span class="network-detail-label">Node Address:</span>
                                    <span class="network-detail-value">${version.node_address || 'N/A'}</span>
                                </div>
                                <div class="network-detail-item">
                                    <span class="network-detail-label">Service Status:</span>
                                    <span class="network-detail-value status-${connection.service_status}">${connection.service_status || 'N/A'}</span>
                                </div>
                                <div class="network-detail-item">
                                    <span class="network-detail-label">Uptime:</span>
                                    <span class="network-detail-value">${this.formatUptime(connection.uptime_duration)}</span>
                                </div>
                                <div class="network-detail-item">
                                    <span class="network-detail-label">Node Version:</span>
                                    <span class="network-detail-value">${version.cellframe_version || 'N/A'}</span>
                                </div>
                                ${system.load_average ? `
                                <div class="network-detail-item">
                                    <span class="network-detail-label">Load Average:</span>
                                    <span class="network-detail-value">${system.load_average}</span>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>

                    <!-- Network Status Card -->
                    <div class="identity-card">
                        <div class="card-header">
                            <h4>🌐 Network Status</h4>
                        </div>
                        <div class="card-content">
                            ${this.generateNetworkStatusCardsHTML(networks, delegations)}
                        </div>
                    </div>

                    <!-- Financial Data Card -->
                    <div class="identity-card financial-data-card">
                        <div class="card-header">
                            <h4>💰 Financial Data (30 days)</h4>
                            <div class="loading-indicator" id="financial-loading">Loading RPC data...</div>
                        </div>
                        <div class="card-content" id="financial-content">
                            <div id="rpc-earnings-data">
                            </div>
                        </div>
                    </div>

                    <!-- Income Summary Card -->
                    <div class="identity-card">
                        <div class="card-header">
                            <h4>📊 Pending Rewards</h4>
                        </div>
                        <div class="card-content">
                            ${this.generateIncomeSummaryHTML(node.phase6_autocollect)}
                        </div>
                    </div>

                    <!-- Earnings Charts Container -->
                    <div id="earnings-charts-container-${nodeId}" style="grid-column: 1 / -1;">
                        <!-- Charts will be dynamically created for active delegations -->
                    </div>
                </div>
            </div>
        `;
    }

    generateNetworkStatusCardsHTML(networks, delegations) {
        let html = '<div class="network-status-grid">';
        
        // Backbone network info
        const backboneNet = networks['backbone'];
        if (backboneNet && backboneNet.available) {
            const backboneDelegation = delegations['backbone'];
            const backboneStakeValue = backboneDelegation?.stake_value ? 
                (parseFloat(backboneDelegation.stake_value) * 1000).toLocaleString() : 
                '0';
                
            html += `
                <div class="network-status-item">
                    <div class="network-name">
                        <span>Backbone</span>
                        <span>(Active Links: ${backboneNet.links_active})</span>
                    </div>
                    <div class="network-details">
                        <div class="network-detail-item">
                            <span class="network-detail-label">Sync Status:</span>
                            <span class="network-detail-value">
                                <span class="status-indicator ${backboneNet.fully_synced ? 'synced' : 'syncing'}"></span>
                                ${backboneNet.sync_overall}
                            </span>
                        </div>
                        <div class="network-detail-item">
                            <span class="network-detail-label">Delegated:</span>
                            <span class="network-detail-value">${backboneStakeValue} CELL | Status: <span class="${backboneDelegation?.status === 'active' ? 'status-success' : 'status-error'}">${backboneDelegation?.status === 'active' ? 'Active' : 'Inactive'}</span></span>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // KelVPN network info
        const kelvpnNet = networks['kelvpn'];
        if (kelvpnNet && kelvpnNet.available) {
            const kelvpnDelegation = delegations['kelvpn'];
            const kelvpnStakeValue = kelvpnDelegation?.stake_value ? 
                (parseFloat(kelvpnDelegation.stake_value) * 1000).toLocaleString() : 
                '0';
                
            html += `
                <div class="network-status-item">
                    <div class="network-name">
                        <span>KelVPN</span>
                        <span>(Active Links: ${kelvpnNet.links_active})</span>
                    </div>
                    <div class="network-details">
                        <div class="network-detail-item">
                            <span class="network-detail-label">Sync Status:</span>
                            <span class="network-detail-value">
                                <span class="status-indicator ${kelvpnNet.fully_synced ? 'synced' : 'syncing'}"></span>
                                ${kelvpnNet.sync_overall}
                            </span>
                        </div>
                        <div class="network-detail-item">
                            <span class="network-detail-label">Delegated:</span>
                            <span class="network-detail-value">${kelvpnStakeValue} KEL | Status: <span class="${kelvpnDelegation?.status === 'active' ? 'status-success' : 'status-error'}">${kelvpnDelegation?.status === 'active' ? 'Active' : 'Inactive'}</span></span>
                        </div>
                    </div>
                </div>
            `;
        }
        
        html += '</div>';
        return html;
    }

    generateIncomeSummaryHTML(autocollect) {
        if (!autocollect) {
            return '<div class="no-data">No autocollect data available</div>';
        }

        let html = '<div class="income-summary-grid">';

        // Backbone autocollect info
        html += `
            <div class="income-network-section">
                <div class="income-network-header">
                    <h5>
                        <span>Backbone</span>
                        <span>(${autocollect.backbone_autocollect || 'N/A'})</span>
                    </h5>
                </div>
        `;

        if (autocollect.backbone_financial) {
            const backbone = autocollect.backbone_financial;
            html += `
                <div class="income-metrics">
                    <div class="income-metric">
                        <span class="metric-label">Uncollected Fees:</span>
                        <span class="metric-value">${backbone.fees_total || '0'} ${backbone.currency || 'CELL'}</span>
                    </div>
                    <div class="income-metric">
                        <span class="metric-label">Uncollected Rewards:</span>
                        <span class="metric-value">${backbone.rewards_total || '0'} ${backbone.currency || 'CELL'}</span>
                    </div>
                </div>
            `;
        } else {
            html += '<div class="no-financial-data">No financial data available</div>';
        }

        html += '</div>';

        // KelVPN autocollect info
        html += `
            <div class="income-network-section">
                <div class="income-network-header">
                    <h5>
                        <span>KelVPN</span>
                        <span>(${autocollect.kelvpn_autocollect || 'N/A'})</span>
                    </h5>
                </div>
        `;

        if (autocollect.kelvpn_financial) {
            const kelvpn = autocollect.kelvpn_financial;
            html += `
                <div class="income-metrics">
                    <div class="income-metric">
                        <span class="metric-label">Uncollected Fees:</span>
                        <span class="metric-value">${kelvpn.fees_total || '0'} ${kelvpn.currency || 'KEL'}</span>
                    </div>
                    <div class="income-metric">
                        <span class="metric-label">Uncollected Rewards:</span>
                        <span class="metric-value">${kelvpn.rewards_total || '0'} ${kelvpn.currency || 'KEL'}</span>
                    </div>
                </div>
            `;
        } else {
            html += '<div class="no-financial-data">No KEL financial data available</div>';
        }

        html += '</div>';
        html += '</div>';

        return html;
    }

    formatUptime(uptimeString) {
        if (!uptimeString || uptimeString === 'N/A') return 'N/A';
        
        const match = uptimeString.match(/(\d+)\s*minutes?/);
        if (!match) return uptimeString;
        
        const totalMinutes = parseInt(match[1]);
        const days = Math.floor(totalMinutes / (24 * 60));
        const hours = Math.floor((totalMinutes % (24 * 60)) / 60);
        
        if (days > 0 && hours > 0) {
            return `${days} days ${hours} hours`;
        } else if (days > 0) {
            return `${days} days`;
        } else if (hours > 0) {
            return `${hours} hours`;
        } else {
            return `${totalMinutes} minutes`;
        }
    }

    formatTimeAgo(timestampString) {
        if (!timestampString || timestampString === 'N/A') return 'N/A';
        
        try {
            const cleanedTimestamp = timestampString.replace(' at ', ' ').replace(' +03', ' +0300');
            const lastCheckedDate = new Date(cleanedTimestamp);
            
            if (isNaN(lastCheckedDate.getTime())) {
                return timestampString;
            }
            
            const now = new Date();
            const diffMs = now - lastCheckedDate;
            const diffMinutes = Math.floor(diffMs / (1000 * 60));
            
            if (diffMinutes < 1) {
                return 'just now';
            } else if (diffMinutes < 60) {
                return `${diffMinutes} mins ago`;
            } else if (diffMinutes < 1440) {
                const hours = Math.floor(diffMinutes / 60);
                const mins = diffMinutes % 60;
                if (mins > 0) {
                    return `${hours} hours ${mins} mins ago`;
                } else {
                    return `${hours} hours ago`;
                }
            } else {
                const days = Math.floor(diffMinutes / 1440);
                return `${days} days ago`;
            }
        } catch (error) {
            console.warn('Error parsing timestamp:', timestampString, error);
            return timestampString;
        }
    }
}

// Initialize when DOM is loaded
let delegationStats;
document.addEventListener('DOMContentLoaded', () => {
    delegationStats = new DelegationStats();
});