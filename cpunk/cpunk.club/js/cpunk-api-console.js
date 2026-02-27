// CPUNK API Console
// A resizable, draggable console for debugging API requests and responses

// Global variables
let apiLogs = [];
let requestResponsePairs = {};

// Function to extract API method from message or data
function extractMethod(message, data) {
    // First check if message has method in it
    let methodMatch = message.match(/API (?:Request|Response): ([A-Za-z]+)/);
    if (methodMatch && methodMatch[1]) {
        return methodMatch[1];
    }
    
    // Try to get from URL or method parameter
    if (data) {
        if (data.url) {
            const urlMatch = data.url.match(/method=([A-Za-z]+)/);
            if (urlMatch && urlMatch[1]) return urlMatch[1];
        }
        
        if (data.params && data.params.hashTx) {
            // Store request identifier for params with hashTx
            return `${data.params.net || ''}:${data.params.hashTx}`;
        }
        
        if (data.method) return data.method;
    }
    
    return null;
}

// Function to extract unique request identifier 
function extractRequestIdentifier(data) {
    // For data with hashTx, create a unique identifier
    if (data && data.params && data.params.hashTx) {
        return `${data.params.net || ''}:${data.params.hashTx}`;
    }
    
    // For data with hash in response
    if (data && data.data && data.data.hash) {
        return `Cpunk:${data.data.hash}`;
    }
    
    return null;
}

// Create API activity indicator
function createActivityIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'apiActivityIndicator';
    indicator.className = 'api-activity-indicator';
    indicator.innerHTML = '<div class="indicator-dot"></div>';
    indicator.style.display = 'none';
    
    // Add click handler to show console
    indicator.addEventListener('click', function() {
        const consoleContainer = document.getElementById('apiConsoleContainer');
        if (consoleContainer) {
            consoleContainer.style.display = 'flex';
            indicator.style.display = 'none';
        }
    });
    
    document.body.appendChild(indicator);
    return indicator;
}

// Show activity indicator with animation
function showActivityIndicator() {
    const indicator = document.getElementById('apiActivityIndicator');
    if (!indicator) return;
    
    // Only show indicator if console is hidden
    const consoleContainer = document.getElementById('apiConsoleContainer');
    if (consoleContainer && consoleContainer.style.display === 'none') {
        indicator.style.display = 'block';
        
        // Animate indicator
        const dot = indicator.querySelector('.indicator-dot');
        if (dot) {
            dot.classList.add('pulse');
            setTimeout(() => {
                dot.classList.remove('pulse');
            }, 1000);
        }
    }
}

// Function to log API activities with timestamp - make it globally available
window.logAPI = function(message, data) {
    const timestamp = new Date().toLocaleTimeString();
    const now = Date.now();
    
    // Check if this is a request or response
    const isRequest = message.includes('request') || message.includes('Request:');
    const isResponse = message.includes('response') || message.includes('Response:');
    
    // Extract the API method and unique identifier for better pairing
    const method = extractMethod(message, data);
    const requestId = extractRequestIdentifier(data);
    
    const logEntry = {
        id: now, // Unique ID for this log entry
        timestamp,
        message,
        data,
        type: isRequest ? 'request' : (isResponse ? 'response' : 'info'),
        method: method, // Store the method for pairing
        requestId: requestId, // Store unique request ID if available
        pair: null // Will be filled in if this is part of a request/response pair
    };
    
    // Try to organize requests and responses
    if (isRequest) {
        // Create a unique key for the request-response pair
        const pairKey = requestId || method || now.toString();
        
        // This is a request, store it by its ID and method
        requestResponsePairs[pairKey] = {
            request: logEntry,
            responses: [], // Store multiple responses
            method: method,
            requestId: requestId,
            time: now,
            key: pairKey
        };
    } else if (isResponse) {
        // This is a response, try to find matching request
        let matched = false;
        
        // First try to match by request ID (most accurate)
        if (requestId) {
            // Find the matching request entry by requestId
            const matchingPair = Object.values(requestResponsePairs)
                .find(pair => pair.requestId === requestId);
            
            if (matchingPair) {
                matchingPair.responses.push(logEntry);
                logEntry.relatedRequest = matchingPair.request.id;
                matched = true;
            }
        }
        
        // If not matched by request ID, try matching by method
        if (!matched && method) {
            // Find requests with the same method
            const matchingMethodRequests = Object.values(requestResponsePairs)
                .filter(pair => pair.method === method)
                .sort((a, b) => b.time - a.time); // Most recent first
            
            if (matchingMethodRequests.length > 0) {
                // Match found by method - add this response to the responses array
                const pair = matchingMethodRequests[0];
                pair.responses.push(logEntry);
                
                // Store reference to the request in the response
                logEntry.relatedRequest = pair.request.id;
                matched = true;
            }
        }
        
        // If still no match, fall back to time-based matching
        if (!matched) {
            const recentRequests = Object.values(requestResponsePairs)
                .sort((a, b) => b.time - a.time);
            
            if (recentRequests.length > 0) {
                const pair = recentRequests[0];
                pair.responses.push(logEntry);
                
                // Store reference to the request in the response
                logEntry.relatedRequest = pair.request.id;
            }
        }
    }
    
    apiLogs.push(logEntry);
    
    // Update the console display if it exists
    updateAPIConsole();
    
    // Show activity indicator
    showActivityIndicator();
    
}

// Function to create and update the API console
function updateAPIConsole() {
    const apiConsole = document.getElementById('apiConsole');
    if (!apiConsole) return;
    
    // Get the container and check if we need to create a toggle button
    const consoleContainer = document.getElementById('apiConsoleContainer');
    let toggleAllBtn = document.getElementById('toggleAllLogsBtn');
    
    // Create toggle all button if it doesn't exist
    if (!toggleAllBtn) {
        const consoleHeader = consoleContainer.querySelector('.api-console-header');
        toggleAllBtn = document.createElement('button');
        toggleAllBtn.id = 'toggleAllLogsBtn';
        toggleAllBtn.className = 'toggle-all-btn';
        toggleAllBtn.textContent = 'Show Details';
        toggleAllBtn.setAttribute('data-state', 'collapsed');
        consoleHeader.appendChild(toggleAllBtn);
        
        // Add event listener to toggle all entries
        toggleAllBtn.addEventListener('click', function() {
            const state = toggleAllBtn.getAttribute('data-state');
            const allContentSections = document.querySelectorAll('.api-log-pair-content, .api-log-content');
            const allToggleBtns = document.querySelectorAll('.api-toggle-btn');
            
            if (state === 'collapsed') {
                // Expand all
                allContentSections.forEach(section => {
                    section.style.display = 'block';
                });
                allToggleBtns.forEach(btn => {
                    btn.textContent = '▼';
                });
                toggleAllBtn.textContent = 'Hide Details';
                toggleAllBtn.setAttribute('data-state', 'expanded');
            } else {
                // Collapse all
                allContentSections.forEach(section => {
                    section.style.display = 'none';
                });
                allToggleBtns.forEach(btn => {
                    btn.textContent = '▶';
                });
                toggleAllBtn.textContent = 'Show Details';
                toggleAllBtn.setAttribute('data-state', 'collapsed');
            }
        });
    }
    
    // Clear existing content
    apiConsole.innerHTML = '';
    
    // Create a container for all entries
    const entriesContainer = document.createElement('div');
    entriesContainer.className = 'api-entries-container';
    
    // Get all request/response groups from our tracking object
    const groupedLogs = [];
    const processedIds = new Set();
    
    // Convert our tracking object to ordered entries (most recent first)
    const recentPairs = Object.values(requestResponsePairs)
        .sort((a, b) => b.time - a.time) // Sort by request time, newest first
        .slice(0, 5); // Only show the most recent 5 request groups
    
    // Process each request-response group
    recentPairs.forEach(pair => {
        // Mark the request as processed
        processedIds.add(pair.request.id);
        
        // Add all responses to processed set
        pair.responses.forEach(response => {
            processedIds.add(response.id);
        });
        
        // Add the group to our display list
        groupedLogs.push({
            type: 'group',
            request: pair.request,
            responses: pair.responses,
            timestamp: pair.request.timestamp,
            method: pair.method
        });
    });
    
    // Process any remaining logs that aren't part of a group (unlikely with new logic)
    const recentLogs = apiLogs.slice(-10).reverse();
    
    recentLogs.forEach(log => {
        if (processedIds.has(log.id)) return; // Skip already processed logs
        
        // This is a standalone log
        groupedLogs.push({
            type: 'single',
            log: log
        });
        processedIds.add(log.id);
    });
    
    // Display logs - already limited to 5 in the grouping logic
    const displayLogs = groupedLogs;
    
    displayLogs.forEach(item => {
        if (item.type === 'group') {
            // Create a unified entry for request/response group
            const pairEntry = document.createElement('div');
            pairEntry.className = 'api-log-pair';
            
            // Get the method name to display in the header
            const methodName = item.method || extractMethod(item.request.message, item.request.data) || 'API';
            
            // Show timestamp range if there are responses
            let timeRange = item.request.timestamp;
            if (item.responses.length > 0) {
                // Get last response timestamp
                const lastResponseTime = item.responses[item.responses.length - 1].timestamp;
                timeRange += ` → ${lastResponseTime}`;
            }
            
            // Pair header with timestamps
            const pairHeader = document.createElement('div');
            pairHeader.className = 'api-log-pair-header';
            pairHeader.innerHTML = `
                <div class="api-log-time">${timeRange}</div>
                <div class="api-method-badge">${methodName}</div>
                <div class="api-log-pair-title">
                    Request + ${item.responses.length} Response${item.responses.length !== 1 ? 's' : ''}
                </div>
                <button class="copy-group-btn" title="Copy all request & responses">Copy All</button>
                <button class="api-toggle-btn">▶</button>
            `;
            pairEntry.appendChild(pairHeader);
            
            // Content container
            const pairContent = document.createElement('div');
            pairContent.className = 'api-log-pair-content';
            pairContent.style.display = 'none';
            
            // Request section
            const reqSection = document.createElement('div');
            reqSection.className = 'api-req-section';
            
            // Create request header
            const reqHeader = document.createElement('div');
            reqHeader.className = 'api-section-header';
            reqHeader.innerHTML = `
                <span class="api-request-label">REQUEST</span>
                <span class="api-section-detail">${item.request.message}</span>
            `;
            reqSection.appendChild(reqHeader);
            
            // Create request data display
            const reqData = document.createElement('pre');
            reqData.className = 'api-log-data';
            try {
                reqData.textContent = JSON.stringify(item.request.data, null, 2);
            } catch (e) {
                reqData.textContent = String(item.request.data);
            }
            reqSection.appendChild(reqData);
            
            // Add request section to content
            pairContent.appendChild(reqSection);
            
            // Add each response section
            item.responses.forEach((response, index) => {
                const resSection = document.createElement('div');
                resSection.className = 'api-res-section';
                
                // Create response header with index
                const resHeader = document.createElement('div');
                resHeader.className = 'api-section-header';
                resHeader.innerHTML = `
                    <span class="api-response-label">RESPONSE ${item.responses.length > 1 ? (index + 1) : ''}</span>
                    <span class="api-section-detail">${response.message || 'API Response'} (${response.timestamp})</span>
                `;
                resSection.appendChild(resHeader);
                
                // Create response data display
                const resData = document.createElement('pre');
                resData.className = 'api-log-data';
                try {
                    resData.textContent = JSON.stringify(response.data, null, 2);
                } catch (e) {
                    resData.textContent = String(response.data);
                }
                resSection.appendChild(resData);
                
                // Add this response section to content
                pairContent.appendChild(resSection);
            });
            
            // Add content to pair entry
            pairEntry.appendChild(pairContent);
            
            // Get toggle and copy buttons
            const toggleBtn = pairHeader.querySelector('.api-toggle-btn');
            const copyBtn = pairHeader.querySelector('.copy-group-btn');
            
            // Add copy functionality
            copyBtn.addEventListener('click', function(e) {
                e.stopPropagation(); // Don't trigger parent click
                
                // Create formatted text for copying
                let copyText = '';
                
                // Add request
                copyText += `REQUEST: ${item.request.message}\n`;
                copyText += JSON.stringify(item.request.data, null, 2);
                copyText += '\n\n';
                
                // Add all responses
                item.responses.forEach((response, index) => {
                    if (item.responses.length > 1) {
                        copyText += `RESPONSE ${index+1}: ${response.message}\n`;
                    } else {
                        copyText += `RESPONSE: ${response.message}\n`;
                    }
                    copyText += JSON.stringify(response.data, null, 2);
                    copyText += '\n\n';
                });
                
                // Copy to clipboard
                navigator.clipboard.writeText(copyText).then(() => {
                    // Visual feedback
                    const originalText = copyBtn.textContent;
                    copyBtn.textContent = '✓ Copied!';
                    copyBtn.style.background = '#27ae60';
                    
                    // Revert after a delay
                    setTimeout(() => {
                        copyBtn.textContent = originalText;
                        copyBtn.style.background = '';
                    }, 1500);
                });
            });
            
            // Make the header clickable for toggling (except buttons)
            pairHeader.addEventListener('click', function(e) {
                // Don't toggle if clicked on a button
                if (e.target.tagName === 'BUTTON') {
                    return;
                }
                
                if (pairContent.style.display === 'none') {
                    pairContent.style.display = 'block';
                    toggleBtn.textContent = '▼';
                } else {
                    pairContent.style.display = 'none';
                    toggleBtn.textContent = '▶';
                }
            });
            
            entriesContainer.appendChild(pairEntry);
        } else {
            // Create a single entry for unpaired log
            const logEntry = document.createElement('div');
            logEntry.className = 'api-log-entry';
            
            const logHeader = document.createElement('div');
            logHeader.className = 'api-log-header';
            logHeader.innerHTML = `
                <span class="api-log-time">${item.log.timestamp}</span>
                <span class="api-log-message">${item.log.message}</span>
                <button class="api-toggle-btn">▶</button>
            `;
            
            const logContent = document.createElement('div');
            logContent.className = 'api-log-content';
            logContent.style.display = 'none';
            
            const logData = document.createElement('pre');
            logData.className = 'api-log-data';
            try {
                logData.textContent = JSON.stringify(item.log.data, null, 2);
            } catch (e) {
                logData.textContent = String(item.log.data);
            }
            
            logContent.appendChild(logData);
            logEntry.appendChild(logHeader);
            logEntry.appendChild(logContent);
            
            // Add toggle functionality
            const toggleBtn = logHeader.querySelector('.api-toggle-btn');
            
            // Make the entire header clickable for toggling
            logHeader.addEventListener('click', function(e) {
                // Don't toggle if clicked on a button
                if (e.target.tagName === 'BUTTON' && e.target.id === 'toggleAllLogsBtn') {
                    return;
                }
                
                if (logContent.style.display === 'none') {
                    logContent.style.display = 'block';
                    toggleBtn.textContent = '▼';
                } else {
                    logContent.style.display = 'none';
                    toggleBtn.textContent = '▶';
                }
            });
            
            entriesContainer.appendChild(logEntry);
        }
    });
    
    apiConsole.appendChild(entriesContainer);
}

// Initialize API console when document is ready
function initApiConsole() {
    // Create API console element
    const apiConsoleContainer = document.createElement('div');
    apiConsoleContainer.id = 'apiConsoleContainer';
    apiConsoleContainer.className = 'api-console-container';
    apiConsoleContainer.style.display = 'none'; // Hide by default
    apiConsoleContainer.innerHTML = `
        <div class="api-console-header">
            <h3>API Activity</h3>
            <button id="toggleApiConsole">Hide</button>
        </div>
        <div id="apiConsole" class="api-console"></div>
    `;
    document.body.appendChild(apiConsoleContainer);
    
    // Add key combination listener (Ctrl+Shift+A)
    document.addEventListener('keydown', function(e) {
        // Check for Ctrl+Shift+A
        if (e.ctrlKey && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
            const consoleContainer = document.getElementById('apiConsoleContainer');
            if (consoleContainer) {
                if (consoleContainer.style.display === 'none') {
                    consoleContainer.style.display = 'flex';
                    
                    // Hide the activity indicator when console is shown
                    const indicator = document.getElementById('apiActivityIndicator');
                    if (indicator) {
                        indicator.style.display = 'none';
                    }
                } else {
                    consoleContainer.style.display = 'none';
                }
            }
        }
    });
    
    // Add styles for API console and activity indicator
    const style = document.createElement('style');
    style.textContent = `
        .api-console-container {
            position: fixed;
            bottom: 0;
            right: 0;
            width: 500px;
            height: 400px;
            background: rgba(18, 28, 44, 0.95);
            color: #f0f0f0;
            border: 1px solid #3661aa;
            border-radius: 5px 0 0 0;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            overflow: hidden;
            resize: both;
            min-width: 350px;
            min-height: 150px;
            box-shadow: 0 0 15px rgba(54, 97, 170, 0.6);
        }
        
        /* API Activity Indicator */
        .api-activity-indicator {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 20px;
            height: 20px;
            background: rgba(18, 28, 44, 0.8);
            border: 1px solid #3661aa;
            border-radius: 50%;
            z-index: 9998;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 0 10px rgba(54, 97, 170, 0.5);
            transition: all 0.3s ease;
        }
        
        .api-activity-indicator:hover {
            transform: scale(1.2);
            box-shadow: 0 0 15px rgba(54, 97, 170, 0.8);
        }
        
        .indicator-dot {
            width: 10px;
            height: 10px;
            background: #3661aa;
            border-radius: 50%;
        }
        
        .indicator-dot.pulse {
            animation: pulse-animation 1s ease;
            background: #f97834;
        }
        
        @keyframes pulse-animation {
            0% { transform: scale(1); }
            50% { transform: scale(1.5); }
            100% { transform: scale(1); }
        }
        .api-console-header {
            padding: 8px 10px;
            background: linear-gradient(90deg, #1a365d 0%, #2a5ca9 100%);
            border-bottom: 1px solid #3661aa;
            display: flex;
            align-items: center;
            cursor: move;
            user-select: none;
        }
        .api-console-header h3 {
            flex: 1;
            text-shadow: 0 1px 2px rgba(0,0,0,0.5);
            color: #fff;
        }
        .toggle-all-btn {
            margin-right: 10px;
            background: #0f7ac0;
            color: white;
            border: none;
            padding: 4px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 500;
            box-shadow: 0 1px 3px rgba(0,0,0,0.2);
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
            transition: all 0.2s ease;
        }
        .toggle-all-btn:hover {
            background: #2994de;
            box-shadow: 0 2px 5px rgba(0,0,0,0.3);
        }
        .api-console-header h3 {
            margin: 0;
            font-size: 14px;
            font-weight: 500;
            color: #fff;
        }
        .api-console {
            flex: 1;
            overflow-y: auto;
            padding: 10px;
            scroll-behavior: smooth;
        }
        .api-entries-container {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .api-log-pair {
            margin-bottom: 12px;
            border: 1px solid #3661aa;
            border-radius: 6px;
            overflow: hidden;
            background: rgba(24, 36, 58, 0.85);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            transition: all 0.2s ease;
        }
        .api-log-pair:hover {
            box-shadow: 0 3px 8px rgba(54, 97, 170, 0.5);
        }
        .api-log-pair-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 12px;
            background: linear-gradient(90deg, #1e4177 0%, #2a5ca9 100%);
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }
        .api-log-pair-header:hover {
            background: linear-gradient(90deg, #245090 0%, #326ac1 100%);
        }
        .api-method-badge {
            background: #0f7ac0;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 0.3px;
            text-transform: uppercase;
            box-shadow: 0 1px 3px rgba(0,0,0,0.2);
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
        }
        .copy-group-btn {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: #ffffff;
            cursor: pointer;
            font-size: 10px;
            padding: 3px 8px;
            border-radius: 3px;
            margin-right: 5px;
            transition: all 0.2s;
        }
        .copy-group-btn:hover {
            background: rgba(255,255,255,0.25);
            color: #ffffff;
        }
        .api-log-pair-title {
            flex: 1;
            color: #ffffff;
            font-weight: 500;
            margin: 0 12px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
        }
        .api-log-pair-content {
            padding: 0;
            border-top: 1px solid #622a88;
        }
        .api-req-section, .api-res-section {
            padding: 10px 12px;
        }
        .api-req-section {
            background: rgba(24, 40, 80, 0.3);
            border-bottom: 1px dotted #3661aa;
        }
        .api-res-section {
            background: rgba(24, 60, 90, 0.2);
            margin-bottom: 2px;
            position: relative;
        }
        
        .api-res-section:not(:last-child)::after {
            content: "";
            position: absolute;
            bottom: -1px;
            left: 15%;
            width: 70%;
            height: 1px;
            background: rgba(54, 97, 170, 0.3);
        }
        .api-section-header {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        .api-section-detail {
            color: #b5d2ff;
            font-size: 11px;
            margin-left: 8px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            flex: 1;
        }
        .api-log-entry {
            margin-bottom: 12px;
            border-radius: 6px;
            background: rgba(24, 36, 58, 0.85);
            border: 1px solid #3661aa;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .api-log-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 12px;
            background: linear-gradient(90deg, #1e4177 0%, #2a5ca9 100%);
            cursor: pointer;
            user-select: none;
        }
        .api-log-content {
            padding: 10px 12px;
            border-top: 1px solid #3661aa;
        }
        .api-toggle-btn {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: #b5d2ff;
            cursor: pointer;
            font-size: 10px;
            padding: 3px 8px;
            border-radius: 3px;
            transition: all 0.2s;
        }
        .api-toggle-btn:hover {
            background: rgba(255,255,255,0.2);
            color: #ffffff;
        }
        .api-log-time {
            color: #79bbff;
            margin-right: 8px;
            font-weight: bold;
            white-space: nowrap;
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
        }
        .api-request-label {
            background: #2351a0;
            color: white;
            padding: 3px 8px;
            margin-right: 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            box-shadow: 0 1px 2px rgba(0,0,0,0.2);
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
        }
        .api-response-label {
            background: #08689c;
            color: white;
            padding: 3px 8px;
            margin-right: 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            box-shadow: 0 1px 2px rgba(0,0,0,0.2);
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
        }
        .api-log-message {
            color: #ffffff;
            font-weight: 500;
            flex: 1;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin: 0 12px;
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
        }
        .api-log-data {
            color: #b2d4ff;
            margin: 10px 0 0 0;
            font-size: 11px;
            max-height: 150px;
            overflow-y: auto;
            background: rgba(20, 12, 30, 0.4);
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #8032c3;
            white-space: pre-wrap;
            word-break: break-word;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.2);
            line-height: 1.4;
        }
        #toggleApiConsole {
            background: #0f7ac0;
            border: none;
            color: white;
            padding: 3px 10px;
            border-radius: 3px;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 1px 2px rgba(0,0,0,0.2);
            text-shadow: 0 1px 1px rgba(0,0,0,0.3);
        }
        #toggleApiConsole:hover {
            background: #2994de;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
    `;
    document.head.appendChild(style);
    
    // Add toggle functionality to completely hide the console
    document.getElementById('toggleApiConsole').addEventListener('click', function() {
        const consoleContainer = document.getElementById('apiConsoleContainer');
        if (consoleContainer) {
            consoleContainer.style.display = 'none';
        }
    });
    
    // Make the console draggable
    const header = apiConsoleContainer.querySelector('.api-console-header');
    let isDragging = false;
    let offsetX, offsetY;
    
    header.addEventListener('mousedown', function(e) {
        isDragging = true;
        offsetX = e.clientX - apiConsoleContainer.getBoundingClientRect().left;
        offsetY = e.clientY - apiConsoleContainer.getBoundingClientRect().top;
    });
    
    document.addEventListener('mousemove', function(e) {
        if (!isDragging) return;
        
        const x = e.clientX - offsetX;
        const y = e.clientY - offsetY;
        
        apiConsoleContainer.style.right = 'auto';
        apiConsoleContainer.style.bottom = 'auto';
        apiConsoleContainer.style.left = `${x}px`;
        apiConsoleContainer.style.top = `${y}px`;
    });
    
    document.addEventListener('mouseup', function() {
        isDragging = false;
    });
    
    // Log initial message
    logAPI('API Console Initialized', { time: new Date().toString() });
}

// Create a global API console object
window.CpunkAPIConsole = {
    // Modified init to ensure only one console instance
    init: function() {
        if (!consoleInitialized) {
            if (!document.getElementById('apiConsoleContainer')) {
                initApiConsole();
                consoleInitialized = true;
                return true;
            } else {
                return false;
            }
        }
        return false;
    },
    log: logAPI
};

// Keep track of console instances
let consoleInitialized = false;

// Initialize immediately to ensure it's available
(function() {
    
    // Use MutationObserver to ensure we don't create multiple consoles
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initOnce);
    } else {
        initOnce();
    }
    
    function initOnce() {
        if (!consoleInitialized) {
            // Check if a console already exists
            if (!document.getElementById('apiConsoleContainer')) {
                initApiConsole();
                // Create the activity indicator
                createActivityIndicator();
                consoleInitialized = true;
            }
        }
    }
})();