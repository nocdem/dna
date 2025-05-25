<?php
// DNA API Proxy for CPUNK - With Message Retrieval Support
header('Content-Type: application/json');

// Allow cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Debug all request parameters
error_log("REQUEST PARAMS: " . json_encode($_GET));

// Handle OPTIONS request (preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// The DNA API endpoint
$api_url = "https://api.dna.cpunk.club";

// Determine the action based on the parameters and request method
if (isset($_GET['get_messages'])) {
    // Handle get messages request - NEW ENDPOINT
    $conversation_partner = isset($_GET['conversation_with']) ? $_GET['conversation_with'] : null;
    // Fix any URL decoding issues
    $conversation_partner = urldecode($conversation_partner);
    handleGetMessages($_GET['get_messages'], $conversation_partner);
} elseif (isset($_GET['action']) && $_GET['action'] === 'check_reservation' && isset($_GET['dna'])) {
    // Handle reservation check - NEW ENDPOINT FOR EVENT REGISTRATIONS
    $wallet = isset($_GET['wallet']) ? $_GET['wallet'] : null;
    handleCheckReservation($_GET['dna'], $wallet);
} elseif (isset($_GET['action']) && $_GET['action'] === 'get_attendees') {
    // Handle getting all attendees for the party
    handleGetAttendees();
} elseif (isset($_GET['tx_validate'])) {
    // Handle transaction validation
    handleTransactionValidation($_GET['tx_validate']);
} elseif (isset($_GET['lookup'])) {
    // Handle lookup requests
    handleLookup($_GET['lookup']);
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle POST requests (registration, update, or messaging)
    handlePostRequest();
} else {
    sendError('Invalid request. Please provide a lookup parameter for searches or tx_validate for transaction validation.');
}

/**
 * NEW FUNCTION: Handle message retrieval requests
 *
 * @param string $dna The DNA nickname to retrieve messages for
 * @param string|null $conversation_partner Optional DNA to filter messages by conversation
 */
function handleGetMessages($dna, $conversation_partner = null) {
    global $api_url;

    if (empty($dna)) {
        sendError('DNA parameter cannot be empty');
        return;
    }

    // Normalize input parameters 
    $dna = trim($dna);
    $conversation_partner = $conversation_partner ? trim($conversation_partner) : null;
    
    error_log("FINAL FIX: Getting messages between $dna and $conversation_partner");
    
    // Solution: Always get messages for BOTH users and merge them
    // This addresses the issue where messages may be stored in different profiles
    $all_messages = [];
    
    // Get first user's messages
    $url1 = $api_url . "?lookup=" . urlencode($dna);
    $response1 = @file_get_contents($url1);
    
    if ($response1 !== false) {
        $data1 = json_decode($response1, true);
        if ($data1 && isset($data1['status_code']) && $data1['status_code'] === 0 && isset($data1['response_data']['messages'])) {
            $user1_messages = $data1['response_data']['messages'];
            error_log("Got " . count($user1_messages) . " messages from $dna's profile");
            $all_messages = array_merge($all_messages, $user1_messages);
        }
    }
    
    // If conversation partner specified, get their messages too
    if ($conversation_partner) {
        $url2 = $api_url . "?lookup=" . urlencode($conversation_partner);
        $response2 = @file_get_contents($url2);
        
        if ($response2 !== false) {
            $data2 = json_decode($response2, true);
            if ($data2 && isset($data2['status_code']) && $data2['status_code'] === 0 && isset($data2['response_data']['messages'])) {
                $user2_messages = $data2['response_data']['messages'];
                error_log("Got " . count($user2_messages) . " messages from $conversation_partner's profile");
                $all_messages = array_merge($all_messages, $user2_messages);
            }
        }
    }
    
    // Now we have all messages from both profiles
    $messages = $all_messages;
    
    // Log the total combined messages
    error_log("TOTAL COMBINED MESSAGES from both profiles: " . count($messages));
    
    // Continue with the original code flow, but use our merged messages array

    // We already have $messages populated from both users
    // We'll skip the response checking since we handled that above
    
    try {
        // If we have no messages at all, return an appropriate response
        if (empty($messages)) {
            echo json_encode([
                'status_code' => 0,
                'dna' => $dna,
                'conversation_partner' => $conversation_partner,
                'messages' => []
            ]);
            return;
        }
        
        // If a conversation partner is specified, filter messages
        if ($conversation_partner) {
            $filtered_messages = [];
            $dnaLower = strtolower($dna);
            $partnerLower = strtolower($conversation_partner);
            
            error_log("Filtering " . count($messages) . " messages for conversation between $dna and $conversation_partner");
            
            // Filter messages to include only those between these two users
            foreach ($messages as $message) {
                // Skip messages missing required fields
                if (!isset($message['s_dna']) || !isset($message['r_dna'])) {
                    continue;
                }
                
                // Get lowercase versions for case-insensitive comparison
                $sender = strtolower(trim($message['s_dna']));
                $recipient = strtolower(trim($message['r_dna']));
                
                // Include message if it's between our two users in either direction
                if (
                    ($sender === $dnaLower && $recipient === $partnerLower) ||
                    ($sender === $partnerLower && $recipient === $dnaLower)
                ) {
                    // Format the message to have a consistent structure
                    if (!isset($message['msg']) && isset($message['message'])) {
                        $message['msg'] = $message['message'];
                    }
                    
                    $filtered_messages[] = $message;
                    error_log("✓ Including message: " . substr($message['msg'] ?? '', 0, 20) . 
                             " from " . $message['s_dna'] . " to " . $message['r_dna']);
                }
            }
            
            $messages = $filtered_messages;
            
            // Debug log to show message count for this conversation
            error_log("Filtered messages for conversation between '$dna' and '$conversation_partner': " . count($filtered_messages));
        }

        // Sort messages by timestamp (newest last for chat display)
        usort($messages, function($a, $b) {
            $timestamp_a = is_numeric($a['timestamp'] ?? 0) ? $a['timestamp'] : strtotime($a['timestamp']);
            $timestamp_b = is_numeric($b['timestamp'] ?? 0) ? $b['timestamp'] : strtotime($b['timestamp']);
            
            return $timestamp_a - $timestamp_b; // Ascending order (oldest first)
        });
        
        // Final message count
        error_log("FINAL MESSAGE COUNT: " . count($messages));
        foreach ($messages as $index => $message) {
            if (isset($message['s_dna']) && isset($message['r_dna']) && isset($message['msg'])) {
                error_log("FINAL MESSAGE $index: sender=" . $message['s_dna'] . 
                         ", recipient=" . $message['r_dna'] . 
                         ", content=" . substr($message['msg'], 0, 20));
            }
        }
        
        // Return just the messages as JSON
        echo json_encode([
            'status_code' => 0,
            'dna' => $dna,
            'conversation_partner' => $conversation_partner,
            'messages' => $messages
        ]);
        
    } catch (Exception $e) {
        sendError('Error processing messages: ' . $e->getMessage());
    }
}

/**
 * Handle lookup requests for nicknames or wallet addresses
 *
 * @param string $lookup The nickname or address to look up
 */
function handleLookup($lookup) {
    global $api_url;

    if (empty($lookup)) {
        sendError('Lookup parameter cannot be empty');
        return;
    }

    // Build the request URL
    $request_url = $api_url . "?lookup=" . urlencode($lookup);

    // Make the API request
    $response = @file_get_contents($request_url);

    if ($response === false) {
        sendError('Error connecting to DNA service');
        return;
    }

    // Return the response as-is
    echo $response;
}

/**
 * Handle transaction validation requests
 *
 * @param string $tx_hash The transaction hash to validate
 */
function handleTransactionValidation($tx_hash) {
    global $api_url;

    if (empty($tx_hash)) {
        sendError('Transaction hash cannot be empty');
        return;
    }

    // Build the request URL
    $request_url = $api_url . "?tx_validate=" . urlencode($tx_hash);

    // Log transaction validation request (optional)
    error_log("Transaction validation request: tx_hash={$tx_hash}");

    // Make the API request
    $response = @file_get_contents($request_url);

    if ($response === false) {
        sendError('Error connecting to DNA service for transaction validation');
        return;
    }

    // Return the validation response as-is
    echo $response;
}

/**
 * Handle all POST requests (registration, update, or messaging)
 */
function handlePostRequest() {
    global $api_url;

    // Get the JSON POST data
    $input = json_decode(file_get_contents('php://input'), true);

    if (!$input) {
        sendError('Invalid JSON data');
        return;
    }

    // Check what action is being requested
    $action = isset($input['action']) ? $input['action'] : 'add';

    // Handle different actions
    switch ($action) {
        case 'add':
            // For registration, require name, wallet and tx_hash
            if (!isset($input['name']) || !isset($input['wallet'])) {
                sendError('Name and wallet parameters are required for registration');
                return;
            }
            // Process registration
            processApiRequest($input);
            break;
            
        case 'update':
            // For updates, wallet is required
            if (!isset($input['wallet'])) {
                sendError('Wallet parameter is required for updates');
                return;
            }
            
            // Check what type of update this is
            if (isset($input['delegations']) && is_array($input['delegations'])) {
                // This is a delegation update
                processDelegationUpdate($input);
            } else if (isset($input['messages']) && is_array($input['messages'])) {
                // This is a messaging update
                processMessagingUpdate($input);
            } else {
                // Regular update
                processApiRequest($input);
            }
            break;

        case 'update_reservation':
            // For party reservation updates, dna_nickname is required
            if (!isset($input['dna_nickname']) || !isset($input['wallet']) || !isset($input['tx_hash'])) {
                sendError('DNA nickname, wallet, and transaction hash are required for reservation updates');
                return;
            }
            
            // Process reservation update
            processReservationUpdate($input);
            break;
            
        default:
            sendError('Invalid action specified');
            break;
    }
}

/**
 * Process standard API requests (add/update)
 * 
 * @param array $input The request data
 */
function processApiRequest($input) {
    global $api_url;
    
    // For debugging
    error_log("DNA API Request: action={$input['action']}, data=" . json_encode($input));

    // Set up the cURL request - pass through all data to the API
    $ch = curl_init($api_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($input));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);

    // Execute the request
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if (curl_errno($ch)) {
        sendError('API request failed: ' . curl_error($ch));
    } else {
        // Log response for debugging (optional)
        error_log("DNA API Response: " . $response);

        http_response_code($http_code);
        echo $response;
    }

    curl_close($ch);
}

/**
 * Process delegation update requests (direct method)
 * 
 * @param array $input The request data
 */
function processDelegationUpdate($input) {
    global $api_url;
    
    // Required fields check
    if (!isset($input['wallet']) || !isset($input['delegations']) || !is_array($input['delegations'])) {
        sendError('Missing required fields: wallet and delegations array');
        return;
    }
    
    $wallet = $input['wallet'];
    $delegations = $input['delegations'];
    
    // Log the delegation update request
    error_log("Delegation update request: wallet={$wallet}, delegations_count=" . count($delegations));
    
    // Validate each delegation in the array
    foreach ($delegations as $delegation) {
        if (!isset($delegation['tx_hash']) || !isset($delegation['order_hash'])) {
            sendError('Each delegation must include tx_hash and order_hash');
            return;
        }
    }
    
    // Process the request directly without fetching existing data
    $ch = curl_init($api_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($input));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    
    // Execute the request
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if (curl_errno($ch)) {
        sendError('API request failed: ' . curl_error($ch));
    } else {
        // Log successful response
        error_log("Delegation update response: HTTP {$http_code}");
        
        // Return the API response
        http_response_code($http_code);
        echo $response;
    }
    
    curl_close($ch);
}

/**
 * Process messaging update requests
 * 
 * @param array $input The request data
 */
function processMessagingUpdate($input) {
    global $api_url;
    
    // Required fields check
    if (!isset($input['wallet']) || !isset($input['messages']) || !is_array($input['messages'])) {
        sendError('Missing required fields: wallet and messages array');
        return;
    }
    
    $wallet = $input['wallet'];
    $messages = $input['messages'];
    
    // Log the messaging update request
    error_log("Messaging update request: wallet={$wallet}, messages_count=" . count($messages));
    
    // Validate each message in the array
    foreach ($messages as $message) {
        if (!isset($message['s_dna']) || !isset($message['r_dna']) || !isset($message['msg'])) {
            sendError('Each message must include s_dna, r_dna, and msg fields');
            return;
        }
    }
    
    // Process the request
    $ch = curl_init($api_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($input));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    
    // Execute the request
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if (curl_errno($ch)) {
        sendError('API request failed: ' . curl_error($ch));
    } else {
        // Log successful response
        error_log("Messaging update response: HTTP {$http_code}");
        
        // Return the API response
        http_response_code($http_code);
        echo $response;
    }
    
    curl_close($ch);
}

/**
 * Handle reservation status check for mainnet party
 * 
 * @param string $dna The DNA nickname to check reservation status for
 */
function handleCheckReservation($dna, $wallet = null) {
    if (empty($dna)) {
        sendError('DNA parameter cannot be empty');
        return;
    }
    
    // Log the request (optional)
    error_log("Reservation check for DNA: {$dna}" . ($wallet ? ", wallet: {$wallet}" : ""));
    
    // Define the party list file path
    $party_list_file = 'party_list.txt';
    
    try {
        // Default values
        $isReserved = false;
        $txHash = null;
        $walletReserved = false;
        
        // Check if file exists
        if (file_exists($party_list_file)) {
            // Read the party list file
            $contents = file_get_contents($party_list_file);
            $wallets = array();
            
            // Process each line to check for the DNA and collect all wallets
            $lines = explode("\n", $contents);
            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line)) continue;
                
                // Each line is formatted as "nickname|tx_hash|date" or can be extended to "nickname|tx_hash|date|wallet"
                $parts = explode('|', $line);
                
                // Check if this line contains wallet information (newer format)
                $lineWallet = (count($parts) >= 4) ? $parts[3] : null;
                
                // If line contains a wallet address, add to set of reserved wallets
                if ($lineWallet) {
                    $wallets[] = $lineWallet;
                }
                
                // Check if this DNA is already reserved
                if (count($parts) >= 2 && $parts[0] === $dna) {
                    $isReserved = true;
                    $txHash = $parts[1];
                }
                
                // If wallet parameter is provided, check if this wallet already has a reservation
                if ($wallet && $lineWallet && $lineWallet === $wallet) {
                    $walletReserved = true;
                }
            }
        }
        
        // Return the reservation status
        $response = [
            'status_code' => 0,
            'dna' => $dna,
            'reserved' => $isReserved,
            'tx_hash' => $txHash
        ];
        
        // Add wallet reservation status if wallet was provided
        if ($wallet) {
            $response['wallet_reserved'] = $walletReserved;
        }
        
        echo json_encode($response);
        
    } catch (Exception $e) {
        sendError('Error processing reservation check: ' . $e->getMessage());
    }
}

/**
 * Handle getting all party attendees
 */
function handleGetAttendees() {
    // Define the party list file path
    $party_list_file = 'party_list.txt';
    
    try {
        // Check if file exists
        if (!file_exists($party_list_file)) {
            // Return empty list if file doesn't exist
            echo json_encode([
                'status_code' => 0,
                'attendees' => []
            ]);
            return;
        }
        
        // Read the party list file
        $contents = file_get_contents($party_list_file);
        $attendees = [];
        
        // Process each line
        $lines = explode("\n", $contents);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            
            // Each line is formatted as "nickname|tx_hash|date"
            $parts = explode('|', $line);
            
            if (count($parts) >= 3) {
                $attendees[] = [
                    'nickname' => $parts[0],
                    'tx_hash' => $parts[1],
                    'date' => $parts[2],
                    'status' => 'Confirmed'
                ];
            }
        }
        
        // Return the attendees list
        echo json_encode([
            'status_code' => 0,
            'attendees' => $attendees
        ]);
        
    } catch (Exception $e) {
        sendError('Error retrieving attendees: ' . $e->getMessage());
    }
}

/**
 * Process reservation updates for the mainnet party
 * 
 * @param array $input The request data with dna_nickname, wallet, and tx_hash
 */
function processReservationUpdate($input) {
    // Required fields check already done in the switch statement
    $wallet = $input['wallet'];
    $dnaName = $input['dna_nickname'];
    $txHash = $input['tx_hash'];
    
    // Enhanced logging for better debugging
    error_log("PARTY RESERVATION - Processing update request: wallet={$wallet}, dna={$dnaName}, tx_hash={$txHash}");
    error_log("PARTY RESERVATION - Request data: " . json_encode($input));
    
    try {
        // First, let's check if this wallet has already made a reservation
        $party_list_file = 'party_list.txt';
        
        if (file_exists($party_list_file)) {
            $contents = file_get_contents($party_list_file);
            $lines = explode("\n", $contents);
            
            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line)) continue;
                
                $parts = explode('|', $line);
                if (count($parts) >= 4 && $parts[3] === $wallet) {
                    // This wallet has already made a reservation
                    error_log("PARTY RESERVATION - Wallet {$wallet} already has a reservation.");
                    sendError('This wallet has already reserved a spot for the party. Only one reservation per wallet is allowed.');
                    return;
                }
            }
        }
        
        // If we get here, wallet doesn't have an existing reservation
        $current_date = date('Y-m-d H:i:s');
        $entry = "{$dnaName}|{$txHash}|{$current_date}|{$wallet}\n";
        
        // Check if file exists and is writable
        if (!file_exists($party_list_file)) {
            // Try to create the file if it doesn't exist
            if (file_put_contents($party_list_file, $entry) === false) {
                error_log("Error: Could not create party_list.txt");
                sendError('Failed to create reservation file');
                return;
            }
        } else if (!is_writable($party_list_file)) {
            error_log("Error: party_list.txt exists but is not writable");
            sendError('Reservation file exists but is not writable');
            return;
        } else {
            // File exists and is writable, append to it
            if (file_put_contents($party_list_file, $entry, FILE_APPEND) === false) {
                error_log("Error: Failed to write to party_list.txt");
                sendError('Failed to save reservation record');
                return;
            }
        }
        
        // Enhanced logging for success confirmation
        error_log("PARTY RESERVATION - Successfully added {$dnaName} to party_list.txt");
        error_log("PARTY RESERVATION - File now contains " . filesize($party_list_file) . " bytes");
        
        // Return success response
        $response = [
            'status_code' => 0,
            'message' => 'OK',
            'description' => 'Reservation recorded successfully',
            'dna' => $dnaName,
            'tx_hash' => $txHash,
            'date' => $current_date
        ];
        
        error_log("PARTY RESERVATION - Sending success response: " . json_encode($response));
        echo json_encode($response);
    } catch (Exception $e) {
        sendError('Error processing reservation update: ' . $e->getMessage());
    }
}

/**
 * Send an error response
 *
 * @param string $message Error message
 */
function sendError($message) {
    http_response_code(400);
    echo json_encode(['error' => $message]);
    exit();
}
?>
