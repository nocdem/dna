<?php
/**
 * Network Health API
 * Returns network health data using Cellframe RPC commands
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

try {
    // Get network node info
    $nodeInfoCommand = '/opt/cellframe-node/bin/cellframe-node-cli node list -net Backbone 2>/dev/null';
    $nodeInfoOutput = shell_exec($nodeInfoCommand);
    
    // Count active masternodes
    $activeMasternodes = 0;
    if ($nodeInfoOutput) {
        // Count lines that contain node information (not including headers)
        $lines = explode("\n", trim($nodeInfoOutput));
        // Filter out empty lines and header lines
        $nodeLines = array_filter($lines, function($line) {
            return !empty(trim($line)) && !preg_match('/^(Node|Address|---)/i', trim($line));
        });
        $activeMasternodes = count($nodeLines);
    }
    
    // Get chain info for block height
    $chainInfoCommand = '/opt/cellframe-node/bin/cellframe-node-cli chain list -net Backbone 2>/dev/null';
    $chainInfoOutput = shell_exec($chainInfoCommand);
    
    $blockHeight = [
        'zerochain' => 0,
        'main' => 0
    ];
    
    if ($chainInfoOutput) {
        // Parse chain info to extract block heights
        $lines = explode("\n", trim($chainInfoOutput));
        foreach ($lines as $line) {
            if (preg_match('/Chain.*0x0.*blocks:\s*(\d+)/i', $line, $matches)) {
                $blockHeight['zerochain'] = (int)$matches[1];
            } elseif (preg_match('/Chain.*0x1.*blocks:\s*(\d+)/i', $line, $matches)) {
                $blockHeight['main'] = (int)$matches[1];
            }
        }
    }
    
    // Determine network status
    $networkSynced = ($blockHeight['zerochain'] > 0 || $blockHeight['main'] > 0) && $activeMasternodes > 0;
    
    // Return JSON response
    echo json_encode([
        'success' => true,
        'active_masternodes' => $activeMasternodes,
        'block_height' => $blockHeight,
        'network_synced' => $networkSynced,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    // Return error response
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'active_masternodes' => 0,
        'block_height' => ['zerochain' => 0, 'main' => 0],
        'network_synced' => false,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}
?>