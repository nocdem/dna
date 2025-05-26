<?php
/**
 * OAuth Configuration Template for CPUNK
 * 
 * Instructions:
 * 1. Copy this file to /home/deployer/config/oauth_config.php on the production server
 * 2. Fill in the actual API credentials
 * 3. Set proper permissions: chmod 600 /home/deployer/config/oauth_config.php
 * 4. Ensure the file is readable by the web server user
 * 
 * NEVER commit the actual configuration file with real credentials to git
 */

return [
    'github' => [
        'client_id' => 'YOUR_GITHUB_CLIENT_ID',
        'client_secret' => 'YOUR_GITHUB_CLIENT_SECRET'
    ],
    'google' => [
        'client_id' => 'YOUR_GOOGLE_CLIENT_ID',
        'client_secret' => 'YOUR_GOOGLE_CLIENT_SECRET'
    ],
    'linkedin' => [
        'client_id' => 'YOUR_LINKEDIN_CLIENT_ID',
        'client_secret' => 'YOUR_LINKEDIN_CLIENT_SECRET'
    ],
    'twitter' => [
        'client_id' => 'YOUR_TWITTER_OAUTH2_CLIENT_ID',
        'client_secret' => 'YOUR_TWITTER_OAUTH2_CLIENT_SECRET'
    ],
    'telegram' => [
        'bot_token' => 'YOUR_TELEGRAM_BOT_TOKEN'
    ]
];
?>