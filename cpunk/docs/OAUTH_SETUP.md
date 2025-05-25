# OAuth Setup Guide

This guide explains how to set up OAuth authentication for the CPUNK platform.

## Prerequisites

1. Create a configuration file at `/home/deployer/config/oauth_config.php`
2. Set appropriate permissions (readable by web server, not publicly accessible)

## Configuration File Structure

Create `/home/deployer/config/oauth_config.php`:

```php
<?php
return [
    'github' => [
        'client_id' => 'your_github_client_id',
        'client_secret' => 'your_github_client_secret'
    ],
    'google' => [
        'client_id' => 'your_google_client_id',
        'client_secret' => 'your_google_client_secret'
    ],
    'linkedin' => [
        'client_id' => 'your_linkedin_client_id',
        'client_secret' => 'your_linkedin_client_secret'
    ],
    'twitter' => [
        'client_id' => 'your_twitter_oauth2_client_id',
        'client_secret' => 'your_twitter_oauth2_client_secret'
    ],
    'telegram' => [
        'bot_token' => 'your_telegram_bot_token'
    ]
];
?>
```

## OAuth Provider Setup

### GitHub
1. Go to https://github.com/settings/developers
2. Create new OAuth App
3. Set Authorization callback URL: `https://yourdomain.com/github_oauth.php`
4. Copy Client ID and Client Secret

### Google
1. Go to https://console.cloud.google.com/
2. Create or select project
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `https://yourdomain.com/google_oauth.php`
6. Copy Client ID and Client Secret

### LinkedIn
1. Go to https://www.linkedin.com/developers/apps
2. Create new app
3. Add redirect URL: `https://yourdomain.com/linkedin_oauth.php`
4. Copy Client ID and Client Secret

### Twitter (OAuth 2.0)
1. Go to https://developer.twitter.com/en/portal/dashboard
2. Create or select app
3. Set up User authentication settings
4. Enable OAuth 2.0
5. Add callback URL: `https://yourdomain.com/twitter_oauth.php`
6. Copy Client ID and Client Secret

### Telegram Bot
1. Message @BotFather on Telegram
2. Create new bot with `/newbot`
3. Copy the bot token
4. Also create `/home/deployer/config/oauth_config.json` for Python bot:
```json
{
    "telegram": {
        "bot_token": "your_telegram_bot_token"
    }
}
```

## Security Best Practices

1. **Never commit credentials** to version control
2. **Restrict file permissions**: 
   ```bash
   chmod 600 /home/deployer/config/oauth_config.php
   chown deployer:www-data /home/deployer/config/oauth_config.php
   ```
3. **Use HTTPS** for all OAuth callbacks
4. **Regenerate tokens** if they are ever exposed
5. **Monitor OAuth logs** for suspicious activity

## Testing

After setup, test each OAuth provider:
1. Navigate to your platform
2. Click on each social login button
3. Verify successful authentication
4. Check logs for any errors

## Troubleshooting

Common issues:
- **Redirect URI mismatch**: Ensure callback URLs match exactly
- **Token errors**: Check file permissions and paths
- **SSL errors**: Ensure valid HTTPS certificate
- **Session errors**: Check PHP session configuration