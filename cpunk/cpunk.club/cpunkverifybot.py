import logging
import json
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Constants
API_URL = "https://api.dna.cpunk.club"
API_UPDATE_URL = "https://api.dna.cpunk.club"  # For verification updates
import json

# Load config from deployer's home
with open('/home/deployer/config/oauth_config.json', 'r') as f:
    config = json.load(f)
    TELEGRAM_BOT_TOKEN = config['telegram']['bot_token']

# Track ongoing verification attempts
verification_attempts = {}  # username -> dna_nickname

# Universal handler that works for both messages and channel posts
async def universal_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle all updates and check for 'whoami?' text or verification attempts"""
    logger.info(f"Received update ID: {update.update_id}")
    
    # Determine if this is a channel post or a message
    if update.channel_post:
        message_obj = update.channel_post
        logger.info(f"Channel post detected: {message_obj.chat.title if message_obj.chat else 'Unknown channel'}")
    elif update.message:
        message_obj = update.message
        logger.info(f"Direct message detected")
    else:
        logger.info("Not a message or channel post - ignoring")
        return
    
    # Check if there's text to process
    if not message_obj.text:
        logger.info("No text in message - ignoring")
        return
    
    message_text = message_obj.text.strip()
    username = message_obj.from_user.username if message_obj.from_user else None
    
    # Log the message content (without logging full text for privacy)
    logger.info(f"Message from @{username}: {message_text[:10]}...")
    
    # Check for "whoami?" query
    if message_text.lower() == "whoami?":
        logger.info("Processing 'whoami?' request")
        await process_whoami(message_obj)
    # Check if this is a verification attempt (any message not starting with /)
    elif username and not message_text.startswith("/") and not is_command(message_text):
        logger.info(f"Possible verification attempt from @{username}")
        await process_verification_attempt(message_obj, message_text)

def is_command(text):
    """Check if text looks like a bot command"""
    return text.startswith('/') and len(text) > 1 and text[1].isalpha()

async def process_whoami(message_obj):
    """Process a whoami request from any source"""
    # Get username if available
    username = message_obj.from_user.username if message_obj.from_user else None
    logger.info(f"Username: {username or 'Not available'}")
    
    # If no username available
    if not username:
        await message_obj.reply_text(
            "I couldn't identify your Telegram username. Please ensure you have a username set in Telegram settings."
        )
        return
    
    # Query the API
    try:
        logger.info(f"Querying DNA API for @{username}")
        api_endpoint = f"{API_URL}/?by_telegram={username}"
        response = requests.get(api_endpoint)
        data = response.json()
        
        logger.info(f"API response: {data.get('status_code', 'No status code')}")
        
        # Process response
        if data.get("status_code") == 0 and data.get("response_data"):
            response_data = data["response_data"]
            registered_names = response_data.get("registered_names", {})
            names_list = list(registered_names.keys())
            
            if names_list:
                primary_name = names_list[0]
                other_names = names_list[1:] if len(names_list) > 1 else []
                
                message = f"🔍 <b>Identity Check for @{username}</b>\n\n"
                message += f"✅ <b>Primary DNA:</b> {primary_name}\n"
                
                if other_names:
                    message += f"🏷️ <b>Other DNAs:</b> {', '.join(other_names)}\n"
                
                # Add wallet addresses if available
                wallet_addresses = response_data.get("wallet_addresses", {})
                if wallet_addresses:
                    message += "\n<b>📱 Cellframe Wallet Addresses:</b>\n"
                    for network, address in wallet_addresses.items():
                        # Format address to show only beginning and end
                        short_address = f"{address[:8]}...{address[-8:]}"
                        message += f"• {network}: <code>{short_address}</code>\n"
                
                # Add external wallet info if available
                dino_wallets = response_data.get("dinosaur_wallets", {})
                has_dino_wallets = any(dino_wallets.get(key) for key in dino_wallets)
                if has_dino_wallets:
                    message += "\n<b>🔗 External Blockchain Wallets:</b>\n"
                    for chain, address in dino_wallets.items():
                        if address:
                            # Format address to show only beginning and end
                            short_address = f"{address[:8]}...{address[-8:]}"
                            message += f"• {chain}: <code>{short_address}</code>\n"
                
                # Add profile link
                message += f"\n🌐 <a href='https://cpunk.club/{primary_name}'>View Full Profile</a>"
                
                await message_obj.reply_html(message, disable_web_page_preview=True)
                logger.info(f"Successfully replied with DNA info for @{username}")
            else:
                await message_obj.reply_text(f"@{username} has no DNA nicknames registered.")
                logger.info(f"No nicknames found for @{username}")
        else:
            error_msg = data.get("error", "No DNA registration found")
            await message_obj.reply_text(f"@{username}: {error_msg}")
            logger.warning(f"No DNA registration found for @{username}")
            
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        await message_obj.reply_text("Error connecting to the DNA service. Please try again later.")

async def process_verification_attempt(message_obj, dna_nickname):
    """Process a verification attempt where user sends their DNA nickname"""
    username = message_obj.from_user.username
    if not username:
        await message_obj.reply_text("I couldn't identify your Telegram username. Please ensure you have a username set in Telegram settings.")
        return
    
    logger.info(f"Verifying @{username} with nickname '{dna_nickname}'")
    
    try:
        # First check if the provided DNA nickname exists
        api_endpoint = f"{API_URL}/?lookup={dna_nickname}"
        response = requests.get(api_endpoint)
        data = response.json()
        
        # Check if nickname exists
        if not data or data.get("status_code") != 0 or not data.get("response_data"):
            await message_obj.reply_text(f"❌ Error: DNA nickname '{dna_nickname}' was not found in our system. Please check the spelling and try again.")
            logger.warning(f"Verification failed - DNA nickname '{dna_nickname}' not found")
            return
        
        # Check if this Telegram username is pending verification for this nickname
        response_data = data.get("response_data", {})
        socials = response_data.get("socials", {})
        telegram_data = socials.get("telegram", {})
        telegram_handle = telegram_data.get("profile", "")
        
        # Check if the Telegram handle matches this username with -unverified suffix
        expected_unverified = f"{username}-unverified"
        
        if telegram_handle.lower() == expected_unverified.lower():
            # This is a valid verification attempt
            logger.info(f"Valid verification match: @{username} for DNA '{dna_nickname}'")
            
            # Update the verification status by removing the -unverified suffix
            updated = await update_verification_status(username, dna_nickname)
            
            if updated:
                # Verification successful
                await message_obj.reply_html(
                    f"✅ <b>Verification successful!</b>\n\n"
                    f"Your Telegram account @{username} has been verified for DNA nickname <b>{dna_nickname}</b>.\n\n"
                    f"You can now use all CPUNK features that require verified Telegram integration."
                )
                logger.info(f"Verification successful for @{username} with DNA '{dna_nickname}'")
            else:
                # Verification failed during update
                await message_obj.reply_text(
                    f"⚠️ Verification process started but could not be completed. Please try again later or contact support."
                )
                logger.error(f"Verification update failed for @{username} with DNA '{dna_nickname}'")
        else:
            # Not pending verification or wrong username
            if not telegram_handle:
                await message_obj.reply_text(
                    f"❌ The DNA nickname '{dna_nickname}' doesn't have a Telegram account pending verification.\n\n"
                    f"Please go to the CPUNK website, enter your Telegram username, and initiate verification first."
                )
            elif not telegram_handle.endswith("-unverified"):
                await message_obj.reply_text(
                    f"❌ The Telegram account for DNA nickname '{dna_nickname}' is already verified as @{telegram_handle}."
                )
            else:
                # There is a pending verification but for another Telegram username
                pending_user = telegram_handle.replace("-unverified", "")
                await message_obj.reply_text(
                    f"❌ The DNA nickname '{dna_nickname}' is pending verification for a different Telegram account (@{pending_user}).\n\n"
                    f"If this is your DNA, please go to the CPUNK website and update your Telegram username."
                )
    
    except Exception as e:
        logger.error(f"Error processing verification: {e}")
        await message_obj.reply_text("Error processing verification. Please try again later.")

async def update_verification_status(username, dna_nickname):
    """Update the verification status in the DNA system"""
    try:
        logger.info(f"Updating verification status for @{username} with DNA '{dna_nickname}'")
        
        # Prepare the update data - using the API format matching the dna-proxy.php
        update_data = {
            "action": "update",
            "name": dna_nickname,
            "socials": {
                "telegram": {
                    "profile": username
                }
            }
        }
        
        # Make the API call to update
        headers = {'Content-Type': 'application/json'}
        response = requests.post(API_UPDATE_URL, json=update_data, headers=headers)
        
        # Check result
        if response.status_code == 200:
            result = response.json()
            if result.get("success") or result.get("status") == "ok" or result.get("status_code") == 0:
                logger.info(f"Successfully updated verification for @{username} with DNA '{dna_nickname}'")
                return True
            else:
                logger.error(f"API returned error: {result}")
                return False
        else:
            logger.error(f"API request failed with status {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error updating verification status: {e}")
        return False

# Command handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    await update.message.reply_text(
        'Welcome to the CPUNK DNA Verification Bot! 🚀\n\n'
        'This bot helps you verify your Telegram account with your CPUNK DNA identity.\n\n'
        'Available commands:\n'
        '• Send "whoami?" to check your DNA registration\n'
        '• To verify your account, start the verification on the CPUNK website, then send your DNA nickname here\n\n'
        'Need help? Visit https://cpunk.club/support'
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    await update.message.reply_text(
        '🔍 <b>CPUNK DNA Verification Bot Help</b>\n\n'
        '<b>Available Commands:</b>\n'
        '• Type "whoami?" to check your DNA registration\n'
        '• Send your DNA nickname to verify your account\n\n'
        '<b>Verification Process:</b>\n'
        '1. Go to the CPUNK website and enter your Telegram username\n'
        '2. Click "Verify" and note your DNA nickname\n'
        '3. Send your DNA nickname to this bot\n'
        '4. Wait for confirmation\n\n'
        'For more information, visit our website at https://cpunk.club',
        parse_mode='HTML'
    )

async def whoami_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /whoami command"""
    # Determine if this is a channel post or direct message
    if update.channel_post:
        await process_whoami(update.channel_post)
    elif update.message:
        await process_whoami(update.message)

async def verify_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /verify command with instructions"""
    await update.message.reply_html(
        '<b>CPUNK DNA Verification Process</b>\n\n'
        'To verify your Telegram account with your CPUNK DNA:\n\n'
        '1. Go to https://cpunk.club/user_settings.html\n'
        '2. Enter your Telegram username (without @)\n'
        '3. Click "Verify" and note your DNA nickname\n'
        '4. Send your DNA nickname to this bot\n\n'
        'Example: If your DNA nickname is "crypto_fan", just send "crypto_fan" as a message'
    )

def main() -> None:
    """Start the bot."""
    # Create the Application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("whoami", whoami_command))
    application.add_handler(CommandHandler("verify", verify_command))
    
    # Use a single universal handler with ALL filter to catch both messages and channel posts
    application.add_handler(MessageHandler(filters.ALL, universal_handler))

    # Run the bot with explicit update types
    logger.info("Starting bot...")
    application.run_polling(allowed_updates=["message", "channel_post"])

if __name__ == "__main__":
    main()
