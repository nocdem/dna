# Changelog

All notable changes to CPUNK platform will be documented in this file.

## [0.1.14] - 2025-05-31

### Added
- **New primary mission item for quantum apocalypse awareness** - Added first mission item emphasizing CPUNK's role in quantum resistance education
- **Mission subtitle for quantum era messaging** - Added supporting subtitle about tools and education for the quantum era
- **Complete multilingual translations** for new mission content in all 5 languages:
  - English: "Lead the charge in raising awareness about the looming 'quantum apocalypse' and the urgent need for quantum-resistant blockchain technology"
  - Spanish: Professional cryptocurrency translations with quantum terminology
  - Italian: Accurate blockchain terminology with quantum resistance messaging
  - Russian: Technical translations maintaining quantum safety emphasis
  - Turkish: Native quantum technology awareness messaging
- **Updated about.html structure** - Added new mission item (missionItem0) with 🌐 emoji and subtitle with proper data-i18n attributes
- **Enhanced CSS styling** - Added mission-subtitle class with accent color styling and proper spacing
- **Renumbered existing mission items** - Updated missionItem1-3 to maintain consistency while adding the new primary mission

### Updated
- All language files (en.json, es.json, it.json, ru.json, tr.json) with new translation keys missionItem0 and missionSubtitle
- About page HTML structure to include quantum apocalypse awareness as the primary mission focus
- CSS styling for mission subtitle with accent color and proper formatting

## [0.1.13] - 2025-05-31

### Added
- **Complete multilingual support for network statistics page** - Comprehensive refactor with translations in all 5 languages (en, es, it, ru, tr)
- **New networkStats translation section** - Added extensive translation keys for all network statistics content:
  - Page title, meta descriptions, and SEO content
  - Token metrics section with all data labels (price, market cap, volume, etc.)
  - Network health section with node status indicators
  - Treasury status section with balance and update information
  - Delegation statistics section with staking metrics
  - Top holders section with loading states and DNA information
  - Circulation statistics section with address and token data
  - Network resources section with link descriptions
  - Community growth section with social media metrics
  - Footer section with refresh notes and copyright
  - Loading states for all dynamic content types
- **Data-i18n attributes for all static content** - Added internationalization attributes to all text elements in network-stats.html
- **Dynamic translation support in JavaScript** - Updated network-stats.js to use translations for:
  - All loading messages and error states
  - Dynamic content like "Coming Soon" and "Data unavailable"
  - Treasury update timestamps and status messages
  - Top holders loading states and DNA lookup messages
- **SEO multilingual support** - Added translation support for meta tags, OpenGraph, and Twitter Card content
- **Complete language coverage** with appropriate translations:
  - Spanish (es.json) - Professional cryptocurrency and technical translations
  - Italian (it.json) - Accurate blockchain terminology and interface text
  - Russian (ru.json) - Comprehensive crypto platform translations
  - Turkish (tr.json) - Complete localization for Turkish users
- **Enhanced user experience** - All network statistics content now displays in user's selected language
- **Improved loading states** - All dynamic loading messages now respect language preferences

### Technical Details
- Added networkStats translation object with 7 main sections and 40+ translation keys
- Updated HTML template with comprehensive data-i18n attribute coverage
- Enhanced JavaScript internationalization for all dynamic content generation
- Maintained fallback English text for compatibility and development

## [0.1.12] - 2025-05-31

### Added
- Complete translations for installation page (network.html) in all supported languages (en, es, it, ru, tr)
- New translation keys for installation sections including:
  - Page title and quick installation header
  - OS-specific installation commands and descriptions
  - Copy command buttons and explanations
  - Verification section with commands for all platforms
  - Manual installation section with file categories
  - All button labels and instructions
- Data-i18n attributes to all static text elements in network.html
- Improved manual installation section design with better layout
- Enhanced download button styling with consistent sizing and hover effects
- Updated copy-to-clipboard functionality to use translation keys for success/error messages
- **Detailed installation paths for manual installation** - Added specific file paths for each operating system:
  - Linux paths: `/opt/cellframe-node/etc/network/` and `/opt/cellframe-node/share/ca/`
  - Windows paths: `%PROGRAMFILES%\cellframe-node\etc\network\` and `%PROGRAMFILES%\cellframe-node\share\ca\`
  - macOS paths: `/Applications/Cellframe.app/Contents/Resources/etc/network/` and `/Applications/Cellframe.app/Contents/Resources/share/ca/`
- Installation path translations in all 5 supported languages (English, Spanish, Italian, Russian, Turkish)
- Important note section explaining the need to restart the Cellframe node service after manual installation

### Improved
- Manual installation section now features a grid layout for better organization
- Download buttons are now consistently sized and styled
- Better mobile responsiveness for download sections
- Removed deprecated "View manual installation guide" link as requested
- **Enhanced manual installation guidance** - Users now have clear, OS-specific instructions for where to place configuration and certificate files
- More descriptive installation instructions that guide users through the complete manual installation process

### Changed
- Updated network.html to use translation keys instead of hardcoded text
- Replaced static button text with translatable content
- Modified CSS for improved button styling and layout consistency
- **Updated manual installation description** to be more informative and user-friendly

## [0.1.11] - 2025-05-31

### Added
- Complete translations for mainnet_party.html page in all supported languages (en, es, it, ru, tr)
- New translation keys for mainnet party sections including:
  - Event description and features
  - Countdown labels
  - Reservation rules and instructions
  - Wallet and DNA selection
  - Invitation code system
  - Transaction processing messages
  - Confirmation details
  - Attendees list
  - Error messages
- Data-i18n attributes to all static text elements in mainnet_party.html
- Translation support for dynamically generated text in mainnet_party.js

### Updated
- All language files with comprehensive mainnet party translations
- mainnet_party.html to use translation system for all text content
- mainnet_party.js to use translation system for dynamic messages and error handling

## [0.1.10] - 2025-05-31

### Added
- Complete translations for whitepaper.html page in all supported languages (en, es, it, ru, tr)
- New translation keys for all whitepaper sections, subsections, and content
- Data-i18n attributes to all text elements in whitepaper.html

### Updated
- All language files with whitepaper translations including table of contents, sections, and token allocation data
- whitepaper.html to use translation system for all text content

## [0.1.9] - 2025-05-31

### Added
- Complete translations for about.html page in all supported languages (en, es, it, ru, tr)
- New translation keys for Council application modal and all about page sections
- Data-i18n attributes to all translatable content in about.html

### Updated
- All language files with missing about page translations
- about.html to use translation system for all text content

## [0.1.8] - 2025-05-30

### Added
- Implemented validator delegation model replacing simple staking
  - Create validator wallet with sig_dil signature
  - Create node and delegate certificates
  - Use CreateOrderValidator API instead of CreateOrderStaker
  - Execute srv_stake delegate command with order hash
- Added network parameter support to transaction verification
  - Updated cpunk-utils.js to pass network parameter
  - Updated dna-proxy.php to forward network parameter
  - Supports KelVPN and other network verification
- Improved wallet matching using DNA lookup
  - Get user's network-specific address from DNA
  - Match dashboard wallet by network address
  - Support for multi-network delegation

### Fixed
- Fixed wallet balance loading for delegation
- Fixed scientific notation formatting for small amounts (e.g., 0.00000001)
- Fixed session ID missing error in CpunkTransaction
- Removed minimum delegation amount validation during refactoring

## [0.1.7] - 2025-05-28

### Changed
- Removed Register DNA button from navbar Services dropdown
  - Users can register DNA through the login page when needed
  - Existing link shown in dashboardConnector when no DNA found

### Fixed
- Authentication loop in register.html
  - Removed sso.js from register page to prevent redirect loop
  - Register page now handles its own authentication through dashboard
- Register page now uses existing session from SSO login
  - Checks sessionStorage for existing dashboard connection
  - Automatically shows registration form if coming from SSO

## [0.1.6] - 2025-05-26

### Added
- Community Board feature (board.html)
  - Public wall where users can post messages
  - Wallet-based authentication for posting
  - Real-time post display with timestamps
  - Like and reply placeholders for future features
  - Character limit (500) for posts
  - Load more pagination system
  - DNA nickname resolution for wallet addresses
  - DNA badge (🧬) for verified DNA users
  - Green avatar border for DNA-verified posts
  - Internal SSO integration - uses existing login session
  - DNA selection flow - posts now use selected DNA nickname instead of wallet name
- Board navigation link in Social dropdown menu
- Divider styling in dropdown menus

## [0.1.5] - 2025-05-26

### Added
- Centralized authentication module (authentication.js)
  - Created reusable authentication library for admin-protected pages
  - Provides consistent authentication flow across admin and editor pages
  - Automatic admin DNA detection after wallet selection
  - Simplified authentication process - no manual DNA selection needed

### Changed
- Updated Editor page authentication
  - Now uses centralized authentication module
  - Removed DNA selection step - automatically checks for admin access
  - Updated wallets tab to show only crypto wallets (dinosaur_wallets)
  - Added "Clear All Wallets" button that preserves wallet structure
- Updated Admin page authentication
  - Migrated to use centralized authentication module
  - Consistent authentication behavior with editor page

### Fixed
- Fixed wallet clearing to preserve crypto currency structure (BTC, ETH, SOL, QEVM, BNB)
- Fixed editor authentication to match admin page behavior

## [0.1.4] - 2025-05-19

### Added
- CPUNK Improvement Proposals (CIPs) system
  - Added new proposals.html page for viewing and interacting with CIPs
  - Created draft UI for viewing proposal details with voting capability
  - Added first proposal (CIP-1: Migration to $CPUNK Parachain)
  - Added proposal filtering by status and sorting options
  - Added navigation link in the main menu under Services
  - Integrated with wallet selection for future voting functionality

### Changed
- Updated Network Stats page
  - Removed TPS metric
  - Changed Network Health section to use "Coming Soon" placeholders for future metrics

## [0.1.3] - 2025-05-18

### Changed
- Simplified DEX interface
  - Removed DNA selection step, using only wallet selection
  - Removed session ID display for cleaner UI
  - Hidden intro text when connected to dashboard
  - Removed "CPUNK Decentralized Exchange" header text (keeping BETA badge)
  - Fixed double connection issue to dashboard
  - Moved API debug display to footer for better visibility
  - Added wallet balance display directly from GetDataWallet API

### Fixed
- Fixed voting system error by correcting parameter names:
  - Changed 'wallet' to 'walletName'
  - Changed 'hash' to 'hashTx'
  - Changed 'answer' to 'optionIdx'
- Improved error reporting in voting system to show more detailed API error messages
- Fixed "Back to Proposals List" button functionality
- Added more robust error handling for voting system elements
- Added special handling for "already voted" responses to show a warning instead of an error

## [0.1.2] - 2025-05-16

### Added
- DEX (Decentralized Exchange) functionality
  - Added DEX interface for trading CPUNK tokens
  - Implemented token pair selection and rate calculation
  - Added order creation and management features
  - Added transaction history viewing
  - Included responsive design for mobile compatibility
  - Added API debug display for monitoring API requests and responses
  - Implemented DEX token pair retrieval using GetDexPairs API
  - Added automatic population of token selectors with available tokens
  - Improved wallet selection flow with proper user authentication
  - Added automatic exchange rate calculation based on token pairs
  - Implemented order confirmation modal and validation

## [0.1.1] - 2025-05-15

### Added
- SEO improvements to enhance search engine visibility
  - Added meta tags for better search indexing
  - Added Open Graph and Twitter card support for social sharing
  - Added JSON-LD structured data for rich search results
  - Created XML sitemap for improved site crawling
  - Added robots.txt file to guide search engines
  - Improved semantic HTML structure with proper HTML5 elements

## [0.1.0] - 2025-05-15

### Added
- DNA registration system
- Wallet delegation and rewards tracking
- User authentication and profile management
- Community messaging system
- Voting functionality
- Content management and distribution

### Changed
- Improved wallet selection UI to only show active wallets
- Fixed duplicate dashboard connection attempts in settings page
- Removed council_application.html and unused user_settings.html
- Added login functionality with JS module separation
- Hidden submit button after submission and simplified close instructions

### Fixed
- Duplicated dashboard connections in settings page
- Various UI/UX issues in messaging page
- Fixed profile description and image loading from API (field name mismatch)
- Fixed inconsistent wallet container sizes in settings page

### Added
- Added BNB wallet support to external wallets section
- Added Trust Wallet integration for Solana
- Added automatic wallet connection saving

## [0.1.5] - 2025-05-26

### Added
- File backup system for development safety
  - Created backup-system.sh script for automated backups before file edits
  - Maintains last 5 timestamped backups per file
  - Automatic cleanup of old backups
  - Git ignored and excluded from deployment
  - Added comprehensive documentation in doc/backup-system.md
  - Integrated backup requirements into CLAUDE.md for automated use
- Claude Code optimization and documentation
  - Updated README.md with Claude Code-specific instructions and workflow
  - Created comprehensive development-guide.md for development procedures
  - Added quick-reference.md for essential commands and patterns
  - Enhanced CLAUDE.md with quick access documentation links
  - Organized documentation for easy navigation and reference

### Changed
- Removed all console.log statements from production JavaScript files for cleaner code
  - Updated cpunk-api-console.js, proposals.js, cpublic.js, messaging.js, voting.js, and login.js
  - Console logging now only happens through the API console when enabled
- Minified all CSS files to improve page load performance
  - Reduced total CSS size by approximately 27% (saved ~60KB across 21 files)
  - All CSS files now have comments and unnecessary whitespace removed
- Improved viewport meta tags for better accessibility
  - Removed user-scalable=no from 14 HTML files to allow users to zoom
  - Standardized viewport meta tag to: width=device-width, initial-scale=1.0
- Cleaned up unused JavaScript files
  - Moved 4 unused JS files to js/unused/ folder (cpublic.js, login.js, login-loader.js, profile.js)
  - These files were not referenced by any HTML pages or other scripts
- Removed unnecessary comments and dead code from JavaScript files
  - Removed redundant structure comments in settings.js
  - Removed obsolete notes and commented code in voting.js
  - Kept all useful documentation and function comments

## 2025-05-26 20:48:14 - Add Login Page for Single Sign-On

### Added
- Created login.html with single sign-on functionality
- Created login-page.css for login page styling
- Created login.js with wallet and DNA selection
- Added login link to navbar-template.html

### Features
- Wallet selection with backbone address display
- DNA selection for selected wallet
- Remember wallet preference with local storage
- Session storage for SSO across pages
- Dashboard connection integration

## [2025-01-27] SSO Implementation

### Added
- Created unified SSO module (sso.js) for global authentication across all pages
- SSO module features:
  - Automatic session restoration from sessionStorage
  - Dynamic navbar updates showing login/logout state
  - Authentication state checking on every page
  - Support for authentication-required pages with automatic redirects
  - Unified logout functionality

### Changed
- Updated login.js to use SSO module for saving authentication sessions
- Refactored all HTML pages to include and initialize SSO:
  - index.html, about.html, register.html, lookup.html
  - delegate.html, voting.html, proposals.html
  - messaging.html, settings.html, network.html
  - network-stats.html, whitepaper.html, mainnet_party.html
  - cprofile.html
- Pages requiring authentication (messaging.html, settings.html) now automatically redirect to login

### Technical Details
- SSO stores wallet address, DNA nickname, and session ID in sessionStorage
- Navbar dynamically shows user DNA nickname when logged in
- Logout clears all session data and redirects to home page
- Login page redirects back to requested page after successful authentication

### Changed
- Navbar now only shows Login (no Settings link)
- After login, Login changes to user's DNA name
- Clicking DNA name in navbar loads settings page
- Simplified SSO navbar behavior - no dropdown, direct link to settings
