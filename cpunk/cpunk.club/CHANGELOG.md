# Changelog

All notable changes to CPUNK platform will be documented in this file.

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
