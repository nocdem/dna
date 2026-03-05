<?php
/**
 * Generic Profile Handler for CPUNK DNA Profiles
 * Handles URLs like cpunk.io/bios, cpunk.io/CC_CC, etc.
 */

// Get the requested path
$requestUri = $_SERVER['REQUEST_URI'];
$path = parse_url($requestUri, PHP_URL_PATH);
$pathSegments = array_filter(explode('/', $path));

// Get the last segment as the username
$username = end($pathSegments);

// Validate username
if (!$username || !preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
    http_response_code(404);
    header('Location: /');
    exit;
}

// Read the profile template
ob_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CPUNK - <?php echo htmlspecialchars($username); ?> Profile</title>
    <meta name="description" content="CPUNK DNA Identity Profile for <?php echo htmlspecialchars($username); ?> - View bio, social links, and identity information on the post-quantum identity protocol.">
    <link rel="canonical" href="https://cpunk.io/<?php echo urlencode($username); ?>">
    
    <!-- Open Graph -->
    <meta property="og:type" content="profile">
    <meta property="og:url" content="https://cpunk.io/<?php echo urlencode($username); ?>">
    <meta property="og:title" content="CPUNK - <?php echo htmlspecialchars($username); ?> DNA Profile">
    <meta property="og:description" content="View <?php echo htmlspecialchars($username); ?> DNA identity profile on CPUNK's post-quantum blockchain protocol.">
    <meta property="og:image" content="https://cpunk.io/images/cpunk-logo.png">
    
    <!-- Security Headers -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com https://cpunk.club;">
    <meta http-equiv="X-Frame-Options" content="SAMEORIGIN">
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="stylesheet" href="/styles.css">
    
    <style>
        /* Same styles as profile.html */
        .profile-container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 2rem;
            margin-top: 100px;
        }
        
        .profile-loading {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }
        
        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border-primary);
            border-top: 3px solid var(--accent-primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Copy all the lookup-style CSS from dna-lookup.html */
        .profile-header {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            margin-bottom: 2rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 2rem;
        }
        
        .avatar {
            width: 80px;
            height: 80px;
            background: var(--accent-primary);
            color: var(--bg-primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            font-weight: 900;
            font-family: 'Orbitron', monospace;
        }
        
        .profile-info {
            flex: 1;
        }
        
        .profile-nickname {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
            font-family: 'Orbitron', monospace;
        }
        
        .profile-id {
            color: var(--text-secondary);
            font-size: 1rem;
        }
        
        /* All other styles from the lookup page */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        
        .info-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .info-item:hover {
            border-color: var(--accent-primary);
            box-shadow: 0 8px 32px var(--accent-glow);
            transform: translateY(-5px);
        }
        
        .info-item h3 {
            color: var(--accent-primary);
            margin-bottom: 1rem;
            font-size: 1rem;
        }
        
        .stat-value {
            font-size: 2rem;
            color: var(--text-primary);
            font-weight: 900;
            font-family: 'Orbitron', monospace;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="logo">CPUNK.IO</a>
            <ul class="nav-menu">
                <li class="nav-item"><a href="/" class="nav-link">Home</a></li>
                <li class="nav-item"><a href="/about.html" class="nav-link">About</a></li>
                <li class="nav-item"><a href="/team.html" class="nav-link">Team</a></li>
                <li class="nav-item dropdown">
                    <a href="#" class="nav-link">Services ▼</a>
                    <div class="dropdown-content">
                        <a href="/services/dna.html">DNA Identity</a>
                    </div>
                </li>
                <li class="nav-item"><a href="/whitepaper.html" class="nav-link">Whitepaper</a></li>
                <li class="nav-item"><a href="/contact.html" class="nav-link">Contact</a></li>
            </ul>
            <button class="mobile-menu-toggle">☰</button>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="main-content">
        <div class="profile-container">
            <!-- Loading State -->
            <div id="loading" class="profile-loading">
                <div class="loading-spinner"></div>
                <p>Loading DNA profile for <?php echo htmlspecialchars($username); ?>...</p>
            </div>

            <!-- Profile Content -->
            <div id="result" style="display: none;">
                <!-- Profile content will be populated here by JavaScript -->
            </div>
        </div>
    </main>

    <script src="js/cpunk-utils.js"></script>
    <script src="https://cpunk.club/js/lookup.js"></script>
    <script>
        // Set the username from PHP
        const PROFILE_USERNAME = '<?php echo addslashes($username); ?>';
        
        // Override the page to load profile for specific user
        document.addEventListener('DOMContentLoaded', function() {
            // Create a fake search input with the username
            const fakeInput = document.createElement('input');
            fakeInput.id = 'searchInput';
            fakeInput.value = PROFILE_USERNAME;
            fakeInput.style.display = 'none';
            document.body.appendChild(fakeInput);
            
            // Create fake elements that lookup.js expects
            const loadingElement = document.getElementById('loading');
            const resultContainer = document.getElementById('result');
            
            // Auto-trigger the lookup
            setTimeout(() => {
                if (typeof handleSearch === 'function') {
                    handleSearch();
                }
            }, 500);
            
            // Mobile menu toggle
            const mobileToggle = document.querySelector('.mobile-menu-toggle');
            const navMenu = document.querySelector('.nav-menu');
            
            if (mobileToggle && navMenu) {
                mobileToggle.addEventListener('click', function() {
                    navMenu.classList.toggle('active');
                });
            }
        });
    </script>
</body>
</html>
<?php
$content = ob_get_clean();
echo $content;
?>