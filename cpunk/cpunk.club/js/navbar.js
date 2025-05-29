/**
 * CPUNK Mobile Menu Handler
 * Handles mobile menu toggling and dropdown functionality
 */

// Load and setup navbar
document.addEventListener('DOMContentLoaded', function() {
    // Load navbar template with AJAX
    fetch('/navbar-template.html')
        .then(response => response.text())
        .then(html => {
            // Insert the navbar before the container
            const navbarPlaceholder = document.querySelector('.navbar-placeholder');
            if (navbarPlaceholder) {
                navbarPlaceholder.innerHTML = html;
                
                // Determine current page and set active state
                setActivePage();
                
                // Setup mobile menu functionality
                setupMobileMenu();
                
                // Setup language switcher
                setupLanguageSwitcher();
                
                // Update navbar with SSO state if SSO is loaded
                if (typeof CpunkSSO !== 'undefined') {
                    const sso = CpunkSSO.getInstance();
                    // Initialize SSO if not already initialized
                    if (!sso.initialized) {
                        sso.init({
                            updateNavbar: false // We'll update manually after
                        });
                    }
                    // Now update navbar
                    sso.updateNavbar();
                }
            }
        })
        .catch(error => {
            console.error('Error loading navbar template:', error);
        });
});

// Set active page in navbar
function setActivePage() {
    // Get current page filename
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    
    // Find and set active link
    const navLinks = document.querySelectorAll('.navbar-nav a');
    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPage) {
            link.classList.add('active');
        }
    });
}

// Setup mobile menu functionality
function setupMobileMenu() {
    const menuToggle = document.getElementById('menuToggle');
    const navbarMenu = document.getElementById('navbarMenu');
    const menuOverlay = document.getElementById('menuOverlay');
    const dropdowns = document.querySelectorAll('.dropdown');
    
    // Toggle mobile menu when hamburger is clicked
    if (menuToggle) {
        menuToggle.addEventListener('click', function() {
            menuToggle.classList.toggle('active');
            navbarMenu.classList.toggle('active');
            menuOverlay.classList.toggle('active');
            
            // Prevent scrolling on body when menu is open
            if (navbarMenu.classList.contains('active')) {
                document.body.style.overflow = 'hidden';
            } else {
                document.body.style.overflow = '';
            }
        });
    }
    
    // Close menu when overlay is clicked
    if (menuOverlay) {
        menuOverlay.addEventListener('click', function() {
            menuToggle.classList.remove('active');
            navbarMenu.classList.remove('active');
            menuOverlay.classList.remove('active');
            document.body.style.overflow = '';
            
            // Close all dropdowns
            dropdowns.forEach(dropdown => {
                dropdown.classList.remove('active');
            });
        });
    }
    
    // Handle dropdown toggles on mobile
    dropdowns.forEach(dropdown => {
        const toggle = dropdown.querySelector('.dropdown-toggle');
        
        if (toggle) {
            toggle.addEventListener('click', function(e) {
                // Only for mobile view
                if (window.innerWidth <= 768) {
                    e.preventDefault();
                    
                    // Close other dropdowns
                    dropdowns.forEach(other => {
                        if (other !== dropdown) {
                            other.classList.remove('active');
                        }
                    });
                    
                    // Toggle this dropdown
                    dropdown.classList.toggle('active');
                }
            });
        }
    });
    
    // Close menu when clicking a link
    const menuLinks = document.querySelectorAll('.navbar-nav a:not(.dropdown-toggle)');
    menuLinks.forEach(link => {
        link.addEventListener('click', function() {
            if (window.innerWidth <= 768) {
                menuToggle.classList.remove('active');
                navbarMenu.classList.remove('active');
                menuOverlay.classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    });
    
    // Reset mobile menu on window resize
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768) {
            menuToggle.classList.remove('active');
            navbarMenu.classList.remove('active');
            menuOverlay.classList.remove('active');
            document.body.style.overflow = '';
            
            // Reset all dropdowns
            dropdowns.forEach(dropdown => {
                dropdown.classList.remove('active');
            });
        }
    });
}

// Setup language switcher functionality
function setupLanguageSwitcher() {
    const languageLinks = document.querySelectorAll('[data-lang]');
    const langText = document.querySelector('.lang-text');
    
    languageLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const selectedLang = this.getAttribute('data-lang');
            
            console.log('Language clicked:', selectedLang);
            
            // Update the display text
            if (langText) {
                langText.textContent = selectedLang.toUpperCase();
            }
            
            // Change language using the translation system
            if (window.i18n) {
                console.log('Translation system found, changing language to:', selectedLang);
                window.i18n.setLanguage(selectedLang);
            } else {
                console.log('Translation system not found, waiting...');
                // Wait for translation system to load
                setTimeout(() => {
                    if (window.i18n) {
                        console.log('Translation system loaded, changing language to:', selectedLang);
                        window.i18n.setLanguage(selectedLang);
                    } else {
                        console.log('Translation system still not available');
                    }
                }, 500);
            }
            
            // Close dropdown on mobile
            if (window.innerWidth <= 768) {
                const dropdown = this.closest('.dropdown');
                if (dropdown) {
                    dropdown.classList.remove('active');
                }
            }
        });
    });
    
    // Set initial language text based on current language
    if (langText && window.i18n && window.i18n.currentLanguage) {
        langText.textContent = window.i18n.currentLanguage.toUpperCase();
    }
}