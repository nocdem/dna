/**
 * CPUNK Community Board
 * A public board where users can post messages
 */

// Configuration
const POSTS_PER_PAGE = 100;  // Show last 100 posts on the wall
const MAX_POST_LENGTH = 500;
const BOARD_DATA_FILE = 'board_posts.txt';
const DNA_PROXY_URL = 'dna-proxy.php';

// State
let currentWallet = null;
let currentDNA = null;
let posts = [];
let currentPage = 1;
let isLoading = false;
let dnaCache = {}; // Cache DNA lookups to reduce API calls

// DOM Elements (initialized in DOMContentLoaded)
let loginRequiredSection;
let loginBtn;
let postSection;
let postContent;
let postButton;
let charCount;
let postsContainer;
let loadMoreButton;
let loadMoreSection;
let refreshInterval;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize DOM elements
    loginRequiredSection = document.getElementById('loginRequiredSection');
    loginBtn = document.getElementById('loginBtn');
    postSection = document.getElementById('postSection');
    postContent = document.getElementById('postContent');
    postButton = document.getElementById('postButton');
    charCount = document.getElementById('charCount');
    postsContainer = document.getElementById('postsContainer');
    loadMoreButton = document.getElementById('loadMoreButton');
    loadMoreSection = document.getElementById('loadMoreSection');

    // Initialize utilities
    if (typeof CpunkUtils !== 'undefined') {
        CpunkUtils.init();
    }

    // Initialize SSO
    const sso = CpunkSSO.getInstance();
    sso.init({
        onAuthenticated: (user) => {
            console.log('Board: User authenticated', user.dna);
            currentWallet = user.wallet;
            currentDNA = user.dna;
            
            // Show post section
            loginRequiredSection.style.display = 'none';
            postSection.style.display = 'block';
            
            // Cache DNA
            if (currentWallet) {
                dnaCache[currentWallet] = currentDNA;
            }
        },
        onUnauthenticated: () => {
            console.log('Board: User not authenticated');
            // Show login required
            loginRequiredSection.style.display = 'block';
            postSection.style.display = 'none';
        },
        updateNavbar: true
    });

    // Set up login button
    if (loginBtn) {
        loginBtn.addEventListener('click', function() {
            window.location.href = 'login.html?redirect=board.html';
        });
    }

    // Event listeners
    if (postContent) postContent.addEventListener('input', handlePostInput);
    if (postButton) postButton.addEventListener('click', handlePost);
    if (loadMoreButton) loadMoreButton.addEventListener('click', loadMorePosts);

    // Load posts on page load
    loadPosts();
    
    // Set up auto-refresh every 15 seconds
    refreshInterval = setInterval(refreshPosts, 15000);
});

// Handle post input
function handlePostInput() {
    const length = postContent.value.length;
    charCount.textContent = length;
    
    if (length > MAX_POST_LENGTH * 0.9) {
        charCount.style.color = 'var(--error-color)';
    } else {
        charCount.style.color = 'var(--text-secondary)';
    }
    
    postButton.disabled = length === 0 || length > MAX_POST_LENGTH || !currentWallet;
}

// Handle post submission
async function handlePost() {
    if (!currentWallet || !postContent.value.trim()) return;
    
    try {
        postButton.disabled = true;
        postButton.textContent = 'Posting...';
        
        // Use current DNA from SSO
        const dnaName = currentDNA;
        
        const post = {
            id: Date.now().toString(),
            author: currentWallet,
            authorName: dnaName || 'Anonymous',
            content: postContent.value.trim(),
            timestamp: new Date().toISOString(),
            likes: 0,
            replies: 0,
            hasDNA: !!dnaName
        };
        
        // Save post (in production, this would be an API call)
        await savePost(post);
        
        // Clear input
        postContent.value = '';
        charCount.textContent = '0';
        
        // Refresh posts
        await refreshPosts();
        
        // Show success message
        console.log('Post published successfully!');
        
    } catch (error) {
        console.error('Error posting:', error);
        alert('Failed to publish post');
    } finally {
        postButton.disabled = false;
        postButton.textContent = 'Post';
    }
}

// Save post to storage
async function savePost(post) {
    try {
        // TODO: When backend access is available, implement proper GDB storage
        // Options:
        // 1. Create a dedicated board API endpoint that doesn't require DNA lookup
        // 2. Use a special DNA account for "wall" posts
        // 3. Store in a separate database table for public posts
        
        // TEMPORARY: Using localStorage until backend solution is implemented
        const savedPosts = JSON.parse(localStorage.getItem('cpunk_board_posts') || '[]');
        savedPosts.unshift(post);
        
        // Keep only last 100 posts in localStorage
        if (savedPosts.length > 100) {
            savedPosts.length = 100;
        }
        
        localStorage.setItem('cpunk_board_posts', JSON.stringify(savedPosts));
        
        console.log('Post saved successfully');
        
    } catch (error) {
        console.error('Error saving post:', error);
        throw error;
    }
}

// Load posts
async function loadPosts() {
    if (isLoading) return;
    
    try {
        isLoading = true;
        postsContainer.innerHTML = '<div class="loading-message">Loading community posts...</div>';
        
        // TODO: When backend access is available, load from GDB/database
        // Will need to implement one of the solutions mentioned in savePost
        
        // TEMPORARY: Loading from localStorage
        const savedPosts = JSON.parse(localStorage.getItem('cpunk_board_posts') || '[]');
        posts = savedPosts;
        
        displayPosts();
        
    } catch (error) {
        console.error('Error loading posts:', error);
        postsContainer.innerHTML = '<div class="error-message">Failed to load posts</div>';
    } finally {
        isLoading = false;
    }
}

// Display posts
async function displayPosts() {
    if (posts.length === 0) {
        postsContainer.innerHTML = '<div class="empty-message">No posts yet. Be the first to share!</div>';
        loadMoreSection.style.display = 'none';
        return;
    }
    
    postsContainer.innerHTML = '';
    const endIndex = currentPage * POSTS_PER_PAGE;
    const postsToShow = posts.slice(0, endIndex);
    
    // Resolve DNA names for posts that don't have them
    const unresolvedAddresses = postsToShow
        .filter(post => !post.hasDNA && !dnaCache[post.author])
        .map(post => post.author);
    
    // Batch resolve DNA names
    if (unresolvedAddresses.length > 0) {
        await Promise.all(unresolvedAddresses.map(addr => resolveDNA(addr)));
    }
    
    postsToShow.forEach(post => {
        const postElement = createPostElement(post);
        postsContainer.appendChild(postElement);
    });
    
    // Show/hide load more button
    if (posts.length > endIndex) {
        loadMoreSection.style.display = 'block';
    } else {
        loadMoreSection.style.display = 'none';
    }
}

// Create post element
function createPostElement(post) {
    const postDiv = document.createElement('div');
    postDiv.className = 'post-item';
    postDiv.dataset.postId = post.id;
    
    const timeAgo = getTimeAgo(new Date(post.timestamp));
    
    // Use DNA name if available in cache, otherwise use post's authorName
    const displayName = dnaCache[post.author] || post.authorName;
    const avatar = displayName.charAt(0).toUpperCase();
    const isDNA = !!dnaCache[post.author] || post.hasDNA;
    
    postDiv.innerHTML = `
        <div class="post-header">
            <div class="post-author">
                <div class="author-avatar${isDNA ? ' dna-verified' : ''}">${avatar}</div>
                <div class="author-info">
                    <div class="author-name">${displayName}${isDNA ? ' <span class="dna-badge">🧬</span>' : ''}</div>
                    <div class="author-wallet">${post.author.substring(0, 10)}...${post.author.substring(post.author.length - 8)}</div>
                </div>
            </div>
            <div class="post-time">${timeAgo}</div>
        </div>
        <div class="post-content">${escapeHtml(post.content)}</div>
        <div class="post-actions">
            <div class="post-action" onclick="likePost('${post.id}')">
                <span class="action-icon">👍</span>
                <span class="action-count">${post.likes || 0}</span>
            </div>
            <div class="post-action" onclick="replyToPost('${post.id}')">
                <span class="action-icon">💬</span>
                <span class="action-count">${post.replies || 0}</span>
            </div>
        </div>
    `;
    
    return postDiv;
}

// Refresh posts
async function refreshPosts() {
    // Don't refresh if user is typing
    if (postContent && postContent.value.trim().length > 0) {
        return;
    }
    
    currentPage = 1;
    await loadPosts();
}

// Load more posts
function loadMorePosts() {
    currentPage++;
    displayPosts();
}

// Like post (placeholder function)
function likePost(postId) {
    // In production, this would update the like count via API
    const postElement = document.querySelector(`[data-post-id="${postId}"]`);
    if (postElement) {
        const likeAction = postElement.querySelector('.post-action');
        likeAction.classList.toggle('liked');
    }
    CpunkUI.showToast('Like feature coming soon!', 'info');
}

// Reply to post (placeholder function)
function replyToPost(postId) {
    CpunkUI.showToast('Reply feature coming soon!', 'info');
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + 'd ago';
    
    return date.toLocaleDateString();
}

function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
        setTimeout(() => {
            errorElement.style.display = 'none';
        }, 5000);
    }
}

// Resolve DNA name from wallet address
async function resolveDNA(walletAddress) {
    // Check cache first
    if (dnaCache[walletAddress]) {
        return dnaCache[walletAddress];
    }
    
    try {
        const response = await fetch(`${DNA_PROXY_URL}?lookup=${encodeURIComponent(walletAddress)}`);
        const data = await response.json();
        
        if (data.status_code === 0 && data.response_data) {
            // Check if this is a wallet lookup result with DNA names
            if (data.response_data.names && data.response_data.names.length > 0) {
                // Use the first DNA name
                const dnaName = data.response_data.names[0];
                dnaCache[walletAddress] = dnaName;
                return dnaName;
            }
        }
    } catch (error) {
        console.error('Error resolving DNA:', error);
    }
    
    return null;
}

// Clean up interval on page unload
window.addEventListener('beforeunload', function() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});
