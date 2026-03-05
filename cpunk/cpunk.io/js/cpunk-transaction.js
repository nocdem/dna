/**
 * CPUNK Transaction - Minimal version
 */

// Global session ID
let cpunkSessionId = null;

// Set session ID
function setTransactionSessionId(id) {
    cpunkSessionId = id;
}

// Get session ID
function getTransactionSessionId() {
    return cpunkSessionId;
}