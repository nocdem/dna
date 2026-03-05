/**
 * CPUNK.IO UI Components Library
 * Reusable UI components and interactions
 * 
 * Features:
 * - Step progress indicators
 * - Wallet selection cards
 * - Transaction status displays
 * - Loading animations
 * - Notification system
 * - Modal dialogs
 * - Form components
 * - Status indicators
 * 
 * @version 1.0.0
 */

class CpunkUIComponents {
    constructor(core) {
        this.core = core;
        this.initialized = false;
        
        // Component registry
        this.components = new Map();
        this.activeComponents = new Map();
        
        // UI state
        this.modals = new Map();
        this.notifications = [];
        this.loadingStates = new Set();
        
        // Configuration
        this.config = {
            animations: {
                duration: 300,
                easing: 'ease-in-out'
            },
            notifications: {
                duration: 5000,
                maxVisible: 5
            },
            stepIndicator: {
                completedClass: 'completed',
                activeClass: 'active',
                errorClass: 'error'
            }
        };
    }

    /**
     * Initialize UI components
     * @param {Object} options - Configuration options
     */
    init(options = {}) {
        if (this.initialized) return;

        // Merge configuration
        this.config = this.core?.deepMerge(this.config, options) || { ...this.config, ...options };

        // Register default components
        this.registerDefaultComponents();

        // Setup global styles
        this.injectGlobalStyles();

        this.initialized = true;
        this.core?.log('UI Components initialized');
    }

    /**
     * Register default components
     */
    registerDefaultComponents() {
        // Register all component types
        this.registerComponent('stepIndicator', StepIndicatorComponent);
        this.registerComponent('walletCard', WalletCardComponent);
        this.registerComponent('transactionStatus', TransactionStatusComponent);
        this.registerComponent('loadingSpinner', LoadingSpinnerComponent);
        // this.registerComponent('notification', NotificationComponent); // TODO: Implement NotificationComponent
        // this.registerComponent('modal', ModalComponent); // TODO: Implement ModalComponent
        this.registerComponent('priceDisplay', PriceDisplayComponent);
        this.registerComponent('statusBox', StatusBoxComponent);
    }

    /**
     * Component Registration
     */

    /**
     * Register a UI component
     * @param {string} name - Component name
     * @param {Function} componentClass - Component class
     */
    registerComponent(name, componentClass) {
        this.components.set(name, componentClass);
        this.core?.log(`UI Component registered: ${name}`);
    }

    /**
     * Create component instance
     * @param {string} name - Component name
     * @param {HTMLElement} element - Target element
     * @param {Object} options - Component options
     * @returns {Object} Component instance
     */
    createComponent(name, element, options = {}) {
        const ComponentClass = this.components.get(name);
        if (!ComponentClass) {
            throw new Error(`Component not found: ${name}`);
        }

        const componentId = this.generateComponentId();
        const instance = new ComponentClass(element, options, this.core, this);
        instance.id = componentId;
        instance.name = name;

        this.activeComponents.set(componentId, instance);
        
        if (instance.init) {
            instance.init();
        }

        return instance;
    }

    /**
     * Destroy component instance
     * @param {string} componentId - Component ID
     */
    destroyComponent(componentId) {
        const instance = this.activeComponents.get(componentId);
        if (instance) {
            if (instance.destroy) {
                instance.destroy();
            }
            this.activeComponents.delete(componentId);
        }
    }

    /**
     * Step Indicator Component
     */

    /**
     * Create step indicator
     * @param {HTMLElement} container - Container element
     * @param {Array} steps - Array of step objects
     * @param {Object} options - Options
     * @returns {Object} Step indicator instance
     */
    createStepIndicator(container, steps, options = {}) {
        return this.createComponent('stepIndicator', container, { steps, ...options });
    }

    /**
     * Update step status
     * @param {Object} stepIndicator - Step indicator instance
     * @param {number} stepIndex - Step index (0-based)
     * @param {string} status - Status ('active', 'completed', 'error')
     */
    updateStepStatus(stepIndicator, stepIndex, status) {
        if (stepIndicator && stepIndicator.updateStep) {
            stepIndicator.updateStep(stepIndex, status);
        }
    }

    /**
     * Wallet Component Methods
     */

    /**
     * Create wallet selection card
     * @param {HTMLElement} container - Container element
     * @param {Array} wallets - Array of wallet objects
     * @param {Object} options - Options
     * @returns {Object} Wallet card instance
     */
    createWalletCards(container, wallets, options = {}) {
        return this.createComponent('walletCard', container, { wallets, ...options });
    }

    /**
     * Transaction Component Methods
     */

    /**
     * Create transaction status display
     * @param {HTMLElement} container - Container element
     * @param {Object} transaction - Transaction object
     * @param {Object} options - Options
     * @returns {Object} Transaction status instance
     */
    createTransactionStatus(container, transaction, options = {}) {
        return this.createComponent('transactionStatus', container, { transaction, ...options });
    }

    /**
     * Update transaction status
     * @param {Object} statusComponent - Status component instance
     * @param {Object} transaction - Updated transaction data
     */
    updateTransactionStatus(statusComponent, transaction) {
        if (statusComponent && statusComponent.updateTransaction) {
            statusComponent.updateTransaction(transaction);
        }
    }

    /**
     * Loading Components
     */

    /**
     * Show loading spinner
     * @param {HTMLElement} element - Target element
     * @param {Object} options - Options
     * @returns {Object} Loading spinner instance
     */
    showLoading(element, options = {}) {
        const loadingId = `loading_${element.id || this.generateComponentId()}`;
        
        if (this.loadingStates.has(loadingId)) {
            return this.loadingStates.get(loadingId);
        }

        const spinner = this.createComponent('loadingSpinner', element, options);
        this.loadingStates.add(loadingId);
        
        return spinner;
    }

    /**
     * Hide loading spinner
     * @param {HTMLElement} element - Target element
     */
    hideLoading(element) {
        const loadingId = `loading_${element.id || 'unknown'}`;
        
        if (this.loadingStates.has(loadingId)) {
            this.loadingStates.delete(loadingId);
        }

        // Remove loading elements
        const spinners = element.querySelectorAll('.cpunk-loading-spinner');
        spinners.forEach(spinner => spinner.remove());
    }

    /**
     * Notification System
     */

    /**
     * Show notification
     * @param {string} message - Notification message
     * @param {string} type - Notification type ('success', 'error', 'warning', 'info')
     * @param {Object} options - Options
     * @returns {string} Notification ID
     */
    showNotification(message, type = 'info', options = {}) {
        const notification = {
            id: this.generateComponentId(),
            message,
            type,
            timestamp: Date.now(),
            ...options
        };

        this.notifications.unshift(notification);
        
        // Limit visible notifications
        if (this.notifications.length > this.config.notifications.maxVisible) {
            this.notifications = this.notifications.slice(0, this.config.notifications.maxVisible);
        }

        this.renderNotifications();

        // Auto-remove after duration
        if (options.duration !== 0) {
            const duration = options.duration || this.config.notifications.duration;
            setTimeout(() => {
                this.hideNotification(notification.id);
            }, duration);
        }

        return notification.id;
    }

    /**
     * Hide notification
     * @param {string} notificationId - Notification ID
     */
    hideNotification(notificationId) {
        const index = this.notifications.findIndex(n => n.id === notificationId);
        if (index >= 0) {
            this.notifications.splice(index, 1);
            this.renderNotifications();
        }
    }

    /**
     * Render notifications
     */
    renderNotifications() {
        let container = document.getElementById('cpunk-notifications');
        
        if (!container && this.notifications.length > 0) {
            container = document.createElement('div');
            container.id = 'cpunk-notifications';
            container.className = 'cpunk-notifications-container';
            document.body.appendChild(container);
        }

        if (container) {
            container.innerHTML = this.notifications.map(notification => 
                this.renderNotification(notification)
            ).join('');
        }
    }

    /**
     * Render single notification
     * @param {Object} notification - Notification object
     * @returns {string} HTML string
     */
    renderNotification(notification) {
        return `
            <div class="cpunk-notification cpunk-notification-${notification.type}" data-id="${notification.id}">
                <div class="cpunk-notification-content">
                    <div class="cpunk-notification-message">${notification.message}</div>
                    ${notification.actions ? this.renderNotificationActions(notification.actions) : ''}
                </div>
                <button class="cpunk-notification-close" onclick="window.CpunkIO.getModule('ui').hideNotification('${notification.id}')">&times;</button>
            </div>
        `;
    }

    /**
     * Render notification actions
     * @param {Array} actions - Action buttons
     * @returns {string} HTML string
     */
    renderNotificationActions(actions) {
        return `
            <div class="cpunk-notification-actions">
                ${actions.map(action => `
                    <button class="cpunk-notification-action cpunk-notification-action-${action.type || 'default'}" 
                            onclick="${action.onclick}">
                        ${action.label}
                    </button>
                `).join('')}
            </div>
        `;
    }

    /**
     * Modal System
     */

    /**
     * Show modal dialog
     * @param {Object} options - Modal options
     * @returns {string} Modal ID
     */
    showModal(options) {
        const modalId = this.generateComponentId();
        const modal = {
            id: modalId,
            title: options.title || '',
            content: options.content || '',
            className: options.className || '',
            closable: options.closable !== false,
            overlay: options.overlay !== false,
            ...options
        };

        this.modals.set(modalId, modal);
        this.renderModal(modal);

        return modalId;
    }

    /**
     * Hide modal dialog
     * @param {string} modalId - Modal ID
     */
    hideModal(modalId) {
        const modalElement = document.getElementById(`cpunk-modal-${modalId}`);
        if (modalElement) {
            modalElement.remove();
        }
        this.modals.delete(modalId);
    }

    /**
     * Render modal
     * @param {Object} modal - Modal object
     */
    renderModal(modal) {
        const modalHTML = `
            <div id="cpunk-modal-${modal.id}" class="cpunk-modal ${modal.className}">
                ${modal.overlay ? '<div class="cpunk-modal-overlay"></div>' : ''}
                <div class="cpunk-modal-container">
                    <div class="cpunk-modal-content">
                        ${modal.title ? `
                            <div class="cpunk-modal-header">
                                <h3 class="cpunk-modal-title">${modal.title}</h3>
                                ${modal.closable ? '<button class="cpunk-modal-close" onclick="window.CpunkIO.getModule(\'ui\').hideModal(\'' + modal.id + '\')">&times;</button>' : ''}
                            </div>
                        ` : ''}
                        <div class="cpunk-modal-body">
                            ${modal.content}
                        </div>
                        ${modal.actions ? `
                            <div class="cpunk-modal-footer">
                                ${modal.actions.map(action => `
                                    <button class="cpunk-modal-action cpunk-modal-action-${action.type || 'default'}" 
                                            onclick="${action.onclick}">
                                        ${action.label}
                                    </button>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Setup event listeners
        const modalElement = document.getElementById(`cpunk-modal-${modal.id}`);
        if (modal.overlay && modal.closable) {
            modalElement.querySelector('.cpunk-modal-overlay').addEventListener('click', () => {
                this.hideModal(modal.id);
            });
        }
    }

    /**
     * Utility Methods
     */

    /**
     * Generate component ID
     * @returns {string} Component ID
     */
    generateComponentId() {
        return `cpunk_ui_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Animate element
     * @param {HTMLElement} element - Element to animate
     * @param {string} animation - Animation name
     * @param {Object} options - Animation options
     */
    animateElement(element, animation, options = {}) {
        const duration = options.duration || this.config.animations.duration;
        const easing = options.easing || this.config.animations.easing;

        element.style.transition = `all ${duration}ms ${easing}`;
        element.classList.add(`cpunk-animate-${animation}`);

        setTimeout(() => {
            element.classList.remove(`cpunk-animate-${animation}`);
        }, duration);
    }

    /**
     * Show/hide element with animation
     * @param {HTMLElement} element - Element
     * @param {boolean} show - Show or hide
     * @param {Object} options - Options
     */
    toggleElement(element, show, options = {}) {
        if (show) {
            element.style.display = options.display || 'block';
            this.animateElement(element, 'fadeIn', options);
        } else {
            this.animateElement(element, 'fadeOut', options);
            setTimeout(() => {
                element.style.display = 'none';
            }, options.duration || this.config.animations.duration);
        }
    }

    /**
     * Update element content with animation
     * @param {HTMLElement} element - Element
     * @param {string} content - New content
     * @param {Object} options - Options
     */
    updateContent(element, content, options = {}) {
        if (options.animate !== false) {
            this.animateElement(element, 'fadeOut', { duration: 150 });
            setTimeout(() => {
                element.innerHTML = content;
                this.animateElement(element, 'fadeIn', { duration: 150 });
            }, 150);
        } else {
            element.innerHTML = content;
        }
    }

    /**
     * Copy to clipboard with feedback
     * @param {string} text - Text to copy
     * @param {HTMLElement} feedbackElement - Element to show feedback
     */
    copyToClipboard(text, feedbackElement) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = feedbackElement ? feedbackElement.textContent : '';
            
            if (feedbackElement) {
                feedbackElement.textContent = 'Copied!';
                feedbackElement.classList.add('cpunk-copied');
                
                setTimeout(() => {
                    feedbackElement.textContent = originalText;
                    feedbackElement.classList.remove('cpunk-copied');
                }, 2000);
            }

            this.showNotification('Copied to clipboard', 'success', { duration: 2000 });
        }).catch(err => {
            this.core?.error('Failed to copy to clipboard:', err);
            this.showNotification('Failed to copy to clipboard', 'error');
        });
    }

    /**
     * Inject global UI styles
     */
    injectGlobalStyles() {
        if (document.getElementById('cpunk-ui-styles')) return;

        const styles = `
            <style id="cpunk-ui-styles">
                /* Notification Styles */
                .cpunk-notifications-container {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    z-index: 10000;
                    max-width: 400px;
                }

                .cpunk-notification {
                    background: var(--bg-secondary, #1a1a1a);
                    border: 1px solid var(--border-color, #333);
                    border-radius: 8px;
                    padding: 16px;
                    margin-bottom: 10px;
                    display: flex;
                    align-items: flex-start;
                    gap: 12px;
                    animation: cpunkSlideIn 0.3s ease-out;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                }

                .cpunk-notification-success { border-left: 4px solid var(--success, #00c851); }
                .cpunk-notification-error { border-left: 4px solid var(--error, #ff4444); }
                .cpunk-notification-warning { border-left: 4px solid var(--warning, #ffbb33); }
                .cpunk-notification-info { border-left: 4px solid var(--accent-primary, #00ffcc); }

                .cpunk-notification-content {
                    flex: 1;
                    color: var(--text-primary, #ffffff);
                }

                .cpunk-notification-message {
                    font-size: 14px;
                    line-height: 1.4;
                    margin-bottom: 8px;
                }

                .cpunk-notification-actions {
                    display: flex;
                    gap: 8px;
                    margin-top: 8px;
                }

                .cpunk-notification-action {
                    padding: 4px 12px;
                    border: 1px solid var(--border-color, #333);
                    background: transparent;
                    color: var(--text-primary, #ffffff);
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 12px;
                    transition: all 0.2s ease;
                }

                .cpunk-notification-action:hover {
                    background: var(--accent-primary, #00ffcc);
                    color: var(--bg-primary, #0a0a0a);
                }

                .cpunk-notification-close {
                    background: none;
                    border: none;
                    color: var(--text-secondary, #cccccc);
                    cursor: pointer;
                    font-size: 18px;
                    line-height: 1;
                    padding: 0;
                    width: 20px;
                    height: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }

                .cpunk-notification-close:hover {
                    color: var(--text-primary, #ffffff);
                }

                /* Modal Styles */
                .cpunk-modal {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    z-index: 10001;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }

                .cpunk-modal-overlay {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.8);
                    backdrop-filter: blur(5px);
                }

                .cpunk-modal-container {
                    position: relative;
                    max-width: 90vw;
                    max-height: 90vh;
                    background: var(--bg-secondary, #1a1a1a);
                    border: 1px solid var(--border-color, #333);
                    border-radius: 12px;
                    overflow: hidden;
                    animation: cpunkModalIn 0.3s ease-out;
                }

                .cpunk-modal-header {
                    padding: 20px;
                    border-bottom: 1px solid var(--border-color, #333);
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }

                .cpunk-modal-title {
                    margin: 0;
                    color: var(--accent-primary, #00ffcc);
                    font-family: 'Orbitron', monospace;
                }

                .cpunk-modal-close {
                    background: none;
                    border: none;
                    color: var(--text-secondary, #cccccc);
                    cursor: pointer;
                    font-size: 24px;
                    line-height: 1;
                    padding: 0;
                    width: 30px;
                    height: 30px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }

                .cpunk-modal-body {
                    padding: 20px;
                    color: var(--text-primary, #ffffff);
                }

                .cpunk-modal-footer {
                    padding: 20px;
                    border-top: 1px solid var(--border-color, #333);
                    display: flex;
                    gap: 12px;
                    justify-content: flex-end;
                }

                .cpunk-modal-action {
                    padding: 10px 20px;
                    border: 1px solid var(--border-color, #333);
                    background: transparent;
                    color: var(--text-primary, #ffffff);
                    border-radius: 6px;
                    cursor: pointer;
                    font-family: 'Orbitron', monospace;
                    transition: all 0.3s ease;
                }

                .cpunk-modal-action-primary {
                    background: var(--gradient-primary, linear-gradient(135deg, #00ffcc, #0088ff));
                    color: var(--bg-primary, #0a0a0a);
                    border-color: transparent;
                }

                .cpunk-modal-action:hover {
                    transform: translateY(-1px);
                    box-shadow: 0 4px 8px rgba(0, 255, 204, 0.3);
                }

                /* Loading Spinner */
                .cpunk-loading-spinner {
                    display: inline-block;
                    width: 40px;
                    height: 40px;
                    border: 3px solid rgba(0, 255, 204, 0.1);
                    border-radius: 50%;
                    border-top-color: var(--accent-primary, #00ffcc);
                    animation: cpunkSpin 1s ease-in-out infinite;
                }

                .cpunk-loading-text {
                    margin-top: 10px;
                    color: var(--accent-primary, #00ffcc);
                    font-family: 'Orbitron', monospace;
                    text-align: center;
                }

                /* Copy feedback */
                .cpunk-copied {
                    color: var(--success, #00c851) !important;
                }

                /* Animations */
                @keyframes cpunkSlideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }

                @keyframes cpunkModalIn {
                    from { transform: scale(0.9); opacity: 0; }
                    to { transform: scale(1); opacity: 1; }
                }

                @keyframes cpunkSpin {
                    to { transform: rotate(360deg); }
                }

                .cpunk-animate-fadeIn {
                    animation: cpunkFadeIn 0.3s ease-out;
                }

                .cpunk-animate-fadeOut {
                    animation: cpunkFadeOut 0.3s ease-out;
                }

                @keyframes cpunkFadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }

                @keyframes cpunkFadeOut {
                    from { opacity: 1; }
                    to { opacity: 0; }
                }

                /* Responsive */
                @media (max-width: 768px) {
                    .cpunk-notifications-container {
                        left: 10px;
                        right: 10px;
                        max-width: none;
                    }

                    .cpunk-modal-container {
                        margin: 20px;
                        max-width: calc(100vw - 40px);
                    }
                }
            </style>
        `;

        document.head.insertAdjacentHTML('beforeend', styles);
    }

    /**
     * Get component statistics
     * @returns {Object} Component statistics
     */
    getStats() {
        return {
            registeredComponents: this.components.size,
            activeComponents: this.activeComponents.size,
            activeModals: this.modals.size,
            activeNotifications: this.notifications.length,
            loadingStates: this.loadingStates.size
        };
    }

    /**
     * Clean up all components
     */
    destroy() {
        // Destroy all active components
        for (const [id, instance] of this.activeComponents) {
            this.destroyComponent(id);
        }

        // Clear modals
        for (const modalId of this.modals.keys()) {
            this.hideModal(modalId);
        }

        // Clear notifications
        this.notifications = [];
        this.renderNotifications();

        // Clear state
        this.components.clear();
        this.activeComponents.clear();
        this.modals.clear();
        this.loadingStates.clear();

        this.initialized = false;
        this.core?.log('UI Components destroyed');
    }
}

/**
 * Base Component Class
 */
class BaseComponent {
    constructor(element, options, core, ui) {
        this.element = element;
        this.options = options;
        this.core = core;
        this.ui = ui;
        this.id = null;
        this.name = null;
    }

    init() {
        // Override in subclasses
    }

    destroy() {
        // Override in subclasses
    }
}

/**
 * Step Indicator Component
 */
class StepIndicatorComponent extends BaseComponent {
    init() {
        this.steps = this.options.steps || [];
        this.render();
    }

    render() {
        const stepsHTML = this.steps.map((step, index) => `
            <div class="step-item" id="step-${index}" data-step="${index}">
                <div class="step-number">${index + 1}</div>
                <div class="step-text">${step.title || step}</div>
                <div class="step-check">✓</div>
            </div>
        `).join('');

        this.element.innerHTML = `
            <div class="registration-steps">
                ${stepsHTML}
            </div>
        `;
    }

    updateStep(stepIndex, status) {
        const stepElement = this.element.querySelector(`#step-${stepIndex}`);
        if (stepElement) {
            stepElement.className = `step-item ${status}`;
        }
    }
}

/**
 * Wallet Card Component
 */
class WalletCardComponent extends BaseComponent {
    init() {
        this.wallets = this.options.wallets || [];
        this.onSelect = this.options.onSelect;
        this.render();
    }

    render() {
        const walletsHTML = this.wallets.map(wallet => `
            <div class="wallet-card" data-wallet="${wallet.name}" onclick="this.selectWallet('${wallet.name}')">
                <div class="wallet-name">${wallet.name}</div>
                <div class="wallet-address">${this.core?.formatAddress ? this.core.formatAddress(wallet.address) : wallet.address}</div>
                <div class="wallet-balances">
                    <div class="balance-item">CPUNK: ${wallet.cpunkBalance || 0}</div>
                    <div class="balance-item">CELL: ${wallet.cellBalance || 0}</div>
                </div>
            </div>
        `).join('');

        this.element.innerHTML = walletsHTML;
        this.setupEventListeners();
    }

    setupEventListeners() {
        this.element.querySelectorAll('.wallet-card').forEach(card => {
            card.addEventListener('click', (e) => {
                const walletName = card.dataset.wallet;
                const wallet = this.wallets.find(w => w.name === walletName);
                if (wallet && this.onSelect) {
                    this.onSelect(wallet);
                }
            });
        });
    }
}

/**
 * Transaction Status Component
 */
class TransactionStatusComponent extends BaseComponent {
    init() {
        this.transaction = this.options.transaction;
        this.render();
    }

    render() {
        const { hash, status, verificationAttempts = 0 } = this.transaction || {};

        this.element.innerHTML = `
            <div class="tx-processing-container">
                <div class="tx-processing-animation">
                    <div class="tx-processing-spinner"></div>
                </div>
                <div class="tx-status">${this.getStatusMessage()}</div>
                ${hash ? `<div class="tx-hash">Hash: ${this.core?.formatTxHash ? this.core.formatTxHash(hash) : hash}</div>` : ''}
                ${verificationAttempts > 0 ? `<div class="tx-attempts">Attempt: ${verificationAttempts}</div>` : ''}
            </div>
        `;
    }

    updateTransaction(transaction) {
        this.transaction = transaction;
        this.render();
    }

    getStatusMessage() {
        if (!this.transaction) return 'Preparing transaction...';

        switch (this.transaction.status) {
            case 'submitted': return 'Transaction submitted, waiting for verification...';
            case 'verifying': return `Verifying transaction... (Attempt ${this.transaction.verificationAttempts || 1})`;
            case 'verified': return 'Transaction verified successfully!';
            case 'failed': return 'Transaction failed';
            case 'timeout': return 'Transaction verification timed out';
            default: return 'Processing transaction...';
        }
    }
}

/**
 * Loading Spinner Component
 */
class LoadingSpinnerComponent extends BaseComponent {
    init() {
        this.message = this.options.message || 'Loading...';
        this.render();
    }

    render() {
        this.element.innerHTML = `
            <div class="cpunk-loading-container">
                <div class="cpunk-loading-spinner"></div>
                <div class="cpunk-loading-text">${this.message}</div>
            </div>
        `;
    }
}

// Auto-register with CpunkIO core if available
if (typeof window !== 'undefined' && window.CpunkIO) {
    window.CpunkIO.registerModule('ui', new CpunkUIComponents(window.CpunkIO));
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CpunkUIComponents;
}