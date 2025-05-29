class Translation {
    constructor() {
        this.currentLanguage = 'en';
        this.translations = {};
        this.fallbackLanguage = 'en';
        this.loadedLanguages = new Set();
        
        // Get language from localStorage or browser
        this.currentLanguage = this.getStoredLanguage() || this.getBrowserLanguage() || 'en';
        
        this.init();
    }

    getStoredLanguage() {
        return localStorage.getItem('cpunk-language');
    }

    getBrowserLanguage() {
        const lang = navigator.language || navigator.userLanguage;
        return lang ? lang.split('-')[0] : 'en';
    }

    async init() {
        await this.loadLanguage(this.fallbackLanguage);
        if (this.currentLanguage !== this.fallbackLanguage) {
            await this.loadLanguage(this.currentLanguage);
        }
        this.translatePage();
    }

    async loadLanguage(language) {
        if (this.loadedLanguages.has(language)) {
            return;
        }

        try {
            const response = await fetch(`/lang/${language}.json`);
            if (response.ok) {
                const translations = await response.json();
                this.translations[language] = translations;
                this.loadedLanguages.add(language);
            } else {
                console.warn(`Language file ${language}.json not found`);
            }
        } catch (error) {
            console.error(`Error loading language ${language}:`, error);
        }
    }

    t(key, params = {}) {
        let translation = this.getTranslation(key, this.currentLanguage) || 
                         this.getTranslation(key, this.fallbackLanguage) || 
                         key;

        // Replace parameters in translation
        Object.keys(params).forEach(param => {
            translation = translation.replace(`{{${param}}}`, params[param]);
        });

        return translation;
    }

    getTranslation(key, language) {
        const translations = this.translations[language];
        if (!translations) return null;

        // Support nested keys like "nav.dashboard"
        return key.split('.').reduce((obj, k) => obj && obj[k], translations);
    }

    async setLanguage(language) {
        if (language === this.currentLanguage) {
            return;
        }

        await this.loadLanguage(language);
        this.currentLanguage = language;
        localStorage.setItem('cpunk-language', language);
        this.translatePage();
        
        // Trigger custom event for other components
        window.dispatchEvent(new CustomEvent('languageChanged', { 
            detail: { language } 
        }));
    }

    translatePage() {
        // Translate elements with data-i18n attribute
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            const translation = this.t(key);
            
            if (element.tagName === 'INPUT' && element.type === 'text') {
                element.placeholder = translation;
            } else {
                element.textContent = translation;
            }
        });

        // Translate elements with data-i18n-html attribute (for HTML content)
        document.querySelectorAll('[data-i18n-html]').forEach(element => {
            const key = element.getAttribute('data-i18n-html');
            const translation = this.t(key);
            element.innerHTML = translation;
        });

        // Translate title and alt attributes
        document.querySelectorAll('[data-i18n-title]').forEach(element => {
            const key = element.getAttribute('data-i18n-title');
            element.title = this.t(key);
        });

        document.querySelectorAll('[data-i18n-alt]').forEach(element => {
            const key = element.getAttribute('data-i18n-alt');
            element.alt = this.t(key);
        });
    }

    getCurrentLanguage() {
        return this.currentLanguage;
    }

    getAvailableLanguages() {
        return Array.from(this.loadedLanguages);
    }
}

// Global translation instance
window.i18n = new Translation();

// Expose translation function globally
window.t = (key, params) => window.i18n.t(key, params);