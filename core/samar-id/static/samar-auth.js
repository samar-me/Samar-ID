/**
 * Samar ID Official Authentication SDK (samar-auth.js)
 * Versiya: 1.0.0 — Samar OS Mega-Ecosystem
 * Enables seamless "Sign in with Samar ID" for all ecosystem apps.
 */
(function(window) {
    'use strict';

    const SamarAuth = {
        config: {
            clientId: '',
            redirectUri: '',
            scope: 'profile,email',
            state: '',
            authEndpoint: '/oauth/authorize'
        },

        init(options) {
            this.config = Object.assign({}, this.config, options);
            if (options.samarIdUrl) {
                this.config.authEndpoint = options.samarIdUrl.replace(/\/$/, '') + '/oauth/authorize';
            }
            return this;
        },

        getAuthUrl(customOpts) {
            const opts = Object.assign({}, this.config, customOpts);
            const state = opts.state || ('samar_' + Math.random().toString(36).substring(2, 12));
            const params = new URLSearchParams({
                client_id: opts.clientId || 'samar_app',
                redirect_uri: opts.redirectUri || window.location.href,
                response_type: opts.responseType || 'code',
                scope: opts.scope || 'profile,email',
                state: state
            });
            return (opts.authEndpoint || '/oauth/authorize') + '?' + params.toString();
        },

        signIn(options) {
            const url = this.getAuthUrl(options);
            if (options && options.popup) {
                const w = 520, h = 720;
                const left = (window.screen.width / 2) - (w / 2);
                const top = (window.screen.height / 2) - (h / 2);
                return window.open(url, 'SamarAuthPopup', `width=${w},height=${h},top=${top},left=${left},status=no,toolbar=no,menubar=no`);
            } else {
                window.location.href = url;
            }
        },

        renderButton(targetElement, options) {
            const el = typeof targetElement === 'string' ? document.getElementById(targetElement) : targetElement;
            if (!el) {
                console.error('[SamarAuth] Target element not found:', targetElement);
                return;
            }

            const opts = Object.assign({
                text: 'Samar ID orqali kirish',
                theme: 'dark', // 'dark' | 'light'
                size: 'medium', // 'small' | 'medium' | 'large'
                clientId: this.config.clientId || 'samar_app',
                redirectUri: this.config.redirectUri || window.location.href,
                scope: this.config.scope || 'profile,email'
            }, options);

            const isLight = opts.theme === 'light';
            const bg = isLight ? '#f4f6fa' : '#0e1422';
            const textCol = isLight ? '#0a0d14' : '#ffffff';
            const borderCol = isLight ? '#d2d8e6' : '#22304d';
            const py = opts.size === 'large' ? '14px 22px' : (opts.size === 'small' ? '8px 14px' : '11px 18px');
            const fontSize = opts.size === 'large' ? '15px' : (opts.size === 'small' ? '13px' : '14px');

            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'samar-auth-btn';
            btn.style.cssText = `
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                background: ${bg};
                color: ${textCol};
                border: 1px solid ${borderCol};
                padding: ${py};
                border-radius: 12px;
                font-size: ${fontSize};
                font-weight: 600;
                font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
                cursor: pointer;
                box-shadow: 0 4px 14px rgba(0, 0, 0, 0.15);
                transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
                user-select: none;
                text-decoration: none;
            `;

            btn.innerHTML = `
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" style="flex-shrink:0;">
                    <defs>
                        <linearGradient id="samarBtnGrad_${Math.floor(Math.random()*1000)}" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#00f2fe"/>
                            <stop offset="100%" stop-color="#7f00ff"/>
                        </linearGradient>
                    </defs>
                    <path d="M12 2L20 6.5C20 15 14.5 20.5 12 22C9.5 20.5 4 15 4 6.5L12 2Z" stroke="#00f2fe" stroke-width="2" fill="#0d1524" />
                    <polygon points="12,7 16,11 12,15 8,11" fill="#00f2fe" />
                </svg>
                <span>${opts.text}</span>
            `;

            btn.onmouseenter = () => {
                btn.style.borderColor = '#00f2fe';
                btn.style.boxShadow = '0 6px 22px rgba(0, 242, 254, 0.3)';
                btn.style.transform = 'translateY(-1.5px)';
            };
            btn.onmouseleave = () => {
                btn.style.borderColor = borderCol;
                btn.style.boxShadow = '0 4px 14px rgba(0, 0, 0, 0.15)';
                btn.style.transform = 'translateY(0)';
            };

            btn.onclick = () => {
                this.signIn(opts);
            };

            el.innerHTML = '';
            el.appendChild(btn);
        }
    };

    window.SamarAuth = SamarAuth;
})(window);
