/**
 * Cipher — Content Script (Autofill)
 *
 * Detects login forms on web pages and fills credentials from the vault.
 * Uses heuristic field detection (input types, names, labels, aria attributes).
 */

(() => {
  "use strict";

  const chromeAPI = typeof chrome !== "undefined" && chrome.runtime ? chrome : (typeof browser !== "undefined" ? browser : null);

  // ── Form Field Detection ─────────────────────────────────────────

  const USERNAME_PATTERNS = [
    /user/i, /email/i, /login/i, /account/i, /name/i, /id$/i,
    /identifier/i, /phone/i,
  ];

  const PASSWORD_PATTERNS = [/pass/i, /pwd/i, /secret/i];

  /**
   * Score an input element's likelihood of being a username/email field.
   */
  function scoreUsernameField(input) {
    if (input.type === "password" || input.type === "hidden") return 0;
    if (input.type === "email") return 10;

    let score = 0;
    const attrs = [
      input.name, input.id, input.placeholder,
      input.getAttribute("aria-label"), input.autocomplete,
    ].filter(Boolean).join(" ");

    for (const pattern of USERNAME_PATTERNS) {
      if (pattern.test(attrs)) score += 3;
    }

    if (input.autocomplete === "username" || input.autocomplete === "email") {
      score += 5;
    }

    return score;
  }

  /**
   * Score an input element's likelihood of being a password field.
   */
  function scorePasswordField(input) {
    if (input.type === "password") return 10;
    if (input.type === "hidden") return 0;

    let score = 0;
    const attrs = [
      input.name, input.id, input.placeholder,
      input.getAttribute("aria-label"),
    ].filter(Boolean).join(" ");

    for (const pattern of PASSWORD_PATTERNS) {
      if (pattern.test(attrs)) score += 3;
    }

    if (input.autocomplete === "current-password") score += 5;

    return score;
  }

  /**
   * Detect login forms on the current page.
   * Returns an array of { form, usernameField, passwordField }.
   */
  function detectLoginForms() {
    const results = [];
    const forms = document.querySelectorAll("form");

    for (const form of forms) {
      const inputs = form.querySelectorAll(
        'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])'
      );

      let bestUsername = null;
      let bestUsernameScore = 0;
      let bestPassword = null;
      let bestPasswordScore = 0;

      for (const input of inputs) {
        const uScore = scoreUsernameField(input);
        if (uScore > bestUsernameScore) {
          bestUsernameScore = uScore;
          bestUsername = input;
        }

        const pScore = scorePasswordField(input);
        if (pScore > bestPasswordScore) {
          bestPasswordScore = pScore;
          bestPassword = input;
        }
      }

      if (bestPassword && bestPasswordScore > 0) {
        results.push({
          form,
          usernameField: bestUsername,
          passwordField: bestPassword,
        });
      }
    }

    // Also check for password fields outside forms
    if (results.length === 0) {
      const allInputs = document.querySelectorAll('input[type="password"]');
      for (const pwdInput of allInputs) {
        // Walk backwards to find a sibling username field
        let usernameField = null;
        let sibling = pwdInput.previousElementSibling;
        while (sibling) {
          if (sibling.tagName === "INPUT" && scoreUsernameField(sibling) > 0) {
            usernameField = sibling;
            break;
          }
          sibling = sibling.previousElementSibling;
        }

        // If no sibling, check parent
        if (!usernameField) {
          const parent = pwdInput.closest("div, section, main, body");
          if (parent) {
            const inputs = parent.querySelectorAll(
              'input:not([type="password"]):not([type="hidden"]):not([type="submit"])'
            );
            for (const input of inputs) {
              if (scoreUsernameField(input) > 0) {
                usernameField = input;
                break;
              }
            }
          }
        }

        results.push({
          form: null,
          usernameField,
          passwordField: pwdInput,
        });
      }
    }

    return results;
  }

  // ── Autofill Execution ───────────────────────────────────────────

  /**
   * Fill a credential into the detected form fields.
   * Dispatches input events so JS frameworks (React, Vue) pick up the change.
   */
  function fillCredential(username, password) {
    const loginForms = detectLoginForms();
    if (loginForms.length === 0) return false;

    const { usernameField, passwordField } = loginForms[0];

    if (usernameField && username) {
      setNativeValue(usernameField, username);
    }

    if (passwordField && password) {
      setNativeValue(passwordField, password);
    }

    return true;
  }

  /**
   * Set a value using the native setter to trigger React/Vue reactivity.
   */
  function setNativeValue(element, value) {
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value"
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(element, value);
    } else {
      element.value = value;
    }

    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // ── Credential Capture & Save Prompt ─────────────────────────────

  function getFriendlyTitle() {
    let title = document.title || "";
    // Clean common prefixes/suffixes like " - Sign in", " | Log in"
    title = title.replace(/\s*[-|–—]\s*(sign in|log in|login|register|sign up).*$/i, "").trim();
    if (!title || title.length < 2) {
      let host = window.location.hostname;
      if (host.startsWith("www.")) host = host.slice(4);
      title = host.charAt(0).toUpperCase() + host.slice(1);
    }
    return title;
  }

  function showSavePrompt(username, password) {
    if (!password) return;

    // Avoid duplicate banners
    const existingHost = document.getElementById("cipher-save-host");
    if (existingHost) existingHost.remove();

    const host = document.createElement("div");
    host.id = "cipher-save-host";
    host.style.cssText = "all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;";

    const shadow = host.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = `
      .cipher-banner {
        width: 320px;
        background: #0E1013;
        color: #F5F5F5;
        border: 1px solid #252930;
        border-radius: 10px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
        padding: 14px 16px;
        display: flex;
        flex-direction: column;
        gap: 10px;
        box-sizing: border-box;
        animation: cipherSlideIn 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes cipherSlideIn {
        from { transform: translateY(-16px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      .cipher-header {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .cipher-icon {
        width: 20px;
        height: 20px;
        flex-shrink: 0;
      }
      .cipher-title {
        font-size: 13px;
        font-weight: 600;
        color: #F5F5F5;
        flex: 1;
      }
      .cipher-close {
        background: transparent;
        border: none;
        color: #5F6570;
        font-size: 16px;
        cursor: pointer;
        padding: 0 4px;
        line-height: 1;
      }
      .cipher-close:hover { color: #F5F5F5; }
      .cipher-body {
        font-size: 12px;
        color: #9298A3;
        line-height: 1.4;
      }
      .cipher-user {
        color: #F5F5F5;
        font-weight: 500;
        word-break: break-all;
      }
      .cipher-actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
        margin-top: 4px;
      }
      .cipher-btn {
        padding: 6px 12px;
        border-radius: 5px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        border: none;
        transition: all 0.15s ease;
      }
      .cipher-btn-save {
        background: linear-gradient(135deg, #3D8FFF 0%, #1A6FE8 100%);
        color: white;
      }
      .cipher-btn-save:hover { opacity: 0.95; }
      .cipher-btn-dismiss {
        background: transparent;
        border: 1px solid #252930;
        color: #9298A3;
      }
      .cipher-btn-dismiss:hover { color: #F5F5F5; background: rgba(255,255,255,0.05); }
      .cipher-success {
        color: #30A46C;
        font-size: 12px;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0;
      }
    `;

    const banner = document.createElement("div");
    banner.className = "cipher-banner";

    const friendlyHost = window.location.hostname.replace(/^www\./, "");
    const userDisplay = username ? username : "Current site account";

    banner.innerHTML = `
      <div class="cipher-header">
        <svg class="cipher-icon" viewBox="0 0 48 48">
          <polygon points="24,4 44,24 24,44 4,24" fill="#2D7FF9"/>
          <rect x="18" y="21" width="12" height="9" rx="2" fill="#0B0C0E"/>
          <path d="M20 21 V18 A4 4 0 0 1 28 18 V21" fill="none" stroke="#0B0C0E" stroke-width="2.2" stroke-linecap="round"/>
        </svg>
        <span class="cipher-title">Save password to Cipher?</span>
        <button class="cipher-close" id="btn-cipher-close">&times;</button>
      </div>
      <div class="cipher-body">
        <span class="cipher-user" id="cipher-user-span"></span> on <strong id="cipher-host-strong"></strong>
      </div>
      <div class="cipher-actions" id="cipher-actions-bar">
        <button class="cipher-btn cipher-btn-dismiss" id="btn-cipher-dismiss">Not now</button>
        <button class="cipher-btn cipher-btn-save" id="btn-cipher-save">Save</button>
      </div>
    `;
    banner.querySelector("#cipher-user-span").textContent = userDisplay;
    banner.querySelector("#cipher-host-strong").textContent = friendlyHost;

    shadow.appendChild(style);
    shadow.appendChild(banner);
    document.documentElement.appendChild(host);

    const btnClose = shadow.getElementById("btn-cipher-close");
    const btnDismiss = shadow.getElementById("btn-cipher-dismiss");
    const btnSave = shadow.getElementById("btn-cipher-save");
    const actionsBar = shadow.getElementById("cipher-actions-bar");

    const dismissBanner = () => {
      host.remove();
    };

    btnClose.addEventListener("click", dismissBanner);
    btnDismiss.addEventListener("click", dismissBanner);

    btnSave.addEventListener("click", async () => {
      btnSave.disabled = true;
      btnSave.textContent = "Saving...";

      try {
        const resp = await new Promise((resolve) => {
          if (!chromeAPI || !chromeAPI.runtime) {
            resolve({ success: false, error: "Extension runtime unavailable" });
            return;
          }
          chromeAPI.runtime.sendMessage({
            action: "save_credential",
            payload: {
              title: getFriendlyTitle(),
              username: username || "",
              password: password,
              url: window.location.href,
            },
          }, (response) => {
            if (chromeAPI.runtime.lastError) {
              resolve({ success: false, error: chromeAPI.runtime.lastError.message });
            } else {
              resolve(response);
            }
          });
        });

        if (resp && resp.success) {
          actionsBar.textContent = "✓ Password saved to Cipher";
          actionsBar.className = "cipher-success";
          setTimeout(dismissBanner, 1600);
        } else {
          actionsBar.textContent = `Failed: ${resp?.error || "Vault locked"}`;
          actionsBar.style.color = "#E5484D";
          actionsBar.style.fontSize = "11px";
          setTimeout(dismissBanner, 3000);
        }
      } catch (err) {
        actionsBar.textContent = `Error: ${err.message}`;
        actionsBar.style.color = "#E5484D";
        actionsBar.style.fontSize = "11px";
        setTimeout(dismissBanner, 3000);
      }
    });

    // Auto-dismiss after 20 seconds if untouched
    setTimeout(() => {
      if (document.contains(host)) dismissBanner();
    }, 20000);
  }

  function captureFormValues(form) {
    const inputs = form ? form.querySelectorAll("input") : document.querySelectorAll("input");
    let username = "";
    let bestUserScore = 0;
    let password = "";

    for (const input of inputs) {
      if (input.type === "password" && input.value) {
        password = input.value;
      }
      const uScore = scoreUsernameField(input);
      if (uScore > bestUserScore && input.value) {
        bestUserScore = uScore;
        username = input.value;
      }
    }

    if (password) {
      // Store in sessionStorage so if page immediately unloads, next page can prompt
      try {
        sessionStorage.setItem("cipher_pending_save", JSON.stringify({
          username,
          password,
          url: window.location.href,
          timestamp: Date.now(),
        }));
      } catch {}

      showSavePrompt(username, password);
    }
  }

  // Listen for form submissions
  window.addEventListener("submit", (e) => {
    captureFormValues(e.target);
  }, true);

  // Listen for Enter on password fields or click on submit buttons
  window.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target && e.target.type === "password") {
      const form = e.target.closest("form");
      captureFormValues(form);
    }
  }, true);

  window.addEventListener("click", (e) => {
    const btn = e.target.closest("button, input[type='submit'], [role='button']");
    if (btn) {
      const text = (btn.innerText || btn.value || "").toLowerCase();
      if (/log\s*in|sign\s*in|submit|register|sign\s*up/i.test(text)) {
        const form = btn.closest("form");
        // Slight delay to allow password managers/react state to synchronize
        setTimeout(() => captureFormValues(form), 50);
      }
    }
  }, true);

  // Check if a pending save was queued right before page redirect
  try {
    const pending = sessionStorage.getItem("cipher_pending_save");
    if (pending) {
      sessionStorage.removeItem("cipher_pending_save");
      const data = JSON.parse(pending);
      // Only prompt if queued within the last 60 seconds
      if (Date.now() - data.timestamp < 60000 && data.password) {
        setTimeout(() => {
          showSavePrompt(data.username, data.password);
        }, 500);
      }
    }
  } catch {}

  // ── Message Handler ──────────────────────────────────────────────

  if (chromeAPI && chromeAPI.runtime && chromeAPI.runtime.onMessage) {
    chromeAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === "fill_credential") {
        const { username, password } = message.payload || {};
        const filled = fillCredential(username, password);
        sendResponse({ success: filled });
        return false;
      }

      if (message.action === "detect_forms") {
        const forms = detectLoginForms();
        sendResponse({
          success: true,
          data: {
            formCount: forms.length,
            hasPasswordField: forms.some((f) => f.passwordField),
            url: window.location.href,
            hostname: window.location.hostname,
          },
        });
        return false;
      }

      return false;
    });
  }

  // ── Notify background about detected forms on page load ────────

  const forms = detectLoginForms();
  if (forms.length > 0 && chromeAPI && chromeAPI.runtime && chromeAPI.runtime.sendMessage) {
    try {
      chromeAPI.runtime.sendMessage({
        action: "form_detected",
        payload: {
          url: window.location.href,
          hostname: window.location.hostname,
          formCount: forms.length,
        },
      }, () => {
        // Void lastError if background is not listening
        void chromeAPI.runtime?.lastError;
      });
    } catch {
      // Extension context may not be available
    }
  }
})();
