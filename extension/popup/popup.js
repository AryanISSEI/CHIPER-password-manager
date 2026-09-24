/**
 * Cipher — Popup Script
 *
 * Handles unlock state, site-specific credential querying,
 * searching the vault, autofill execution, and password generation.
 */

(() => {
  "use strict";

  const chromeAPI = typeof chrome !== "undefined" && chrome.runtime ? chrome : (typeof browser !== "undefined" ? browser : null);

  function sendExtensionMessage(msg) {
    return new Promise((resolve, reject) => {
      if (!chromeAPI || !chromeAPI.runtime) {
        reject(new Error("Extension runtime not available"));
        return;
      }
      chromeAPI.runtime.sendMessage(msg, (response) => {
        if (chromeAPI.runtime.lastError) {
          reject(new Error(chromeAPI.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
    });
  }

  function queryActiveTab() {
    return new Promise((resolve, reject) => {
      if (!chromeAPI || !chromeAPI.tabs) {
        resolve([]);
        return;
      }
      chromeAPI.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (chromeAPI.runtime.lastError) {
          reject(new Error(chromeAPI.runtime.lastError.message));
        } else {
          resolve(tabs || []);
        }
      });
    });
  }

  // Elements
  const lockedView = document.getElementById("locked-view");
  const unlockedView = document.getElementById("unlocked-view");
  const unlockForm = document.getElementById("unlock-form");
  const unlockPassword = document.getElementById("unlock-password");
  const unlockError = document.getElementById("unlock-error");
  const btnTogglePwd = document.getElementById("btn-toggle-unlock-pwd");
  const btnLock = document.getElementById("btn-lock");
  const connBadge = document.getElementById("connection-badge");

  const currentDomainEl = document.getElementById("current-domain");
  const searchInput = document.getElementById("search-input");
  const btnClearSearch = document.getElementById("btn-clear-search");
  const listHeaderTitle = document.getElementById("list-header-title");
  const credentialCount = document.getElementById("credential-count");
  const credentialsList = document.getElementById("credentials-list");

  const btnGenToggle = document.getElementById("btn-generator-toggle");
  const genDrawer = document.getElementById("gen-drawer");
  const btnCloseGen = document.getElementById("btn-close-gen");
  const genOutput = document.getElementById("gen-output");
  const btnCopyGen = document.getElementById("btn-copy-generated");
  const btnRegen = document.getElementById("btn-regen");
  const genLengthSlider = document.getElementById("gen-length-slider");
  const genLengthVal = document.getElementById("gen-length-val");
  const genUpper = document.getElementById("gen-chk-upper");
  const genLower = document.getElementById("gen-chk-lower");
  const genDigits = document.getElementById("gen-chk-digits");
  const genSymbols = document.getElementById("gen-chk-symbols");

  // Add Credential Drawer Elements
  const btnAddCred = document.getElementById("btn-add-credential");
  const addDrawer = document.getElementById("add-drawer");
  const btnCloseAdd = document.getElementById("btn-close-add");
  const btnCancelAdd = document.getElementById("btn-cancel-add");
  const addForm = document.getElementById("add-credential-form");
  const addTitle = document.getElementById("add-title");
  const addUsername = document.getElementById("add-username");
  const addPassword = document.getElementById("add-password");
  const addUrl = document.getElementById("add-url");
  const btnFillGenPwd = document.getElementById("btn-fill-gen-pwd");

  const toastEl = document.getElementById("toast");

  let currentTabUrl = "";
  let currentTabDomain = "";
  let matchingEntries = [];

  // ── Toast Helper ───────────────────────────────────────────────────

  let toastTimer = null;
  function showToast(msg) {
    if (toastTimer) clearTimeout(toastTimer);
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    toastTimer = setTimeout(() => {
      toastEl.classList.remove("show");
    }, 2000);
  }

  // ── Domain Helper ──────────────────────────────────────────────────

  function getDomainFromUrl(url) {
    if (!url) return "";
    try {
      const parsed = new URL(url);
      let hostname = parsed.hostname.toLowerCase();
      if (hostname.startsWith("www.")) hostname = hostname.slice(4);
      return hostname;
    } catch {
      return "";
    }
  }

  // ── Password Generator Logic ───────────────────────────────────────

  function generatePassword() {
    const length = parseInt(genLengthSlider.value, 10);
    let chars = "";
    if (genUpper.checked) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (genLower.checked) chars += "abcdefghijklmnopqrstuvwxyz";
    if (genDigits.checked) chars += "0123456789";
    if (genSymbols.checked) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (!chars) chars = "abcdefghijklmnopqrstuvwxyz0123456789";

    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    let result = "";
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
    genOutput.value = result;
  }

  // ── View Transitions ───────────────────────────────────────────────

  function showLockedState() {
    lockedView.style.display = "flex";
    unlockedView.style.display = "none";
    btnLock.style.display = "none";
    btnAddCred.style.display = "none";
    addDrawer.style.display = "none";
    unlockPassword.value = "";
    unlockError.style.display = "none";
    unlockPassword.focus();
  }

  function showUnlockedState() {
    lockedView.style.display = "none";
    unlockedView.style.display = "flex";
    btnLock.style.display = "flex";
    btnAddCred.style.display = "flex";
    loadTabAndCredentials();
  }

  // ── Vault Status & Querying ────────────────────────────────────────

  async function checkStatus() {
    try {
      const resp = await sendExtensionMessage({ action: "status" });
      if (resp && resp.success) {
        connBadge.className = "badge-dot connected";
        connBadge.title = "Connected to Cipher Desktop";
        if (resp.data && resp.data.unlocked) {
          showUnlockedState();
        } else {
          showLockedState();
        }
      } else {
        connBadge.className = "badge-dot disconnected";
        connBadge.title = "Cannot communicate with Cipher desktop";
        showLockedState();
        if (resp && resp.error) {
          unlockError.textContent = resp.error;
          unlockError.style.display = "block";
        }
      }
    } catch (err) {
      connBadge.className = "badge-dot disconnected";
      connBadge.title = "Desktop app not running";
      showLockedState();
      unlockError.textContent = "Cannot connect to Cipher desktop app. Please make sure Cipher is running.";
      unlockError.style.display = "block";
    }
  }

  async function loadTabAndCredentials() {
    try {
      const tabs = await queryActiveTab();
      if (tabs.length > 0 && tabs[0].url) {
        currentTabUrl = tabs[0].url;
        currentTabDomain = getDomainFromUrl(currentTabUrl);
        currentDomainEl.textContent = currentTabDomain || "No active webpage";
      } else {
        currentDomainEl.textContent = "No active webpage";
      }

      if (currentTabDomain) {
        const resp = await sendExtensionMessage({
          action: "get_entries_for_url",
          payload: { url: currentTabUrl },
        });

        if (resp && resp.success) {
          matchingEntries = resp.data || [];
          renderCredentials(matchingEntries, "Matching Credentials");
        } else {
          renderCredentials([], "Matching Credentials");
        }
      } else {
        // Not a web page (e.g. about:blank or settings), load all credentials
        loadSearch("");
      }
    } catch (err) {
      console.error("Error loading credentials for tab:", err);
    }
  }

  async function loadSearch(query) {
    try {
      const resp = await sendExtensionMessage({
        action: "search",
        payload: { query },
      });

      if (resp && resp.success) {
        const list = resp.data || [];
        renderCredentials(list, query ? `Results for "${query}"` : "All Credentials");
      }
    } catch (err) {
      console.error("Error searching vault:", err);
    }
  }

  // ── Render Credential Cards ────────────────────────────────────────

  function renderCredentials(entries, title) {
    listHeaderTitle.textContent = title;
    credentialCount.textContent = entries.length;
    credentialsList.innerHTML = "";

    if (entries.length === 0) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "empty-state";
      emptyDiv.innerHTML = `
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/>
          <line x1="8" y1="12" x2="16" y2="12"/>
        </svg>
        <span>No credentials found</span>
      `;
      credentialsList.appendChild(emptyDiv);
      return;
    }

    entries.forEach((entry) => {
      const card = document.createElement("div");
      card.className = "credential-card";

      const header = document.createElement("div");
      header.className = "cred-header";

      const titleEl = document.createElement("span");
      titleEl.className = "cred-title";
      titleEl.textContent = entry.title || "Untitled";

      const userEl = document.createElement("span");
      userEl.className = "cred-user";
      userEl.textContent = entry.username || "No username";

      header.appendChild(titleEl);
      header.appendChild(userEl);

      const actions = document.createElement("div");
      actions.className = "cred-actions";

      // Fill Button
      const btnFill = document.createElement("button");
      btnFill.className = "btn-fill";
      btnFill.textContent = "Autofill";
      btnFill.addEventListener("click", async () => {
        btnFill.disabled = true;
        try {
          const credResp = await sendExtensionMessage({
            action: "get_credential",
            payload: { entryId: entry.id },
          });

          if (credResp && credResp.success && credResp.data) {
            const fillResp = await sendExtensionMessage({
              action: "autofill",
              payload: {
                username: credResp.data.username,
                password: credResp.data.password,
              },
            });

            if (fillResp && fillResp.success) {
              showToast("Credentials filled!");
              setTimeout(() => window.close(), 600);
            } else {
              showToast("Could not autofill form");
            }
          } else {
            showToast("Failed to decrypt credentials");
          }
        } catch (e) {
          showToast("Autofill error: " + e.message);
        } finally {
          btnFill.disabled = false;
        }
      });

      // Copy Username Button
      const btnCopyUser = document.createElement("button");
      btnCopyUser.className = "btn-copy";
      btnCopyUser.textContent = "Copy User";
      btnCopyUser.addEventListener("click", async () => {
        if (entry.username) {
          await navigator.clipboard.writeText(entry.username);
          showToast("Username copied!");
        } else {
          showToast("No username to copy");
        }
      });

      // Copy Password Button
      const btnCopyPass = document.createElement("button");
      btnCopyPass.className = "btn-copy";
      btnCopyPass.textContent = "Copy Pass";
      btnCopyPass.addEventListener("click", async () => {
        btnCopyPass.disabled = true;
        try {
          const credResp = await sendExtensionMessage({
            action: "get_credential",
            payload: { entryId: entry.id },
          });

          if (credResp && credResp.success && credResp.data) {
            await navigator.clipboard.writeText(credResp.data.password);
            showToast("Password copied!");
          } else {
            showToast("Failed to retrieve password");
          }
        } catch (e) {
          showToast("Error: " + e.message);
        } finally {
          btnCopyPass.disabled = false;
        }
      });

      actions.appendChild(btnFill);
      actions.appendChild(btnCopyUser);
      actions.appendChild(btnCopyPass);

      card.appendChild(header);
      card.appendChild(actions);

      credentialsList.appendChild(card);
    });
  }

  // ── Event Handlers ─────────────────────────────────────────────────

  // Unlock form submission
  unlockForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pwd = unlockPassword.value;
    if (!pwd) return;

    unlockError.style.display = "none";
    const btnSubmit = document.getElementById("btn-unlock-submit");
    btnSubmit.disabled = true;
    btnSubmit.textContent = "Verifying...";

    try {
      const resp = await sendExtensionMessage({
        action: "unlock",
        payload: { password: pwd },
      });

      if (resp && resp.success) {
        showUnlockedState();
      } else {
        unlockError.textContent = resp.error || "Failed to unlock vault";
        unlockError.style.display = "block";
      }
    } catch (err) {
      unlockError.textContent = "Connection error: " + err.message;
      unlockError.style.display = "block";
    } finally {
      btnSubmit.disabled = false;
      btnSubmit.textContent = "Unlock";
    }
  });

  // Toggle unlock password visibility
  btnTogglePwd.addEventListener("click", () => {
    const isPassword = unlockPassword.type === "password";
    unlockPassword.type = isPassword ? "text" : "password";
  });

  // Lock button
  btnLock.addEventListener("click", async () => {
    try {
      await sendExtensionMessage({ action: "lock" });
      showLockedState();
      showToast("Vault locked");
    } catch (e) {
      console.error("Lock error:", e);
    }
  });

  // Search input handling
  let searchTimer = null;
  searchInput.addEventListener("input", () => {
    const query = searchInput.value.trim();
    btnClearSearch.style.display = query ? "block" : "none";

    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      if (query) {
        loadSearch(query);
      } else {
        renderCredentials(matchingEntries, "Matching Credentials");
      }
    }, 200);
  });

  btnClearSearch.addEventListener("click", () => {
    searchInput.value = "";
    btnClearSearch.style.display = "none";
    renderCredentials(matchingEntries, "Matching Credentials");
    searchInput.focus();
  });

  // Generator Drawer Toggle
  btnGenToggle.addEventListener("click", () => {
    const isVisible = genDrawer.style.display !== "none";
    genDrawer.style.display = isVisible ? "none" : "flex";
    if (!isVisible && !genOutput.value) {
      generatePassword();
    }
  });

  btnCloseGen.addEventListener("click", () => {
    genDrawer.style.display = "none";
  });

  genLengthSlider.addEventListener("input", () => {
    genLengthVal.textContent = genLengthSlider.value;
    generatePassword();
  });

  [genUpper, genLower, genDigits, genSymbols].forEach((chk) => {
    chk.addEventListener("change", generatePassword);
  });

  btnRegen.addEventListener("click", generatePassword);

  btnCopyGen.addEventListener("click", async () => {
    if (genOutput.value) {
      await navigator.clipboard.writeText(genOutput.value);
      showToast("Generated password copied!");
    }
  });

  // ── Add Credential Drawer Handling ─────────────────────────────────

  btnAddCred.addEventListener("click", () => {
    const isVisible = addDrawer.style.display !== "none";
    addDrawer.style.display = isVisible ? "none" : "flex";
    if (!isVisible) {
      genDrawer.style.display = "none";
      if (!addUrl.value && currentTabUrl && currentTabUrl.startsWith("http")) {
        addUrl.value = currentTabUrl;
      }
      if (!addTitle.value && currentTabDomain) {
        addTitle.value = currentTabDomain.charAt(0).toUpperCase() + currentTabDomain.slice(1);
      }
      addTitle.focus();
    }
  });

  btnCloseAdd.addEventListener("click", () => {
    addDrawer.style.display = "none";
  });

  btnCancelAdd.addEventListener("click", () => {
    addDrawer.style.display = "none";
    addForm.reset();
  });

  btnFillGenPwd.addEventListener("click", () => {
    generatePassword();
    addPassword.value = genOutput.value;
    addPassword.type = "text";
    showToast("Filled generated password");
  });

  addForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const title = addTitle.value.trim();
    const username = addUsername.value.trim();
    const password = addPassword.value;
    const url = addUrl.value.trim();

    if (!title || !password) return;

    const btnSubmit = document.getElementById("btn-submit-add-cred");
    btnSubmit.disabled = true;
    btnSubmit.textContent = "Saving...";

    try {
      const resp = await sendExtensionMessage({
        action: "save_credential",
        payload: { title, username, password, url },
      });

      if (resp && resp.success) {
        showToast(resp.data?.action === "updated" ? "Password updated!" : "Credential saved!");
        addDrawer.style.display = "none";
        addForm.reset();
        loadTabAndCredentials();
      } else {
        showToast("Error: " + (resp?.error || "Failed to save"));
      }
    } catch (err) {
      showToast("Save error: " + err.message);
    } finally {
      btnSubmit.disabled = false;
      btnSubmit.textContent = "Save";
    }
  });

  // ── Initialization ─────────────────────────────────────────────────
  checkStatus();
})();
