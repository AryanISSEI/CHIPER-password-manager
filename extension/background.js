/**
 * Cipher — Background Service Worker (Google Chrome Manifest V3)
 *
 * Manages the native messaging connection to the desktop Cipher app.
 * Acts as the bridge between the popup/content scripts and the zero-knowledge vault.
 *
 * Protocol:
 *   Extension → Native Host:  { action: "...", payload: { ... } }
 *   Native Host → Extension:  { success: bool, data: { ... }, error?: string }
 */

const NATIVE_HOST_NAME = "com.cipher.password_manager";

let nativePort = null;
let pendingRequests = new Map();  // requestId → { resolve, reject }
let requestCounter = 0;
let isUnlocked = false;

// ── Native Port Lifecycle ────────────────────────────────────────────

function connectNativeHost() {
  if (nativePort) return nativePort;

  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    nativePort.onMessage.addListener((response) => {
      const { requestId, success, data, error } = response;

      if (requestId && pendingRequests.has(requestId)) {
        const { resolve, reject } = pendingRequests.get(requestId);
        pendingRequests.delete(requestId);

        if (success) {
          resolve(data);
        } else {
          reject(new Error(error || "Unknown error from native host"));
        }
      }

      // Update lock state
      if (response.action === "status") {
        isUnlocked = data?.unlocked || false;
        persistLockState(isUnlocked);
      }
    });

    nativePort.onDisconnect.addListener((port) => {
      const lastError = chrome.runtime.lastError?.message || port.error?.message;
      console.warn("Cipher native host disconnected:", lastError);
      nativePort = null;
      isUnlocked = false;
      persistLockState(false);

      // Reject all pending requests
      for (const [id, { reject }] of pendingRequests) {
        reject(new Error(lastError || "Native host disconnected"));
      }
      pendingRequests.clear();
    });

    return nativePort;
  } catch (err) {
    console.error("Failed to connect to Cipher native host:", err);
    nativePort = null;
    return null;
  }
}

function persistLockState(unlocked) {
  if (chrome.storage && chrome.storage.session) {
    chrome.storage.session.set({ isUnlocked: unlocked }).catch(() => {});
  }
}

function sendNativeMessage(action, payload = {}) {
  return new Promise((resolve, reject) => {
    const port = connectNativeHost();
    if (!port) {
      reject(new Error(
        "Cannot connect to Cipher desktop app. Is the native host registered?"
      ));
      return;
    }

    const requestId = `req_${++requestCounter}_${Date.now()}`;
    pendingRequests.set(requestId, { resolve, reject });

    // Auto-timeout after 10 seconds
    const timer = setTimeout(() => {
      if (pendingRequests.has(requestId)) {
        pendingRequests.delete(requestId);
        reject(new Error("Request timed out"));
      }
    }, 10000);

    // Wrap resolve/reject to clear timeout
    const originalResolve = resolve;
    const originalReject = reject;
    pendingRequests.set(requestId, {
      resolve: (data) => {
        clearTimeout(timer);
        originalResolve(data);
      },
      reject: (err) => {
        clearTimeout(timer);
        originalReject(err);
      },
    });

    try {
      port.postMessage({ requestId, action, payload });
    } catch (postErr) {
      clearTimeout(timer);
      pendingRequests.delete(requestId);
      reject(postErr);
    }
  });
}

// ── Message Handler (from popup & content scripts) ───────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((response) => sendResponse(response))
    .catch((err) => sendResponse({ success: false, error: err.message }));

  // Return true to keep message port open for asynchronous sendResponse
  return true;
});

async function handleMessage(message, sender) {
  const { action, payload } = message || {};

  switch (action) {
    case "ping":
      return { alive: true, unlocked: isUnlocked };

    case "unlock":
      try {
        const data = await sendNativeMessage("unlock", payload);
        isUnlocked = true;
        persistLockState(true);
        return { success: true, data };
      } catch (err) {
        return { success: false, error: err.message };
      }

    case "lock":
      try {
        await sendNativeMessage("lock");
        isUnlocked = false;
        persistLockState(false);
        return { success: true };
      } catch (err) {
        return { success: false, error: err.message };
      }

    case "search":
      try {
        const data = await sendNativeMessage("search", payload);
        return { success: true, data };
      } catch (err) {
        return { success: false, error: err.message };
      }

    case "get_entries_for_url":
      try {
        const data = await sendNativeMessage("get_entries_for_url", {
          url: payload?.url,
        });
        return { success: true, data };
      } catch (err) {
        return { success: false, error: err.message };
      }

    case "get_credential":
      try {
        const data = await sendNativeMessage("get_credential", {
          entryId: payload?.entryId,
        });
        return { success: true, data };
      } catch (err) {
        return { success: false, error: err.message };
      }

    case "autofill":
      try {
        const tabs = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });
        if (!tabs || tabs.length === 0) {
          return { success: false, error: "No active tab" };
        }
        const resp = await chrome.tabs.sendMessage(tabs[0].id, {
          action: "fill_credential",
          payload: payload,
        });
        return { success: true, data: resp };
      } catch (err) {
        return { success: false, error: err.message };
      }

    case "save_credential":
      try {
        const data = await sendNativeMessage("save_entry", payload);
        return { success: true, data };
      } catch (err) {
        return { success: false, error: err.message };
      }

    case "status":
      try {
        const data = await sendNativeMessage("status");
        isUnlocked = data?.unlocked || false;
        persistLockState(isUnlocked);
        return { success: true, data };
      } catch (err) {
        return { success: false, error: err.message };
      }

    default:
      return { success: false, error: `Unknown action: ${action}` };
  }
}

// ── Check vault status on startup ────────────────────────────────────

(async () => {
  try {
    const data = await sendNativeMessage("status");
    isUnlocked = data?.unlocked || false;
    persistLockState(isUnlocked);
  } catch {
    // Desktop app or host not running yet
    isUnlocked = false;
    persistLockState(false);
  }
})();
