const API_BASE = "http://127.0.0.1:8000/api/v1/dlp";

async function getOrCreateUserId() {
  const { dlp_user_id } = await chrome.storage.local.get("dlp_user_id");
  if (dlp_user_id) return dlp_user_id;

  const newId = `user_${crypto.randomUUID().slice(0, 12)}`;
  await chrome.storage.local.set({ dlp_user_id: newId });
  return newId;
}

async function syncPolicies() {
  try {
    const res = await fetch(`${API_BASE}/policies`);
    if (!res.ok) {
      console.warn(`[Sentinel DLP Background] Policy sync failed. Server returned HTTP ${res.status}`);
      return false;
    }

    const data = await res.json();
    if (data && Array.isArray(data.policies)) {
      const { dlp_policies_version: currentVersion } = await chrome.storage.local.get("dlp_policies_version");

      if (data.version && data.version === currentVersion) {
        // Policies already up to date
        return true;
      }

      await chrome.storage.local.set({
        dlp_policies: data.policies,
        dlp_policies_version: data.version || null,
        dlp_last_synced: Date.now(),
      });
      console.log(`[Sentinel DLP Background] Policies updated to version "${data.version}" (${data.policies.length} policies):`, data.policies);
      return true;
    } else {
      console.warn("[Sentinel DLP Background] Policy sync response was not a valid policy list:", data);
      return false;
    }
  } catch (err) {
    console.error("[Sentinel DLP Background] Policy sync failed:", err);
    return false;
  }
}

// Setup alarms and initial sync on installation/update
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[Sentinel DLP Background] Extension installed/updated.");
  await getOrCreateUserId();
  chrome.alarms.create("syncPolicies", { periodInMinutes: 1 });
  await syncPolicies();
});

// Sync on browser startup
chrome.runtime.onStartup.addListener(async () => {
  chrome.alarms.create("syncPolicies", { periodInMinutes: 1 });
  await syncPolicies();
});

// Periodic alarm trigger (every 1 minute for near real-time sync)
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "syncPolicies") {
    syncPolicies();
  }
});

// Sync when an AI service tab finishes loading or receives navigation
if (chrome.tabs && chrome.tabs.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
      const isAiSite = /(gemini\.google\.com|chatgpt\.com|claude\.ai)/i.test(tab.url);
      if (isAiSite) {
        syncPolicies();
      }
    }
  });
}

// Listen for incident reports & on-demand sync requests from content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SYNC_POLICIES_NOW") {
    syncPolicies().then((success) => sendResponse({ success }));
    return true;
  }

  if (msg.type === "REPORT_INCIDENT") {
    (async () => {
      try {
        const userId = await getOrCreateUserId();
        const payload = {
          user_identifier: userId,
          ...msg.payload,
        };
        console.log("[Sentinel DLP Background] Relaying incident to server:", payload);

        const res = await fetch(`${API_BASE}/incidents`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          console.error(`[Sentinel DLP Background] Failed to log incident. Server responded with HTTP ${res.status}`);
          sendResponse({ success: false, status: res.status });
          return;
        }

        const result = await res.json();
        console.log("[Sentinel DLP Background] Incident logged successfully:", result);
        sendResponse({ success: true, result });
      } catch (err) {
        console.error("[Sentinel DLP Background] Failed to log incident:", err);
        sendResponse({ success: false, error: err.message });
      }
    })();

    return true; // Keep the message channel open for async response
  }
});
