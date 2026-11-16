// Sentinel DLP - Content Script (ISOLATED World)
// Provides DOM-level prompt capture, in-page DLP modal enforcement, and background sync

console.log("[Sentinel DLP] Content script injected in ISOLATED world.");

let activePolicies = [];
let isBypassingNextSend = false;
let lastBlockedTimestamp = 0;

// Shannon Entropy calculation for detecting random tokens/secrets
function calculateEntropy(str) {
  const len = str.length;
  if (len === 0) return 0;
  const frequencies = {};
  for (const char of str) frequencies[char] = (frequencies[char] || 0) + 1;
  return Object.values(frequencies).reduce((sum, f) => {
    const p = f / len;
    return sum - p * Math.log2(p);
  }, 0);
}

// Mask secret sample for audit logging & UI (never exposes more than 4 characters total)
function maskSecret(str) {
  if (!str || typeof str !== "string") return "***";
  const len = str.length;
  if (len <= 4) return "*".repeat(len);
  if (len <= 8) return str[0] + "*".repeat(len - 2) + str.slice(-1);
  return str.slice(0, 2) + "*".repeat(Math.min(len - 4, 16)) + str.slice(-2);
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isDomainMatched(targetDomains, currentHostname) {
  if (!targetDomains || !Array.isArray(targetDomains) || targetDomains.length === 0) {
    return true;
  }
  const cleanCurrent = (currentHostname || window.location.hostname || "").toLowerCase();
  return targetDomains.some((d) => {
    if (!d || typeof d !== "string") return false;
    let clean = d.toLowerCase().replace(/^https?:\/\//, "").replace(/:\d+$/, "").replace(/\/.*$/, "").trim();
    if (clean.startsWith("*.")) {
      const rootDomain = clean.slice(2);
      return cleanCurrent === rootDomain || cleanCurrent.endsWith("." + rootDomain);
    }
    return cleanCurrent === clean;
  });
}

// Evaluate text against active DLP policies
function evaluatePrompt(text, currentHostname) {
  if (!text || typeof text !== "string") return null;

  for (const policy of activePolicies) {
    if (!isDomainMatched(policy.target_domains, currentHostname)) continue;

    // 1. Regex Detection
    if (policy.detection_type === "regex") {
      if (!policy.pattern || typeof policy.pattern !== "string") continue;
      try {
        const regex = new RegExp(policy.pattern, "gi");
        const match = regex.exec(text);
        if (match && match[0]?.length > 0) {
          return { policy, matchedText: match[0] };
        }
      } catch (err) {
        console.warn(`[Sentinel DLP] Invalid regex in policy "${policy.name}":`, err);
      }
    }

    // 2. Keyword Detection
    if (policy.detection_type === "keyword") {
      if (!policy.pattern || typeof policy.pattern !== "string") continue;
      const keywords = policy.pattern
        .split(",")
        .map((k) => k.trim())
        .filter(Boolean);

      for (const kw of keywords) {
        const idx = text.toLowerCase().indexOf(kw.toLowerCase());
        if (idx !== -1) {
          const actualMatch = text.slice(idx, idx + kw.length);
          return { policy, matchedText: actualMatch };
        }
      }
    }

    // 3. Shannon Entropy Detection
    if (policy.detection_type === "entropy") {
      const threshold = parseFloat(policy.pattern) || 4.5;
      const tokens = text
        .split(/[ \t\n\r,;:\"\'\`<>{}()[\]]+/)
        .map((w) => w.trim())
        .filter((w) => w.length >= 20 && !w.startsWith("http://") && !w.startsWith("https://"));

      for (const token of tokens) {
        if (calculateEntropy(token) >= threshold) {
          return { policy, matchedText: token };
        }
      }
    }
  }

  return null;
}

function redactText(fullText, matchedText, redaction) {
  const regex = new RegExp(escapeRegExp(matchedText), "gi");
  return fullText.replace(regex, redaction);
}

// Find the active prompt input / editor element on Gemini, ChatGPT, Claude, etc.
function findActiveEditor() {
  const active = document.activeElement;
  if (
    active &&
    (active.tagName === "TEXTAREA" ||
      active.tagName === "INPUT" ||
      active.isContentEditable ||
      active.getAttribute("role") === "textbox")
  ) {
    return active;
  }

  const selectors = [
    "rich-textarea .ql-editor",
    "rich-textarea [contenteditable='true']",
    ".ql-editor[contenteditable='true']",
    "rich-textarea [role='textbox']",
    "rich-textarea",
    "#prompt-textarea",
    "div[contenteditable='true'][role='textbox']",
    "div.ProseMirror[contenteditable='true']",
    "fieldset div[contenteditable='true']",
    "textarea",
    "[contenteditable='true']",
  ];

  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el && (el.offsetParent !== null || el.offsetHeight > 0 || el.offsetWidth > 0)) {
      return el;
    }
  }

  return active || document.body;
}

// Get the text from the prompt editor
function getPromptText(el) {
  if (!el) el = findActiveEditor();
  if (!el) return "";

  const editor = el.closest
    ? el.closest("[contenteditable='true'], rich-textarea, .ql-editor") || el
    : el;

  if (editor.tagName === "TEXTAREA" || editor.tagName === "INPUT") {
    return editor.value || "";
  }

  const editableChild = editor.querySelector?.("[contenteditable='true'], .ql-editor, [role='textbox']");
  if (editableChild) {
    return editableChild.innerText || editableChild.textContent || "";
  }

  return editor.innerText || editor.textContent || editor.value || "";
}

// Update the prompt text in the editor (for redaction)
function setPromptText(el, newText) {
  if (!el) el = findActiveEditor();
  if (!el) return;

  if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
    el.value = newText;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  } else {
    const editor = el.isContentEditable ? el : el.querySelector?.("[contenteditable='true'], .ql-editor") || el;
    editor.focus();
    editor.innerText = newText;
    editor.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: newText }));
    editor.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

// Check if a target element is a Send / Submit button
function findSendButtonFromTarget(target) {
  if (!target || !target.closest) return null;
  const btn = target.closest("button, [role='button']");
  if (!btn) return null;

  const ariaLabel = (btn.getAttribute("aria-label") || "").toLowerCase();
  const testId = (btn.getAttribute("data-testid") || "").toLowerCase();
  const className = (btn.className || "").toString().toLowerCase();
  const title = (btn.getAttribute("title") || "").toLowerCase();
  const jsname = btn.getAttribute("jsname") || "";

  if (
    testId.includes("send") ||
    testId.includes("submit") ||
    ariaLabel.includes("send") ||
    ariaLabel.includes("отправить") ||
    ariaLabel.includes("submit") ||
    ariaLabel.includes("yuborish") ||
    title.includes("send") ||
    title.includes("отправить") ||
    title.includes("submit") ||
    className.includes("send-button") ||
    className.includes("submit-button") ||
    jsname === "Qx7uuf"
  ) {
    return btn;
  }

  // Button inside chat area with an icon
  const chatContainer = btn.closest(
    "rich-textarea, .input-area, .chat-input-area, [class*='input-area'], [class*='chat-input'], form, fieldset",
  );
  if (chatContainer && (btn.querySelector("svg, mat-icon") || btn.type === "submit")) {
    return btn;
  }

  return null;
}

// Search for the Send button on the page
function findSendButton() {
  const selectors = [
    'button[aria-label*="Send" i]',
    'button[aria-label*="Отправить" i]',
    'button[data-testid="send-button"]',
    'button[jsname="Qx7uuf"]',
    'button.send-button',
    '.send-button-container button',
    'fieldset button:last-child',
    'button[type="submit"]',
  ];

  for (const sel of selectors) {
    const btn = document.querySelector(sel);
    if (btn && (btn.offsetParent !== null || btn.offsetHeight > 0)) {
      return btn;
    }
  }
  return null;
}

function triggerSend(editor) {
  const sendBtn = findSendButton();
  if (sendBtn) {
    sendBtn.click();
  } else if (editor) {
    editor.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        keyCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true,
      }),
    );
  }
}

// Report incident to background service worker
function reportIncident(policy, matchedText, actionTaken, promptContent) {
  console.warn(
    `[Sentinel DLP] Violation Detected: Policy "${policy.name}" (${actionTaken}) on ${window.location.hostname}`,
  );
  try {
    chrome.runtime.sendMessage(
      {
        type: "REPORT_INCIDENT",
        payload: {
          dlp_policy_id: policy.id,
          domain: window.location.hostname,
          action_taken: actionTaken,
          masked_sample: maskSecret(matchedText),
          prompt_content: promptContent || "",
        },
      },
      (res) => {
        if (chrome.runtime.lastError) {
          // Suppress error if background service worker is waking up
        }
      },
    );
  } catch (err) {
    console.warn("[Sentinel DLP] Failed to relay incident to background:", err);
  }
}

// Display in-page DLP Modal (Shield banner overlay)
function showDlpModal(options) {
  const { type = "block", policy, matchedText, editor, onProceed, onCancel } = options;

  // Remove existing modal if open
  const existing = document.getElementById("sentinel-dlp-modal-root");
  if (existing) existing.remove();

  const isBlock = type === "block";
  const primaryColor = isBlock ? "#ef4444" : "#f59e0b";
  const primaryLight = isBlock ? "rgba(239, 68, 68, 0.15)" : "rgba(245, 158, 11, 0.15)";
  const titleText = isBlock ? "Sentinel DLP — Prompt Blocked" : "Sentinel DLP — Security Warning";
  const actionLabel = isBlock ? "BLOCKED" : "WARNING";
  const descText = isBlock
    ? "Your prompt cannot be sent because it contains sensitive data that violates organizational data protection policies."
    : "Sensitive data was detected in your prompt. Submitting this information to external AI services may violate compliance rules.";

  const modalRoot = document.createElement("div");
  modalRoot.id = "sentinel-dlp-modal-root";
  modalRoot.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    background: rgba(15, 23, 42, 0.75) !important;
    backdrop-filter: blur(4px) !important;
    -webkit-backdrop-filter: blur(4px) !important;
    z-index: 2147483647 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    color: #f8fafc !important;
    box-sizing: border-box !important;
  `;

  const modalBox = document.createElement("div");
  modalBox.style.cssText = `
    background: #1e293b !important;
    border: 1px solid #334155 !important;
    border-radius: 14px !important;
    width: 92% !important;
    max-width: 500px !important;
    padding: 24px !important;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6) !important;
    animation: sentinelSlideIn 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    box-sizing: border-box !important;
  `;

  modalBox.innerHTML = `
    <style>
      @keyframes sentinelSlideIn {
        from { opacity: 0; transform: scale(0.95) translateY(10px); }
        to { opacity: 1; transform: scale(1) translateY(0); }
      }
    </style>
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;">
      <div style="display: flex; align-items: center; gap: 12px;">
        <div style="width: 40px; height: 40px; border-radius: 10px; background: ${primaryLight}; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="${primaryColor}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            ${isBlock ? '<line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>' : '<line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'}
          </svg>
        </div>
        <div>
          <div style="font-weight: 700; font-size: 16px; color: #f8fafc; line-height: 1.2;">${titleText}</div>
          <div style="font-size: 12px; color: #94a3b8; margin-top: 2px;">In-Browser Data Loss Prevention</div>
        </div>
      </div>
      <span style="font-size: 11px; font-weight: 700; padding: 4px 8px; border-radius: 6px; background: ${primaryLight}; color: ${primaryColor}; border: 1px solid ${primaryColor}40; letter-spacing: 0.05em;">
        ${actionLabel}
      </span>
    </div>

    <p style="font-size: 13.5px; color: #cbd5e1; line-height: 1.5; margin: 0 0 16px 0;">
      ${descText}
    </p>

    <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px 14px; margin-bottom: 20px; font-size: 13px;">
      <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
        <span style="color: #94a3b8;">Triggered Policy:</span>
        <span style="font-weight: 600; color: #f1f5f9;">${policy.name || "Default DLP Rule"}</span>
      </div>
      <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
        <span style="color: #94a3b8;">Severity:</span>
        <span style="font-weight: 600; color: ${primaryColor}; text-transform: uppercase;">${policy.severity || "HIGH"}</span>
      </div>
      <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
        <span style="color: #94a3b8;">Protected Domain:</span>
        <span style="font-family: monospace; color: #e2e8f0;">${window.location.hostname}</span>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px dashed #334155; padding-top: 8px; margin-top: 8px;">
        <span style="color: #94a3b8;">Masked Sample:</span>
        <span style="font-family: monospace; font-size: 12.5px; background: #1e293b; padding: 2px 8px; border-radius: 4px; color: #f43f5e; border: 1px solid #475569;">
          ${maskSecret(matchedText)}
        </span>
      </div>
    </div>

    <div style="display: flex; justify-content: flex-end; gap: 10px;" id="sentinel-modal-actions">
      ${
        isBlock
          ? `<button id="sentinel-btn-dismiss" style="
              background: #ef4444;
              color: #ffffff;
              border: none;
              border-radius: 8px;
              padding: 9px 18px;
              font-size: 13.5px;
              font-weight: 600;
              cursor: pointer;
              transition: background 0.15s ease;
            ">Dismiss & Edit Prompt</button>`
          : `<button id="sentinel-btn-cancel" style="
              background: #334155;
              color: #f8fafc;
              border: 1px solid #475569;
              border-radius: 8px;
              padding: 9px 16px;
              font-size: 13.5px;
              font-weight: 500;
              cursor: pointer;
            ">Cancel</button>
            <button id="sentinel-btn-proceed" style="
              background: #f59e0b;
              color: #0f172a;
              border: none;
              border-radius: 8px;
              padding: 9px 16px;
              font-size: 13.5px;
              font-weight: 600;
              cursor: pointer;
            ">Send Anyway</button>`
      }
    </div>
  `;

  modalRoot.appendChild(modalBox);
  (document.body || document.documentElement).appendChild(modalRoot);

  const cleanup = () => {
    modalRoot.remove();
    document.removeEventListener("keydown", onKeyDownEsc);
    if (editor && typeof editor.focus === "function") {
      try {
        editor.focus();
      } catch {}
    }
  };

  const onKeyDownEsc = (e) => {
    if (e.key === "Escape") {
      cleanup();
      if (!isBlock && onCancel) onCancel();
    }
  };
  document.addEventListener("keydown", onKeyDownEsc);

  if (isBlock) {
    const btnDismiss = modalBox.querySelector("#sentinel-btn-dismiss");
    if (btnDismiss) {
      btnDismiss.addEventListener("click", () => cleanup());
      btnDismiss.focus();
    }
  } else {
    const btnCancel = modalBox.querySelector("#sentinel-btn-cancel");
    if (btnCancel) {
      btnCancel.addEventListener("click", () => {
        cleanup();
        if (onCancel) onCancel();
      });
    }
    const btnProceed = modalBox.querySelector("#sentinel-btn-proceed");
    if (btnProceed) {
      btnProceed.addEventListener("click", () => {
        cleanup();
        if (onProceed) onProceed();
      });
    }
  }
}

// Handle submission attempts (Enter key or Send button click)
function handleSubmissionAttempt(e, inputEl) {
  if (isBypassingNextSend) return;

  const now = Date.now();
  if (now - lastBlockedTimestamp < 350) {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
      if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    }
    return false;
  }

  const editor = inputEl || findActiveEditor();
  const text = getPromptText(editor);
  if (!text || text.trim().length === 0) return;

  const currentHost = window.location.hostname;
  const violation = evaluatePrompt(text, currentHost);
  if (!violation) return;

  const { policy, matchedText } = violation;

  if (policy.action === "block") {
    lastBlockedTimestamp = Date.now();
    if (e) {
      e.preventDefault();
      e.stopPropagation();
      if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    }
    reportIncident(policy, matchedText, "block", text);
    showDlpModal({
      type: "block",
      policy,
      matchedText,
      editor,
    });
    return false;
  }

  if (policy.action === "warn") {
    lastBlockedTimestamp = Date.now();
    if (e) {
      e.preventDefault();
      e.stopPropagation();
      if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    }
    showDlpModal({
      type: "warn",
      policy,
      matchedText,
      editor,
      onProceed: () => {
        reportIncident(policy, matchedText, "warn_bypassed", text);
        isBypassingNextSend = true;
        triggerSend(editor);
        setTimeout(() => {
          isBypassingNextSend = false;
        }, 600);
      },
      onCancel: () => {
        reportIncident(policy, matchedText, "warn_blocked", text);
      },
    });
    return false;
  }

  if (policy.action === "redact") {
    const redactedText = redactText(text, matchedText, `[REDACTED:${policy.name}]`);
    setPromptText(editor, redactedText);
    reportIncident(policy, matchedText, "redact", text);
  }

  if (policy.action === "log") {
    reportIncident(policy, matchedText, "log", text);
  }
}

// DOM Capture Listeners (Window capture-phase executes BEFORE any page listeners)
window.addEventListener(
  "keydown",
  (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      handleSubmissionAttempt(e);
    }
  },
  true,
);

window.addEventListener(
  "click",
  (e) => {
    if (findSendButtonFromTarget(e.target)) {
      handleSubmissionAttempt(e);
    }
  },
  true,
);

window.addEventListener(
  "pointerdown",
  (e) => {
    if (findSendButtonFromTarget(e.target)) {
      handleSubmissionAttempt(e);
    }
  },
  true,
);

window.addEventListener(
  "submit",
  (e) => {
    handleSubmissionAttempt(e);
  },
  true,
);

// Storage & Policy Sync
async function pushPoliciesToPage() {
  try {
    const { dlp_policies = [] } = await chrome.storage.local.get("dlp_policies");
    activePolicies = Array.isArray(dlp_policies) ? dlp_policies : [];
    console.log(
      `[Sentinel DLP] Loaded ${activePolicies.length} active policies from storage:`,
      activePolicies.map((p) => `${p.name} [${p.action.toUpperCase()}]`),
    );

    window.postMessage(
      {
        source: "SENTINEL_EXT",
        type: "POLICIES_UPDATED",
        policies: activePolicies,
      },
      "*",
    );
  } catch (err) {
    console.error("[Sentinel DLP] Error reading policies from storage:", err);
  }
}

// Initial push on document start
pushPoliciesToPage();

// Instant sync when tab gains focus or becomes visible
let lastSyncCheck = 0;
function requestBackgroundSync() {
  const now = Date.now();
  if (now - lastSyncCheck < 2500) return; // Throttle to at most once per 2.5s
  lastSyncCheck = now;

  try {
    chrome.runtime.sendMessage({ type: "SYNC_POLICIES_NOW" }, () => {
      if (chrome.runtime.lastError) {}
    });
  } catch {}
}

window.addEventListener("focus", requestBackgroundSync);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    requestBackgroundSync();
  }
});

// Trigger immediate sync check on injection
requestBackgroundSync();

// Listen for updates from background sync
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.dlp_policies) {
    activePolicies = Array.isArray(changes.dlp_policies.newValue) ? changes.dlp_policies.newValue : [];
    pushPoliciesToPage();
  }
});

// Relay messages between MAIN world interceptor and background
window.addEventListener("message", (event) => {
  if (event.source !== window || !event.data || typeof event.data !== "object") {
    return;
  }

  if (event.data.source === "SENTINEL_PAGE" && event.data.type === "REQUEST_POLICIES") {
    pushPoliciesToPage();
  }

  if (event.data.source === "SENTINEL_PAGE" && event.data.type === "DLP_INCIDENT") {
    try {
      chrome.runtime.sendMessage(
        {
          type: "REPORT_INCIDENT",
          payload: event.data.payload,
        },
        () => {
          if (chrome.runtime.lastError) {}
        },
      );
    } catch (err) {
      console.warn("[Sentinel DLP] Failed to relay incident to background:", err);
    }
  }

  if (event.data.source === "SENTINEL_PAGE" && event.data.type === "SHOW_MODAL") {
    showDlpModal(event.data.payload);
  }
});
