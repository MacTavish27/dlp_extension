// Sentinel In-Browser DLP - Interceptor Script (MAIN World)
// Hooks fetch and XMLHttpRequest to monitor and enforce DLP policies at network level

(() => {
  console.log("[Sentinel DLP] Interceptor loaded in MAIN world.");

  let activePolicies = [];
  let lastPoliciesSignature = "";

  // Request policies from ISOLATED content script
  function requestPolicies() {
    window.postMessage({ source: "SENTINEL_PAGE", type: "REQUEST_POLICIES" }, "*");
  }

  // Listen for policies pushed from content script
  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data || typeof event.data !== "object") {
      return;
    }

    if (
      event.data.source === "SENTINEL_EXT" &&
      event.data.type === "POLICIES_UPDATED"
    ) {
      if (Array.isArray(event.data.policies)) {
        activePolicies = event.data.policies;
        const signature = JSON.stringify(activePolicies);
        if (signature !== lastPoliciesSignature) {
          lastPoliciesSignature = signature;
          console.log(
            `[Sentinel DLP] Active policies updated (${activePolicies.length} loaded):`,
            activePolicies.map((p) => `${p.name} [${p.action.toUpperCase()}]`),
          );
        }
      }
    }
  });

  // Pull policies on startup with staggered retries for document_start timing
  requestPolicies();
  setTimeout(requestPolicies, 50);
  setTimeout(requestPolicies, 200);
  setTimeout(requestPolicies, 1000);

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

  // Mask secret sample for audit logging
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

  // Extract user text strings from JSON, skipping internal schema metadata
  function extractTextFragments(data) {
    const texts = [];
    function recurse(val) {
      if (typeof val === "string") {
        texts.push(val);
        // Check if string contains nested serialized JSON (common in Gemini/Google RPC payloads)
        if (
          (val.startsWith("[") && val.endsWith("]")) ||
          (val.startsWith("{") && val.endsWith("}"))
        ) {
          try {
            const nested = JSON.parse(val);
            recurse(nested);
          } catch {}
        }
      } else if (Array.isArray(val)) {
        for (const item of val) recurse(item);
      } else if (val && typeof val === "object") {
        for (const [k, v] of Object.entries(val)) {
          if (["id", "model", "action", "message_id", "parent_message_id", "event"].includes(k)) {
            continue;
          }
          recurse(v);
        }
      }
    }

    try {
      const parsed = JSON.parse(data);
      recurse(parsed);
      return { isJson: true, parsed, texts };
    } catch {
      // If not JSON, check if it's URL-encoded (e.g. Gemini batchexecute f.req=...)
      let raw = data;
      try {
        if (typeof data === "string" && (data.includes("%") || data.includes("+"))) {
          raw = decodeURIComponent(data.replace(/\+/g, " "));
        }
      } catch {}

      // If payload is a form URL-encoded string containing f.req, extract the nested structure
      if (typeof raw === "string" && raw.includes("f.req=")) {
        try {
          const match = raw.match(/f\.req=([^&]+)/);
          if (match && match[1]) {
            const parsedReq = JSON.parse(match[1]);
            recurse(parsedReq);
          }
        } catch {}
      }

      return { isJson: false, parsed: null, texts: [data, raw, ...texts] };
    }
  }

  function evaluatePayload(bodyStr, currentHostname) {
    if (!bodyStr || typeof bodyStr !== "string") return null;
    const { texts } = extractTextFragments(bodyStr);

    for (const policy of activePolicies) {
      if (!isDomainMatched(policy.target_domains, currentHostname)) continue;

      for (const text of texts) {
        if (!text || typeof text !== "string") continue;

        // Regex Detection
        if (policy.detection_type === "regex") {
          if (!policy.pattern || typeof policy.pattern !== "string") continue;
          try {
            const regex = new RegExp(policy.pattern, "gi");
            const match = regex.exec(text);
            if (match && match[0]?.length > 0) {
              return { policy, matchedText: match[0] };
            }
          } catch (err) {
            console.warn(`[Sentinel DLP Net] Invalid regex in policy "${policy.name}":`, err);
          }
        }

        // Keyword Detection (case-insensitive with exact casing extraction)
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

        // Shannon Entropy Detection (clean tokens, length >= 20)
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
    }
    return null;
  }

  // Redaction helper that preserves JSON structure and replaces text case-insensitively
  function redactPayload(bodyStr, matchedText, redaction) {
    const rawRegex = new RegExp(escapeRegExp(matchedText), "gi");
    const encodedRegex = new RegExp(escapeRegExp(encodeURIComponent(matchedText)), "gi");

    try {
      const obj = JSON.parse(bodyStr);
      function walk(val) {
        if (typeof val === "string") {
          return val.replace(rawRegex, redaction);
        }
        if (Array.isArray(val)) {
          return val.map(walk);
        }
        if (val && typeof val === "object") {
          const out = {};
          for (const [k, v] of Object.entries(val)) {
            out[k] = walk(v);
          }
          return out;
        }
        return val;
      }
      return JSON.stringify(walk(obj));
    } catch {
      return bodyStr
        .replace(rawRegex, redaction)
        .replace(encodedRegex, encodeURIComponent(redaction));
    }
  }

  function reportIncident(policy, matchedText, actionTaken, promptContent) {
    console.warn(
      `[Sentinel DLP Net] Violation Detected: Policy "${policy.name}" (${actionTaken}) on ${window.location.hostname}`,
    );
    window.postMessage(
      {
        source: "SENTINEL_PAGE",
        type: "DLP_INCIDENT",
        payload: {
          dlp_policy_id: policy.id,
          domain: window.location.hostname,
          action_taken: actionTaken,
          masked_sample: maskSecret(matchedText),
          prompt_content: promptContent || "",
        },
      },
      "*",
    );
  }

  function showModalViaContentScript(policy, matchedText, action) {
    window.postMessage(
      {
        source: "SENTINEL_PAGE",
        type: "SHOW_MODAL",
        payload: {
          type: action === "warn" ? "warn" : "block",
          policy,
          matchedText,
        },
      },
      "*",
    );
  }

  // ==========================================
  // 1. Hook window.fetch
  // ==========================================
  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    try {
      let [resource, config] = args;
      let url = "";
      let method = "GET";
      let bodyStr = null;
      let isRequestInstance = false;

      if (typeof resource === "string") {
        url = resource;
        method = (config?.method || "GET").toUpperCase();
        if (typeof config?.body === "string") {
          bodyStr = config.body;
        } else if (config?.body instanceof URLSearchParams) {
          bodyStr = config.body.toString();
        } else if (config?.body instanceof Blob) {
          try {
            bodyStr = await config.body.text();
          } catch {}
        } else if (config?.body instanceof ArrayBuffer || config?.body instanceof Uint8Array) {
          try {
            bodyStr = new TextDecoder().decode(config.body);
          } catch {}
        } else if (config?.body instanceof FormData) {
          try {
            const parts = [];
            for (const [k, v] of config.body.entries()) {
              if (typeof v === "string") parts.push(v);
            }
            bodyStr = parts.join("\n");
          } catch {}
        }
      } else if (resource instanceof URL) {
        url = resource.toString();
        method = (config?.method || "GET").toUpperCase();
        if (typeof config?.body === "string") {
          bodyStr = config.body;
        } else if (config?.body instanceof URLSearchParams) {
          bodyStr = config.body.toString();
        } else if (config?.body instanceof Blob) {
          try {
            bodyStr = await config.body.text();
          } catch {}
        } else if (config?.body instanceof ArrayBuffer || config?.body instanceof Uint8Array) {
          try {
            bodyStr = new TextDecoder().decode(config.body);
          } catch {}
        }
      } else if (resource instanceof Request) {
        isRequestInstance = true;
        url = resource.url;
        method = (config?.method || resource.method || "GET").toUpperCase();
        if (typeof config?.body === "string") {
          bodyStr = config.body;
        } else {
          try {
            const cloned = resource.clone();
            bodyStr = await cloned.text();
          } catch {}
        }
      }

      // Ignore standard telemetry/metrics endpoints
      const isTelemetry = /\/(ces\/v1\/t|datadog|statsig|sentry|telemetry|browser-metrics)/i.test(url);

      if (method === "POST" && bodyStr && !isTelemetry) {
        const violation = evaluatePayload(bodyStr, window.location.hostname);

        if (violation) {
          const { policy, matchedText } = violation;

          if (policy.action === "block") {
            reportIncident(policy, matchedText, "block", bodyStr);
            showModalViaContentScript(policy, matchedText, "block");
            return Promise.reject(new Error(`Blocked by Sentinel DLP: ${policy.name}`));
          }

          if (policy.action === "warn") {
            const proceed = confirm(
              `[Sentinel DLP Warning] Policy "${policy.name}" detected sensitive data (${maskSecret(matchedText)}). Send anyway?`,
            );
            const actionTaken = proceed ? "warn_bypassed" : "warn_blocked";
            reportIncident(policy, matchedText, actionTaken, bodyStr);

            if (!proceed) {
              return Promise.reject(
                new Error("Cancelled by user via Sentinel DLP"),
              );
            }
          }

          if (policy.action === "redact") {
            reportIncident(policy, matchedText, "redact", bodyStr);
            const modifiedBody = redactPayload(
              bodyStr,
              matchedText,
              `[REDACTED:${policy.name}]`,
            );

            if (isRequestInstance) {
              const reqHeaders = new Headers(resource.headers);
              reqHeaders.delete("content-length");
              args[0] = new Request(resource, {
                body: modifiedBody,
                headers: reqHeaders,
              });
            } else {
              config = config || {};
              config.body = modifiedBody;
              if (config.headers) {
                if (config.headers instanceof Headers) {
                  config.headers.delete("content-length");
                } else if (typeof config.headers === "object") {
                  delete config.headers["content-length"];
                  delete config.headers["Content-Length"];
                }
              }
              args[1] = config;
            }
          }

          if (policy.action === "log") {
            reportIncident(policy, matchedText, "log", bodyStr);
          }
        }
      }
    } catch (err) {
      if (err.message && err.message.includes("Sentinel DLP")) {
        throw err;
      }
      console.error("[Sentinel DLP Fetch] Error:", err);
    }

    return originalFetch.apply(this, args);
  };

  // ==========================================
  // 2. Hook XMLHttpRequest
  // ==========================================
  const originalXhrOpen = XMLHttpRequest.prototype.open;
  const originalXhrSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._sentinelMethod = method;
    this._sentinelUrl = url;
    return originalXhrOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (body) {
    try {
      const method = (this._sentinelMethod || "GET").toUpperCase();
      const url = typeof this._sentinelUrl === "string" ? this._sentinelUrl : "";
      const isTelemetry = /\/(ces\/v1\/t|datadog|statsig|sentry|telemetry|browser-metrics)/i.test(url);

      if (method === "POST" && body && !isTelemetry) {
        let bodyText = "";
        if (typeof body === "string") {
          bodyText = body;
        } else if (body instanceof URLSearchParams) {
          bodyText = body.toString();
        } else if (body instanceof ArrayBuffer || body instanceof Uint8Array) {
          try {
            bodyText = new TextDecoder().decode(body);
          } catch {}
        } else if (body instanceof FormData) {
          try {
            const parts = [];
            for (const [k, v] of body.entries()) {
              if (typeof v === "string") parts.push(v);
            }
            bodyText = parts.join("\n");
          } catch {}
        }

        if (bodyText) {
          const violation = evaluatePayload(bodyText, window.location.hostname);

          if (violation) {
            const { policy, matchedText } = violation;

            if (policy.action === "block") {
              reportIncident(policy, matchedText, "block", bodyText);
              showModalViaContentScript(policy, matchedText, "block");
              throw new Error(`Blocked by Sentinel DLP: ${policy.name}`);
            }

            if (policy.action === "warn") {
              const proceed = confirm(
                `[Sentinel DLP Warning] Policy "${policy.name}" detected sensitive data (${maskSecret(matchedText)}). Send anyway?`,
              );
              const actionTaken = proceed ? "warn_bypassed" : "warn_blocked";
              reportIncident(policy, matchedText, actionTaken, bodyText);

              if (!proceed) {
                throw new Error("Cancelled by user via Sentinel DLP");
              }
            }

            if (policy.action === "redact") {
              reportIncident(policy, matchedText, "redact", bodyText);
              if (typeof body === "string") {
                body = redactPayload(
                  body,
                  matchedText,
                  `[REDACTED:${policy.name}]`,
                );
              }
            }

            if (policy.action === "log") {
              reportIncident(policy, matchedText, "log", bodyText);
            }
          }
        }
      }
    } catch (err) {
      if (err.message && err.message.includes("Sentinel DLP")) {
        throw err;
      }
      console.error("[Sentinel DLP XHR] Error:", err);
    }

    return originalXhrSend.call(this, body);
  };
})();
