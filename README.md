# Sentinel In-Browser DLP — Chrome Extension

In-browser Data Loss Prevention (DLP) extension for monitoring and enforcing sensitive data protection on AI prompt submissions (Google Gemini, OpenAI ChatGPT, Anthropic Claude).

## Features
- **DOM-Level Prompt Interception**: Captures submission attempts (`Enter` key and Send button clicks) in the capture phase before the AI website dispatches the prompt.
- **In-Page DLP Enforcement Modal**: Displays interactive block/warning dialogs with masked sensitive samples.
- **Network-Level Defense (Fallback)**: Hooks `fetch` and `XMLHttpRequest` to monitor and redact outbound payloads.
- **Incident Audit Logging**: Automatically relays incidents (user ID, target domain, matched policy, prompt excerpt, client IP) to the Laravel DLP backend API.
- **Real-Time Policy Hot-Reload**: Automatically detects policy updates on tab focus and refreshes in-memory policies without requiring an extension reload.

## Installation
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select this directory.
4. The extension will automatically sync policies from `http://127.0.0.1:8000/api/v1/dlp/policies`.
