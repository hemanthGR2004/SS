# SmartShield (Chrome Extension - Manifest V3)

Futuristic, neon-themed browser security assistant that helps you avoid harmful downloads and warns you when visiting suspicious websites.

## Install (Developer Mode)

1. Open `chrome://extensions` in Chrome.
2. Enable "Developer mode" (top right).
3. Click "Load unpacked" and select the folder: `C:\SmartShield`.
4. Pin SmartShield to the toolbar for quick access.

## Files

- `manifest.json` — MV3 config, permissions, background service worker, content script, action popup
- `background.js` — Service worker: download/site detection, logging, profile, whitelist, badge, messaging
- `content.js` — UI injection: site banner, download modal, link hover tooltips
- `popup.html` / `popup.css` / `popup.js` — Neon dashboard UI (Downloads | Sites | Settings), charts & logs
- `icons/` — Neon shield SVG icons

## Features

- Download Monitoring
  - Listens to `chrome.downloads.onCreated`
  - Extracts filename, URL, MIME, size, startTime
  - If MIME missing, infers via file extension into categories: Document, Media, Executable, Archive, Other
  - Heuristics:
    - Executable → +2
    - Executable + size < 50KB → +2
    - First-time domain → +1
    - Rare file type (<10% of profile history) → +1
    - If recent suspicious site → score ×2
  - If score ≥ 2 → content modal with actions: Cancel, Ignore, Whitelist
  - Logs to `downloadsLog` (max 500)
  - Updates adaptive profile: `fileTypeCounts`, `domainCounts`

- Suspicious Site Detection
  - Listens to `chrome.webNavigation.onCompleted`
  - Heuristics:
    - First-time domain → +1
    - Suspicious TLD (.zip, .tk, .xyz, .gq, .cf) → +2
    - Long hostname > 30 chars → +1
    - Punycode (xn--) → +2
    - Mixed Unicode → +2
  - If score ≥ 2 → log to `siteLog` and show neon banner
  - Respects `whitelist` (in `chrome.storage.sync`)

- Link Hover Tooltips
  - On `<a>` hover, compare link text vs hostname
  - If mismatch for common brands or suspicious TLD, show neon tooltip

- Toolbar Badge
  - Red `!` for high risk; Yellow `?` for unusual
  - Glowing pulse effect; clears after safe activity

- Popup Dashboard (read-only)
  - Tabs: Downloads | Sites | Settings
  - Circular meters, radar chart (recent risk categories), heatmap (file type frequencies)
  - Whitelist editor, feature toggles, reset profile, clear/export logs

## Storage

- Local (`chrome.storage.local`):
  - `downloadsLog` (max 500 entries)
  - `siteLog` (max 500 entries)
  - `profile` → `{ fileTypeCounts, domainCounts, totalCount }`
  - `recentSuspiciousTs` (timestamp used for risk multiplier)
- Sync (`chrome.storage.sync`):
  - `whitelist` (array of domains)
  - `settings` → `{ monitorDownloads, siteDetection, linkTooltips }`

## Permissions (Why they are needed)

- `downloads`: Observe new downloads and cancel risky ones on request
- `storage`: Persist logs, profile, whitelist, settings
- `webNavigation`: Detect page loads to score suspicious sites
- `tabs`/`activeTab`: Identify active tab for messaging badge/modal context
- `scripting`: MV3 capability; future script injection if needed
- `host_permissions: <all_urls>`: Allow detection on all pages

## How Detection Works

- All detection is in `background.js` (service worker). The popup is a read-only dashboard.
- Content script (`content.js`) only renders UI (banner, modal, tooltip) when messaged by the background.
- MIME fallback: if missing, the file extension is used to categorize risk.
- Event-driven background ensures monitoring even when the popup is closed.

## Try It (Test Scenarios)

- Executable from shady.xyz → high risk modal
- Tiny executable (≈10KB) → risky modal
- researchpaper.pdf from trusted.edu → safe
- Visit `https://xn--pple-43d.example` → suspicious banner (punycode)
- Hover a link with text "Google" that points to `https://g00gle.tk` → tooltip warning

## Whitelist

- Manage whitelist in popup → Settings → Whitelist
- Whitelisted domains are skipped for warnings (downloads and sites)

## Privacy

- All data stays on your device via Chrome storage.
- No network calls or external analytics.
- You can clear logs or reset the adaptive profile at any time from the popup.

## Troubleshooting

- After loading, refresh pages to ensure `content.js` is injected.
- If banners/modals don’t appear, check permissions in `chrome://extensions` and ensure the extension is enabled.
- Use the popup’s "Export Logs" to review decisions for debugging.

## License

MIT © SmartShield author --{@hemanth GR.} 

