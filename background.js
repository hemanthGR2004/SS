'use strict';

// Storage keys
const STORAGE_KEYS = {
	DOWNLOADS: 'downloadsLog',
	SITES: 'siteLog',
	PROFILE: 'profile',
	RECENT_SUSPICIOUS_TS: 'recentSuspiciousTs'
};

// Sync storage keys
const SYNC_KEYS = {
	WHITELIST: 'whitelist',
	SETTINGS: 'settings'
};

const MAX_LOG_ENTRIES = 500;
const RECENT_SUSPICIOUS_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

// Default state
const defaultState = {
	[STORAGE_KEYS.DOWNLOADS]: [],
	[STORAGE_KEYS.SITES]: [],
	[STORAGE_KEYS.PROFILE]: {
		fileTypeCounts: {},
		domainCounts: {},
		totalCount: 0
	},
	[STORAGE_KEYS.RECENT_SUSPICIOUS_TS]: 0
};

const defaultSync = {
	[SYNC_KEYS.WHITELIST]: [],
	[SYNC_KEYS.SETTINGS]: {
		monitorDownloads: true,
		siteDetection: true,
		linkTooltips: true
	}
};

// Utility: get domain from URL
function extractDomain(urlString) {
	try {
		const u = new URL(urlString);
		return u.hostname;
	} catch (e) {
		return '';
	}
}

function getExtensionFromFilename(filename) {
	const idx = filename.lastIndexOf('.')
	return idx !== -1 ? filename.slice(idx + 1).toLowerCase() : '';
}

function categorizeExtension(ext) {
	const docs = new Set(['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','rtf','odt','ods','odp']);
	const media = new Set(['mp3','mp4','avi','mkv','mov','jpg','jpeg','png','gif','webp','wav','flac','ogg','webm']);
	const execs = new Set(['exe','msi','bat','cmd','sh','appimage','dmg','pkg','jar','js','ps1']);
	const archives = new Set(['zip','rar','7z','tar','gz','bz2','xz']);
	if (execs.has(ext)) return 'Executable';
	if (archives.has(ext)) return 'Archive';
	if (docs.has(ext)) return 'Document';
	if (media.has(ext)) return 'Media';
	return 'Other';
}

function tldIsSuspicious(hostname) {
	return /\.(zip|tk|xyz|gq|cf)(:?$|\b)/i.test(hostname);
}

function hasPunycode(hostname) {
	return /(^|\.)xn--/i.test(hostname);
}

function hasMixedUnicode(hostname) {
	// Simple heuristic: presence of non-ASCII combined with ASCII letters
	const hasNonAscii = /[^\x00-\x7F]/.test(hostname);
	const hasAscii = /[A-Za-z]/.test(hostname);
	return hasNonAscii && hasAscii;
}

async function getState() {
	const local = await chrome.storage.local.get(defaultState);
	const sync = await chrome.storage.sync.get(defaultSync);
	return { local, sync };
}

async function setLocal(partial) {
	await chrome.storage.local.set(partial);
}

async function setSync(partial) {
	await chrome.storage.sync.set(partial);
}

function clampLogs(arr) {
	if (arr.length > MAX_LOG_ENTRIES) {
		return arr.slice(arr.length - MAX_LOG_ENTRIES);
	}
	return arr;
}

function addReason(reasons, text) {
	reasons.push(text);
}

function rarityScore(profile, category) {
	const total = Math.max(1, profile.totalCount || 0);
	const count = profile.fileTypeCounts[category] || 0;
	const ratio = count / total;
	return ratio < 0.10 ? 1 : 0;
}

function firstTimeDomainScore(profile, domain) {
	return profile.domainCounts[domain] ? 0 : 1;
}

function recentSuspiciousMultiplier(recentTs) {
	return (Date.now() - (recentTs || 0)) <= RECENT_SUSPICIOUS_WINDOW_MS ? 2 : 1;
}

function computeRiskForDownload(item, profile, recentTs) {
	let score = 0;
	const reasons = [];

	const filename = item.filename || (item.filenameDangerous || 'download');
	const url = item.url || item.finalUrl || '';
	const domain = extractDomain(url);
	const ext = getExtensionFromFilename(filename);
	const category = item.mime ? categorizeMime(item.mime) : categorizeExtension(ext);
	const sizeBytes = item.fileSize || item.bytesReceived || 0; // onCreated may not have size

	// Executable rule
	if (category === 'Executable') {
		score += 2; addReason(reasons, 'Executable file');
		if (sizeBytes > 0 && sizeBytes < 50 * 1024) { score += 2; addReason(reasons, 'Very small executable (<50KB)'); }
	}

	// First-time domain
	score += firstTimeDomainScore(profile, domain) ? 1 : 0;
	if (firstTimeDomainScore(profile, domain)) addReason(reasons, 'First time visiting this domain');

	// Rare file type
	const rare = rarityScore(profile, category);
	score += rare;
	if (rare) addReason(reasons, 'Rarely downloaded file type');

	// Recent suspicious site multiplier
	const mult = recentSuspiciousMultiplier(recentTs);
	if (mult > 1) addReason(reasons, 'Recent suspicious site (risk x2)');
	const finalScore = score * mult;

	return { score: finalScore, reasons, category, domain, ext, url, filename };
}

function categorizeMime(mime) {
	if (!mime) return 'Other';
	if (/application\/(x-msdownload|x-msi|x-dosexec|x-executable|x-msdos-program)/i.test(mime)) return 'Executable';
	if (/application\/(zip|x-7z-compressed|x-rar-compressed|x-tar|gzip)/i.test(mime)) return 'Archive';
	if (/^(image|audio|video)\//i.test(mime)) return 'Media';
	if (/application\/(pdf|msword|vnd\.openxmlformats|rtf)/i.test(mime) || /^text\//i.test(mime)) return 'Document';
	return 'Other';
}

function computeRiskForSite(url, profile) {
	let score = 0;
	const reasons = [];
	const domain = extractDomain(url);

	// Whitelist will be checked by caller

	// First-time domain
	if (firstTimeDomainScore(profile, domain)) { score += 1; addReason(reasons, 'First time domain'); }

	// Suspicious TLDs
	if (tldIsSuspicious(domain)) { score += 2; addReason(reasons, 'Suspicious TLD'); }

	// Long hostname
	if (domain.length > 30) { score += 1; addReason(reasons, 'Very long hostname'); }

	// Punycode
	if (hasPunycode(domain)) { score += 2; addReason(reasons, 'Punycode hostname'); }

	// Mixed Unicode
	if (hasMixedUnicode(domain)) { score += 2; addReason(reasons, 'Mixed Unicode hostname'); }

	return { score, reasons, domain };
}

async function ensureDefaults() {
	await chrome.storage.local.get(defaultState).then(async (data) => {
		await setLocal(data);
	});
	await chrome.storage.sync.get(defaultSync).then(async (data) => {
		await setSync(data);
	});
}

function updateBadge(level) {
	// level: 'high' | 'medium' | 'clear'
	if (level === 'clear') {
		chrome.action.setBadgeText({ text: '' });
		return;
	}
	const text = level === 'high' ? '!' : '?';
	const color = level === 'high' ? '#ff3366' : '#ffcc33';
	chrome.action.setBadgeText({ text });
	chrome.action.setBadgeBackgroundColor({ color });
	// Simple glow animation: pulse badge background color for a short time
	let ticks = 0;
	const base = color;
	const alt = level === 'high' ? '#ff668a' : '#ffe680';
	const interval = setInterval(() => {
		chrome.action.setBadgeBackgroundColor({ color: ticks % 2 === 0 ? alt : base });
		if (++ticks > 6) { clearInterval(interval); chrome.action.setBadgeBackgroundColor({ color: base }); }
	}, 300);
}

async function logSite(event) {
	const { local, sync } = await getState();
	const whitelist = sync[SYNC_KEYS.WHITELIST] || [];
	const url = event.url || '';
	const domain = extractDomain(url);
	if (whitelist.includes(domain)) return; // Skip whitelisted
	const { score, reasons } = computeRiskForSite(url, local[STORAGE_KEYS.PROFILE]);
	if (score >= 2 && (await isFeatureEnabled('siteDetection'))) {
		const entry = { time: Date.now(), url, domain, score, reasons };
		const sites = clampLogs([ ...local[STORAGE_KEYS.SITES], entry ]);
		await setLocal({ [STORAGE_KEYS.SITES]: sites, [STORAGE_KEYS.RECENT_SUSPICIOUS_TS]: Date.now() });
		// Update domain counts
		await bumpDomainCount(domain);
		// Notify content to show banner
		try {
			chrome.tabs.sendMessage(event.tabId, { type: 'SMARTSHIELD_BANNER', payload: { domain, reasons, score } });
		} catch (e) { /* tab may not have content script */ }
		updateBadge(score >= 3 ? 'high' : 'medium');
	} else {
		updateBadge('clear');
	}
}

async function bumpDomainCount(domain) {
	const { local } = await getState();
	const profile = local[STORAGE_KEYS.PROFILE];
	profile.domainCounts[domain] = (profile.domainCounts[domain] || 0) + 1;
	profile.totalCount = (profile.totalCount || 0) + 1;
	await setLocal({ [STORAGE_KEYS.PROFILE]: profile });
}

async function bumpFileType(category) {
	const { local } = await getState();
	const profile = local[STORAGE_KEYS.PROFILE];
	profile.fileTypeCounts[category] = (profile.fileTypeCounts[category] || 0) + 1;
	profile.totalCount = (profile.totalCount || 0) + 1;
	await setLocal({ [STORAGE_KEYS.PROFILE]: profile });
}

async function isFeatureEnabled(key) {
	const { sync } = await getState();
	const settings = sync[SYNC_KEYS.SETTINGS] || defaultSync[SYNC_KEYS.SETTINGS];
	return Boolean(settings[key] !== false);
}

// Downloads monitoring
chrome.downloads.onCreated.addListener(async (item) => {
	try {
		if (!(await isFeatureEnabled('monitorDownloads'))) return;
		const { local, sync } = await getState();
		const whitelist = sync[SYNC_KEYS.WHITELIST] || [];
		const filename = item.filename || 'download';
		const url = item.url || '';
		const domain = extractDomain(url);
		if (whitelist.includes(domain)) {
			await bumpDomainCount(domain);
			await bumpFileType('Other');
			return;
		}
		const risk = computeRiskForDownload(item, local[STORAGE_KEYS.PROFILE], local[STORAGE_KEYS.RECENT_SUSPICIOUS_TS]);

		const entry = {
			id: item.id,
			filename: risk.filename,
			url: risk.url,
			domain: risk.domain,
			ext: risk.ext,
			mime: item.mime || '',
			size: item.fileSize || 0,
			startTime: item.startTime || new Date().toISOString(),
			score: risk.score,
			reasons: risk.reasons,
			category: risk.category
		};
		const downloads = clampLogs([ ...local[STORAGE_KEYS.DOWNLOADS], entry ]);
		await setLocal({ [STORAGE_KEYS.DOWNLOADS]: downloads });
		await bumpDomainCount(risk.domain);
		await bumpFileType(risk.category);

		if (risk.score >= 2) {
			updateBadge(risk.score >= 4 ? 'high' : 'medium');
			// Ask content to show modal on active tab
			const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
			if (tab && tab.id) {
				chrome.tabs.sendMessage(tab.id, { type: 'SMARTSHIELD_DOWNLOAD_MODAL', payload: { downloadId: item.id, domain: risk.domain, entry } });
			}
		}
	} catch (e) {
		console.error('SmartShield onCreated error', e);
	}
});

// Site detection
chrome.webNavigation.onCompleted.addListener(async (details) => {
	try {
		const url = details.url || '';
		if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;
		await logSite(details);
	} catch (e) {
		console.error('SmartShield webNavigation error', e);
	}
});

// Messaging from content/popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	(async () => {
		try {
			if (message && message.type === 'SMARTSHIELD_MODAL_ACTION') {
				const { action, downloadId, domain } = message.payload || {};
				if (action === 'cancel' && typeof downloadId === 'number') {
					try { await chrome.downloads.cancel(downloadId); } catch (e) {}
					updateBadge('clear');
					sendResponse({ ok: true });
					return;
				}
				if (action === 'whitelist' && domain) {
					const { sync } = await getState();
					const wl = new Set(sync[SYNC_KEYS.WHITELIST] || []);
					wl.add(domain);
					await setSync({ [SYNC_KEYS.WHITELIST]: Array.from(wl) });
					updateBadge('clear');
					sendResponse({ ok: true });
					return;
				}
				if (action === 'ignore') {
					updateBadge('clear');
					sendResponse({ ok: true });
					return;
				}
			}

			if (message && message.type === 'SMARTSHIELD_GET_STATE') {
				const { local, sync } = await getState();
				sendResponse({ ok: true, local, sync });
				return;
			}

			if (message && message.type === 'SMARTSHIELD_UPDATE_SETTINGS') {
				const next = { ...(message.payload || {}) };
				const { sync } = await getState();
				await setSync({ [SYNC_KEYS.SETTINGS]: { ...(sync[SYNC_KEYS.SETTINGS] || {}), ...next } });
				sendResponse({ ok: true });
				return;
			}

			if (message && message.type === 'SMARTSHIELD_RESET_PROFILE') {
				await setLocal({ [STORAGE_KEYS.PROFILE]: defaultState[STORAGE_KEYS.PROFILE] });
				sendResponse({ ok: true });
				return;
			}

			if (message && message.type === 'SMARTSHIELD_CLEAR_LOGS') {
				await setLocal({ [STORAGE_KEYS.DOWNLOADS]: [], [STORAGE_KEYS.SITES]: [] });
				sendResponse({ ok: true });
				return;
			}

			if (message && message.type === 'SMARTSHIELD_UPDATE_WHITELIST') {
				await setSync({ [SYNC_KEYS.WHITELIST]: message.payload || [] });
				sendResponse({ ok: true });
				return;
			}
		} catch (e) {
			console.error('SmartShield message error', e);
			sendResponse({ ok: false, error: String(e) });
		}
	})();
	return true; // keep channel open for async
});

// Initialize defaults on install/update
chrome.runtime.onInstalled.addListener(async () => {
	await ensureDefaults();
});

// Export functions for potential tests (no effect in production)
self.SmartShield = {
	computeRiskForDownload,
	computeRiskForSite,
	categorizeExtension,
	categorizeMime,
	extractDomain
};
