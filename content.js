'use strict';

if (!document.documentElement.dataset.smartshieldInjected) {
	document.documentElement.dataset.smartshieldInjected = '1';

	const SS_PREFIX = 'smartshield';
	let tooltipEl = null;
	let bannerEl = null;
	let modalEl = null;

	function createStyle() {
		const style = document.createElement('style');
		style.textContent = `
			.${SS_PREFIX}-banner{position:fixed;top:-80px;left:0;right:0;height:auto;z-index:2147483647;background:rgba(255,40,80,0.15);backdrop-filter: blur(6px);border-bottom:1px solid rgba(255,80,120,0.6);padding:12px 16px;color:#ff6b8a;font-family:Inter,Segoe UI,Arial,sans-serif;text-shadow:0 0 8px #ff3b6a;display:flex;align-items:center;gap:12px;transition:transform .4s ease, top .4s ease;transform: translateY(-100%);} 
			.${SS_PREFIX}-banner.show{top:0;transform: translateY(0);} 
			.${SS_PREFIX}-badge{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:#ff3b6a;box-shadow:0 0 12px #ff3b6a, 0 0 24px rgba(255,59,106,.4);color:#0b0f12;font-weight:700}
			.${SS_PREFIX}-banner .${SS_PREFIX}-dismiss{margin-left:auto;color:#ffb0c0;cursor:pointer}
			.${SS_PREFIX}-tooltip{position:fixed;pointer-events:none;background:rgba(255, 59, 106, 0.1);border:1px solid rgba(255, 59, 106, 0.6);color:#ffb3c3;padding:6px 10px;border-radius:8px;font-size:12px;font-family:Inter,Arial,sans-serif;z-index:2147483647;box-shadow:0 0 10px #ff3b6a, inset 0 0 10px rgba(255,59,106,.3);backdrop-filter: blur(6px);} 
			.${SS_PREFIX}-modal-overlay{position:fixed;inset:0;background:rgba(11,15,18,.7);backdrop-filter: blur(6px);display:flex;align-items:center;justify-content:center;z-index:2147483647}
			.${SS_PREFIX}-modal{width:min(520px,92vw);background:rgba(14,18,22,.95);border:1px solid rgba(0,255,200,.25);box-shadow:0 0 22px rgba(0,255,200,.25), inset 0 0 18px rgba(0,255,200,.08);border-radius:14px;color:#aef7ff;padding:18px 18px 14px}
			.${SS_PREFIX}-modal h2{margin:0 0 6px;font-weight:700;color:#6cf7ff;text-shadow:0 0 10px rgba(0,255,255,.5)}
			.${SS_PREFIX}-modal .reasons{margin:8px 0 12px;color:#8ae2ff}
			.${SS_PREFIX}-modal .actions{display:flex;gap:10px;justify-content:flex-end}
			.${SS_PREFIX}-btn{padding:8px 12px;border-radius:10px;border:1px solid transparent;cursor:pointer;font-weight:600;background:#0f1418;color:#bfeaff;transition:all .2s}
			.${SS_PREFIX}-btn:hover{box-shadow:0 0 12px rgba(120,220,255,.25)}
			.${SS_PREFIX}-btn.cancel{border-color:rgba(255,60,100,.6);color:#ff9db0;background:rgba(255,60,100,.08)}
			.${SS_PREFIX}-btn.ignore{border-color:rgba(255,200,60,.6);color:#ffe29d;background:rgba(255,200,60,.08)}
			.${SS_PREFIX}-btn.white{border-color:rgba(60,255,180,.6);color:#c6ffd8;background:rgba(60,255,180,.08)}
		`;
		return style;
	}

	document.documentElement.appendChild(createStyle());

	function showBanner({ domain, reasons, score }) {
		if (bannerEl) bannerEl.remove();
		bannerEl = document.createElement('div');
		bannerEl.className = `${SS_PREFIX}-banner`;
		bannerEl.innerHTML = `
			<span class="${SS_PREFIX}-badge">!</span>
			<strong>SmartShield:</strong> Suspicious site detected (${domain}). ${reasons.join(', ')}.
			<span class="${SS_PREFIX}-dismiss">Dismiss ✕</span>
		`;
		document.documentElement.appendChild(bannerEl);
		setTimeout(() => bannerEl.classList.add('show'));
		bannerEl.querySelector(`.${SS_PREFIX}-dismiss`).addEventListener('click', () => bannerEl.remove());
	}

	function showTooltip(text, x, y) {
		if (!tooltipEl) {
			ooltipEl = document.createElement('div');
			tooltipEl.className = `${SS_PREFIX}-tooltip`;
			document.documentElement.appendChild(tooltipEl);
		}
		tooltipEl.textContent = text;
		const offset = 14;
		tooltipEl.style.left = `${x + offset}px`;
		tooltipEl.style.top = `${y + offset}px`;
		tooltipEl.style.display = 'block';
	}

	function hideTooltip() {
		if (tooltipEl) tooltipEl.style.display = 'none';
	}

	function domainFromHref(href) {
		try { return new URL(href, location.href).hostname; } catch { return ''; }
	}

	function textLooksLikeBrand(text) {
		return /google|facebook|apple|microsoft|amazon|netflix|twitter|x\b|github/i.test(text);
	}

	function suspiciousLink(anchor) {
		const host = domainFromHref(anchor.href);
		if (!host) return false;
		const txt = (anchor.textContent || '').trim();
		const mismatch = txt && textLooksLikeBrand(txt) && !host.toLowerCase().includes(txt.toLowerCase().replace(/[^a-z]/gi,''));
		const tldSusp = /\.(zip|tk|xyz|gq|cf)(:?$|\b)/i.test(host);
		return mismatch || tldSusp;
	}

	let hoverListener = (e) => {
		const t = e.target.closest('a[href]');
		if (!t) { hideTooltip(); return; }
		if (suspiciousLink(t)) {
			showTooltip('⚠️ Suspicious link', e.clientX, e.clientY);
		} else {
			hideTooltip();
		}
	};
	document.addEventListener('mousemove', hoverListener, { passive: true });

	function showModal(payload) {
		if (modalEl) modalEl.remove();
		modalEl = document.createElement('div');
		modalEl.className = `${SS_PREFIX}-modal-overlay`;
		const domain = payload.domain || 'this site';
		const reasons = (payload.entry && payload.entry.reasons) || [];
		modalEl.innerHTML = `
			<div class="${SS_PREFIX}-modal">
				<h2>Potentially risky download</h2>
				<div class="reasons">From <strong>${domain}</strong>. Reasons: ${reasons.join(', ') || 'Heuristic risk'}.</div>
				<div class="actions">
					<button class="${SS_PREFIX}-btn cancel">Cancel</button>
					<button class="${SS_PREFIX}-btn ignore">Ignore</button>
					<button class="${SS_PREFIX}-btn white">Whitelist domain</button>
				</div>
			</div>
		`;
		document.documentElement.appendChild(modalEl);
		const send = (action) => chrome.runtime.sendMessage({ type: 'SMARTSHIELD_MODAL_ACTION', payload: { action, downloadId: payload.downloadId, domain } });
		modalEl.querySelector('.cancel').addEventListener('click', () => { send('cancel'); modalEl.remove(); });
		modalEl.querySelector('.ignore').addEventListener('click', () => { send('ignore'); modalEl.remove(); });
		modalEl.querySelector('.white').addEventListener('click', () => { send('whitelist'); modalEl.remove(); });
	}

	chrome.runtime.onMessage.addListener((msg) => {
		if (!msg) return;
		if (msg.type === 'SMARTSHIELD_BANNER') {
			showBanner(msg.payload || {});
		}
		if (msg.type === 'SMARTSHIELD_DOWNLOAD_MODAL') {
			showModal(msg.payload || {});
		}
	});
}
