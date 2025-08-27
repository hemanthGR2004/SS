(() => {
	'use strict';

	const qs = (s, r=document) => r.querySelector(s);
	const qsa = (s, r=document) => Array.from(r.querySelectorAll(s));

	const state = { local: null, sync: null };

	function switchTab(tab) {
		qsa('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
		qsa('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + tab));
	}

	async function getState() {
		return await chrome.runtime.sendMessage({ type: 'SMARTSHIELD_GET_STATE' });
	}

	function riskBadge(score) {
		if (score >= 4) return '<span class="badge high">!</span>';
		if (score >= 2) return '<span class="badge med">?</span>';
		return '<span class="badge low">·</span>';
	}

	function renderDownloads(list) {
		const el = qs('#downloadsList');
		el.innerHTML = '';
		(list || []).slice().reverse().forEach(d => {
			const li = document.createElement('li');
			li.innerHTML = `
				<div class="meter"></div>
				<div style="flex:1">
					<div><strong>${d.filename}</strong></div>
					<div class="small">${d.domain} • ${d.category} • score ${d.score}</div>
				</div>
				${riskBadge(d.score)}
			`;
			el.appendChild(li);
		});
	}

	function renderSites(list) {
		const el = qs('#sitesList');
		el.innerHTML = '';
		(list || []).slice().reverse().forEach(s => {
			const li = document.createElement('li');
			li.innerHTML = `
				<div style="flex:1">
					<div><strong>${s.domain}</strong></div>
					<div class="small">${s.reasons.join(', ')} • score ${s.score}</div>
				</div>
				${riskBadge(s.score)}
			`;
			el.appendChild(li);
		});
	}

	function polarPoint(cx, cy, r, angle) {
		return [cx + r * Math.cos(angle), cy + r * Math.sin(angle)];
	}

	function drawRadar(canvas, counts) {
		if (!canvas) return;
		const ctx = canvas.getContext('2d');
		ctx.clearRect(0,0,canvas.width,canvas.height);
		const labels = ['Executable','Archive','Document','Media','Other'];
		const values = labels.map(l => counts[l] || 0);
		const max = Math.max(1, ...values);
		const cx = canvas.width/2, cy = canvas.height/2 + 10, r = Math.min(cx, cy) - 16;

		ctx.strokeStyle = 'rgba(0,255,255,.25)';
		ctx.lineWidth = 1;
		for (let i=1;i<=4;i++) {
			ctx.beginPath();
			for (let j=0;j<labels.length;j++) {
				const a = (Math.PI*2 * j/labels.length) - Math.PI/2;
				const [x,y] = polarPoint(cx,cy,r*i/4,a);
				j===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
			}
			ctx.closePath();
			ctx.stroke();
		}
		// data
		ctx.beginPath();
		for (let j=0;j<labels.length;j++) {
			const a = (Math.PI*2 * j/labels.length) - Math.PI/2;
			const v = values[j]/max;
			const [x,y] = polarPoint(cx,cy,r*v,a);
			j===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
		}
		ctx.closePath();
		ctx.fillStyle = 'rgba(0,255,200,.25)';
		ctx.strokeStyle = 'rgba(0,255,200,.6)';
		ctx.lineWidth = 2;
		ctx.fill();
		ctx.stroke();
	}

	function drawHeatmap(canvas, counts) {
		if (!canvas) return;
		const ctx = canvas.getContext('2d');
		ctx.clearRect(0,0,canvas.width,canvas.height);
		const labels = ['Executable','Archive','Document','Media','Other'];
		const values = labels.map(l => counts[l] || 0);
		const max = Math.max(1, ...values);
		const cols = labels.length;
		const rows = 4;
		const cellW = canvas.width / cols;
		const cellH = canvas.height / rows;
		for (let c=0;c<cols;c++) {
			for (let r=0;r<rows;r++) {
				const ratio = values[c]/max * (1 - r/rows);
				ctx.fillStyle = `rgba(0,255,200,${0.1 + 0.6*ratio})`;
				ctx.fillRect(c*cellW, r*cellH, cellW-2, cellH-2);
			}
		}
	}

	function renderWhitelist(domains) {
		const el = qs('#whitelist');
		el.innerHTML = '';
		(domains || []).forEach(d => {
			const li = document.createElement('li');
			li.innerHTML = `<span>${d}</span> <button data-d="${d}">Remove</button>`;
			el.appendChild(li);
		});
		qsa('#whitelist button').forEach(b => b.addEventListener('click', async (e) => {
			const d = e.currentTarget.getAttribute('data-d');
			const next = (state.sync.whitelist || []).filter(x => x !== d);
			await chrome.runtime.sendMessage({ type: 'SMARTSHIELD_UPDATE_WHITELIST', payload: next });
			await load();
		}));
	}

	async function applySettingsUI() {
		qs('#toggleDownloads').checked = state.sync.settings?.monitorDownloads !== false;
		qs('#toggleSites').checked = state.sync.settings?.siteDetection !== false;
		qs('#toggleTooltips').checked = state.sync.settings?.linkTooltips !== false;
	}

	function bindEvents() {
		qsa('.tab').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
		qs('#resetProfile').addEventListener('click', async () => { await chrome.runtime.sendMessage({ type: 'SMARTSHIELD_RESET_PROFILE' }); await load(); });
		qs('#clearLogs').addEventListener('click', async () => { await chrome.runtime.sendMessage({ type: 'SMARTSHIELD_CLEAR_LOGS' }); await load(); });
		qs('#exportLogs').addEventListener('click', () => exportLogs());
		qs('#toggleDownloads').addEventListener('change', async (e) => { await chrome.runtime.sendMessage({ type: 'SMARTSHIELD_UPDATE_SETTINGS', payload: { monitorDownloads: e.target.checked } }); });
		qs('#toggleSites').addEventListener('change', async (e) => { await chrome.runtime.sendMessage({ type: 'SMARTSHIELD_UPDATE_SETTINGS', payload: { siteDetection: e.target.checked } }); });
		qs('#toggleTooltips').addEventListener('change', async (e) => { await chrome.runtime.sendMessage({ type: 'SMARTSHIELD_UPDATE_SETTINGS', payload: { linkTooltips: e.target.checked } }); });
	}

	function exportLogs() {
		const blob = new Blob([JSON.stringify({ downloads: state.local.downloadsLog, sites: state.local.siteLog, profile: state.local.profile }, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'smartshield-logs.json';
		document.body.appendChild(a);
		a.click();
		setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
	}

	async function load() {
		const res = await getState();
		if (!res || !res.ok) return;
		state.local = res.local; state.sync = res.sync;
		renderDownloads(res.local.downloadsLog);
		renderSites(res.local.siteLog);
		drawRadar(qs('#radarChart'), res.local.profile?.fileTypeCounts || {});
		drawHeatmap(qs('#heatmap'), res.local.profile?.fileTypeCounts || {});
		renderWhitelist(res.sync.whitelist);
		applySettingsUI();
	}

	bindEvents();
	load();
})();
