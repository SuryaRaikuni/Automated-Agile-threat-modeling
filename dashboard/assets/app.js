(async function() {
  try {
    const [threatsRes, runsRes, backlogRes] = await Promise.all([
      fetch('./data/threats.json').catch(() => ({ json: () => ({ threats: [] }) })),
      fetch('./data/runs.json').catch(() => ({ json: () => ({ runs: [] }) })),
      fetch('./data/backlog.json').catch(() => ({ json: () => ({ tickets: [] }) }))
    ]);
    
    window.TLData = {
      threats: (await threatsRes.json()).threats || [],
      runs: (await runsRes.json()).runs || [],
      tickets: (await backlogRes.json()).tickets || []
    };
  } catch(e) {
    console.error("Failed to load data", e);
    window.TLData = { threats: [], runs: [], tickets: [] };
  }
  
  // Dispatch 'tl-data-ready' event so each page can render
  document.dispatchEvent(new Event('tl-data-ready'));
})();

window.getSeverityColor = function(severity) {
  const s = (severity || '').toUpperCase();
  switch(s) {
    case 'CRITICAL': return 'var(--critical)';
    case 'HIGH': return 'var(--high)';
    case 'MEDIUM': return 'var(--medium)';
    case 'LOW': return 'var(--low)';
    default: return 'var(--info)';
  }
};

window.formatSeverity = function(severity) {
  const s = (severity || '').toUpperCase();
  let cls = 'badge-info';
  if(s==='CRITICAL') cls = 'badge-critical';
  if(s==='HIGH') cls = 'badge-high';
  if(s==='MEDIUM') cls = 'badge-medium';
  if(s==='LOW') cls = 'badge-low';
  return `<span class="badge ${cls}">${window.escapeHtml(s)}</span>`;
};

window.formatStatus = function(status) {
  const s = (status || '').toUpperCase();
  let cls = 'badge-info';
  if(s==='MITIGATED' || s==='SUCCESS') cls = 'badge-success';
  if(s==='FAILURE' || s==='FALSE POSITIVE') cls = 'badge-failure';
  if(s==='RUNNING') cls = 'badge-warning';
  return `<span class="badge ${cls}">${window.escapeHtml(s)}</span>`;
};

window.formatCategory = function(cat) {
  return (cat || '').replace(/_/g, ' ');
};

window.formatDate = function(isoStr) {
  if(!isoStr) return '';
  const d = new Date(isoStr);
  const now = new Date();
  const diff = now - d;
  if(diff < 86400000 && diff > 0) { // less than 24 hours
    const hours = Math.floor(diff / 3600000);
    if(hours > 0) return `${hours} hours ago`;
    const mins = Math.floor(diff / 60000);
    return `${mins} minutes ago`;
  }
  return d.toLocaleString();
};

window.escapeHtml = function(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
};

window.getQueryParam = function(name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
};

window.renderSharedTopbar = function() {
  const tb = document.getElementById('shared-topbar');
  if(!tb) return;
  
  let lastScan = 'Never';
  if (window.TLData.runs.length > 0) {
    lastScan = window.formatDate(window.TLData.runs[0].timestamp);
  }
  
  tb.innerHTML = `
    <div class="topbar-left">
      <span class="pill">SuryaRaikuni/Automated-Agile-threat-modeling</span>
      <span class="pill">main</span>
    </div>
    <div class="topbar-right">
      <span style="color:var(--muted)">Last scan: <span id="last-scan-time">${lastScan}</span></span>
      <button class="btn btn-ghost" id="btn-rerun">Re-run Scan</button>
    </div>
  `;
  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal" id="rerun-modal">
      <div class="modal-content">
        <h3>Trigger Pipeline</h3>
        <p style="margin: 16px 0;">Push a commit to trigger the pipeline.</p>
        <button class="btn btn-primary" onclick="document.getElementById('rerun-modal').classList.remove('open')">Close</button>
      </div>
    </div>
  `);
  
  const rerunBtn = document.getElementById('btn-rerun');
  const modal = document.getElementById('rerun-modal');
  if(rerunBtn && modal) {
    rerunBtn.addEventListener('click', () => modal.classList.add('open'));
    modal.addEventListener('click', (e) => { if(e.target === modal) modal.classList.remove('open'); });
  }
};
