/* ============================================================
   EASM-REPORT.JS — Carrega novo endpoint /api/scans/{id}/easm-report
============================================================ */

const query = new URLSearchParams(window.location.search);
const SCAN_ID = Number(query.get('scan_id') || query.get('id') || 1);

function getApiBaseUrl() {
  const byQuery = query.get('api_url') || query.get('api_base') || '';
  if (byQuery) return byQuery.replace(/\/$/, '');
  if (window.location.port === '8000') return window.location.origin;
  return `${window.location.protocol}//${window.location.hostname}:8000`;
}

const API_BASE_URL = getApiBaseUrl();

// ── Utility Functions ───────────────────────────────────────
function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(value) {
  try {
    return new Date(value).toLocaleDateString('pt-BR', { 
      day: '2-digit', 
      month: 'long', 
      year: 'numeric' 
    });
  } catch {
    return '-';
  }
}

function fmtDatetime(value) {
  try {
    return new Date(value).toLocaleString('pt-BR');
  } catch {
    return '-';
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value == null ? '-' : String(value);
}

function computeGrade(score) {
  const n = Number(score || 0);
  if (n >= 90) return 'A';
  if (n >= 80) return 'B';
  if (n >= 70) return 'C';
  if (n >= 60) return 'D';
  return 'F';
}

function getGradeClass(grade) {
  return `grade-${String(grade || 'f').toLowerCase()}`;
}

function formatSeconds(seconds) {
  if (!seconds) return '-';
  const s = Number(seconds);
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = Math.floor(s % 60);
  
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

// ── Token Management ────────────────────────────────────────
async function tryRefreshToken(refreshToken) {
  const res = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!res.ok) return null;
  const data = await res.json();
  if (data?.access_token) localStorage.setItem('token', data.access_token);
  if (data?.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);
  return data?.access_token || null;
}

async function tryLoginByQuery() {
  const email = query.get('email') || '';
  const password = query.get('password') || '';
  if (!email || !password) return null;

  const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) return null;

  const data = await res.json();
  if (data?.access_token) localStorage.setItem('token', data.access_token);
  if (data?.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);
  return data?.access_token || null;
}

async function ensureAccessToken() {
  const token = localStorage.getItem('token');
  if (token) return token;

  const refreshToken = localStorage.getItem('refresh_token');
  if (refreshToken) {
    const refreshed = await tryRefreshToken(refreshToken);
    if (refreshed) return refreshed;
  }

  const loginToken = await tryLoginByQuery();
  if (loginToken) return loginToken;

  throw new Error(
    `Sem token de acesso. Faça login na aplicação principal ou abra com parametros email/senha. Exemplo: ?scan_id=${SCAN_ID}&api_url=${encodeURIComponent(API_BASE_URL)}&email=admin@example.com&password=admin123`,
  );
}

// ── API Calls ──────────────────────────────────────────────
async function loadEasmReport() {
  const token = await ensureAccessToken();
  const res = await fetch(`${API_BASE_URL}/api/scans/${SCAN_ID}/easm-report`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      detail = body?.detail || body?.message || '';
    } catch {}
    throw new Error(`HTTP ${res.status}: ${detail || 'Falha ao carregar relatório'}`);
  }
  return res.json();
}

// ── Rendering Functions ────────────────────────────────────
function renderHeader(report) {
  setText('scanId', report.scan_id);
  setText('targetName', report.target || '-');
  setText('scanStatus', report.status || '-');
  setText('completedDate', report.completed_at ? fmtDatetime(report.completed_at) : '-');
  setText('duration', formatSeconds(report.execution_duration_seconds));
}

function renderEasmRating(report) {
  const rating = report.easm_rating || {};
  const score = Number(rating.score || 0);
  const grade = rating.grade || computeGrade(score);

  setText('easmScore', score.toFixed(1));
  
  const gradeEl = document.getElementById('easmGrade');
  if (gradeEl) {
    gradeEl.textContent = grade;
    gradeEl.className = `rating-badge ${getGradeClass(grade)}`;
  }

  setText('assetsCount', rating.n_assets_scanned || 0);
  setText('totalRa', Number(rating.total_ra || 0).toFixed(0));

  // FAIR Pillars
  const fair = report.fair_decomposition || {};
  const pillars = Array.isArray(fair.pillars) ? fair.pillars : [];
  const pillarsContainer = document.getElementById('fairPillars');
  
  if (!pillars.length) {
    pillarsContainer.innerHTML = '<div class="empty-state"><p>Sem decomposição FAIR disponível.</p></div>';
    return;
  }

  pillarsContainer.innerHTML = pillars.map((pillar) => {
    const pillarScore = Number(pillar.score || 0);
    const pillarWeight = Number(pillar.weight_pct || 0);
    const impact = Number(pillar.impact_pts || 0);
    
    return `
      <div class="fair-pillar">
        <div class="pillar-header">
          <div>
            <div class="pillar-name">${esc(pillar.name || '-')}</div>
            <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">
              Peso: ${pillarWeight.toFixed(1)}% | Impacto: ${impact.toFixed(2)} pts
            </div>
          </div>
          <div class="pillar-score">${pillarScore.toFixed(2)}</div>
        </div>
        <div class="progress-bar">
          <div class="progress-fill" style="width: ${Math.min(100, (pillarScore / 100) * 100)}%"></div>
        </div>
        ${pillar.finding_count ? `<div style="margin-top: 8px; font-size: 12px; color: #94a3b8;">Achados: ${pillar.finding_count}</div>` : ''}
      </div>
    `;
  }).join('');
}

function renderVulnerabilities(report) {
  const vulns = report.vulnerabilities || {};
  const bySev = vulns.by_severity || {};
  
  setText('vulnCritical', bySev.critical || 0);
  setText('vulnHigh', bySev.high || 0);
  setText('vulnMedium', bySev.medium || 0);
  setText('vulnLow', bySev.low || 0);

  const findings = Array.isArray(vulns.findings) ? vulns.findings : [];
  const container = document.getElementById('vulnTable');

  if (!findings.length) {
    container.innerHTML = '<div class="empty-state"><p>Sem achados para exibir.</p></div>';
    return;
  }

  const rows = findings.map((f) => `
    <tr>
      <td style="font-family: 'JetBrains Mono'; font-size: 12px;">${esc(f.id || '-')}</td>
      <td>${esc(f.title || '-')}</td>
      <td>${esc(f.cve || '-')}</td>
      <td style="text-align: center; font-weight: 600;">${(Number(f.cvss) || 0).toFixed(1)}</td>
      <td>${esc(f.severity || 'info').toUpperCase()}</td>
      <td>${esc(f.domain || '-')}</td>
      <td>${esc(f.tool || '-')}</td>
    </tr>
  `).join('');

  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Título</th>
          <th>CVE</th>
          <th>CVSS</th>
          <th>Severidade</th>
          <th>Domínio</th>
          <th>Ferramenta</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

function renderRecommendations(report) {
  const recs = report.recommendations || {};
  const recommendations = Array.isArray(recs.recommendations) ? recs.recommendations : [];

  setText('recCountBadge', recommendations.length);
  const container = document.getElementById('recList');

  if (!recommendations.length) {
    container.innerHTML = '<div class="empty-state"><p>Nenhuma recomendação disponível.</p></div>';
    return;
  }

  const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#06b6d4',
    info: '#64748b',
  };

  const severityLabels = {
    critical: 'Crítica',
    high: 'Alta',
    medium: 'Média',
    low: 'Baixa',
    info: 'Info',
  };

  container.innerHTML = recommendations.map((rec, idx) => {
    const color = severityColors[rec.severity] || '#64748b';
    const label = severityLabels[rec.severity] || rec.severity;

    return `
      <div style="
        background: #0f172a;
        border-left: 4px solid ${color};
        border-radius: 6px;
        padding: 16px;
        margin-bottom: 12px;
      ">
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
          <div style="font-weight: 600; color: #f1f5f9;">Recomendação ${idx + 1}</div>
          <span style="
            background: ${color};
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
          ">${label}</span>
        </div>
        <div style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
          ${esc(rec.text || '-')}
        </div>
      </div>
    `;
  }).join('');
}

function renderAssets(report) {
  const assets = report.assets || {};
  const details = Array.isArray(assets.assets_detail) ? assets.assets_detail : [];

  setText('assetCountBadge', details.length);
  const container = document.getElementById('assetsList');

  if (!details.length) {
    container.innerHTML = '<div class="empty-state"><p>Nenhum ativo descoberto.</p></div>';
    return;
  }

  container.innerHTML = details.map((asset) => `
    <div class="asset-item">
      <div class="asset-header">
        <div class="asset-address">${esc(asset.address || '-')}</div>
      </div>
      <div class="asset-stats">
        <div class="stat-badge">
          Total de Vulns
          <strong>${asset.vulnerability_count || 0}</strong>
        </div>
        <div class="stat-badge" style="border-left-color: #ef4444;">
          Críticas
          <strong>${asset.critical_count || 0}</strong>
        </div>
        <div class="stat-badge" style="border-left-color: #f97316;">
          Altas
          <strong>${asset.high_count || 0}</strong>
        </div>
        <div class="stat-badge" style="border-left-color: #eab308;">
          Médias
          <strong>${asset.medium_count || 0}</strong>
        </div>
        <div class="stat-badge">
          Idade Média
          <strong>${asset.avg_age_days || 0}d</strong>
        </div>
      </div>
    </div>
  `).join('');
}

function renderToolExecution(report) {
  const tools = report.tool_execution || {};
  const toolStats = tools.executed_tools || {};
  
  setText('toolCount', tools.tool_count || 0);
  setText('execCount', tools.total_executions || 0);

  const container = document.getElementById('toolBreakdown');
  const entries = Object.entries(toolStats).sort((a, b) => b[1] - a[1]);

  if (!entries.length) {
    container.innerHTML = '<div class="empty-state"><p>Nenhuma ferramenta executada.</p></div>';
    return;
  }

  container.innerHTML = entries.map(([tool, count]) => `
    <div class="tool-badge">${esc(tool)}: <strong>${count}</strong> execução${count > 1 ? 's' : ''}</div>
  `).join('');
}

function renderActivityMetrics(report) {
  const activity = report.activity_metrics || {};
  const nodeStats = activity.node_execution_stats || {};
  const nodeSeq = Array.isArray(activity.node_sequence) ? activity.node_sequence : [];

  setText('nodeCount', activity.total_nodes_executed || 0);

  const container = document.getElementById('activityMetrics');
  
  if (!Object.keys(nodeStats).length && !nodeSeq.length) {
    container.innerHTML = '<div class="empty-state"><p>Sem métricas de atividade.</p></div>';
    return;
  }

  let html = '<div class="section-title" style="font-size: 14px;">Duração Média por Nó</div>';
  html += '<div style="margin-top: 12px;">';
  
  Object.entries(nodeStats).forEach(([node, stats]) => {
    const avgDuration = Number(stats.avg_duration_ms || 0).toFixed(0);
    html += `
      <div class="node-item">
        <div class="node-name">${esc(node)}</div>
        <div class="node-metric">Média: ${avgDuration}ms ≈ ${(avgDuration / 1000).toFixed(2)}s</div>
      </div>
    `;
  });

  html += '</div>';

  if (nodeSeq.length) {
    html += '<div class="section-title" style="font-size: 14px; margin-top: 24px;">Sequência de Execução</div>';
    html += '<div class="activity-timeline" style="margin-top: 12px;">';
    
    nodeSeq.forEach((node, idx) => {
      html += `
        <div class="timeline-item">
          <strong>Etapa ${idx + 1}:</strong> ${esc(node)}
        </div>
      `;
    });
    
    html += '</div>';
  }

  container.innerHTML = html;
}

function renderRemediation(report) {
  const rem = report.remediation || {};
  const total = Number(rem.total_vulnerabilities || 0);
  const remediated = Number(rem.remediated_count || 0);
  const pending = Number(rem.pending_retest || 0);
  const falsePos = Number(rem.confirmed_false_positives || 0);
  const remediationRate = total > 0 ? ((remediated / total) * 100).toFixed(1) : 0;

  const container = document.getElementById('remediationStats');
  container.innerHTML = `
    <div class="remediation-stat">
      <div class="remediation-label">Total de Vulnerabilidades</div>
      <div class="remediation-value">${total}</div>
    </div>
    <div class="remediation-stat">
      <div class="remediation-label">Remediadas</div>
      <div class="remediation-value" style="color: #10b981;">${remediated}</div>
    </div>
    <div class="remediation-stat">
      <div class="remediation-label">Taxa de Remediação</div>
      <div class="remediation-value" style="color: #10b981;">${remediationRate}%</div>
    </div>
    <div class="remediation-stat">
      <div class="remediation-label">Pendente de Reteste</div>
      <div class="remediation-value" style="color: #f97316;">${pending}</div>
    </div>
    <div class="remediation-stat">
      <div class="remediation-label">Falsos Positivos Confirmados</div>
      <div class="remediation-value" style="color: #06b6d4;">${falsePos}</div>
    </div>
  `;
}

function renderBurpAsync(report) {
  const burp = report.burp_async || {};
  const status = burp.status || 'none';
  const findings = Number(burp.findings_count || 0);
  const targets = Number(burp.targets_count || 0);

  const statusDisplay = status === 'completed' ? '✓ Concluído' : 
                       status === 'running' ? '⟳ Em Execução' : 
                       status === 'pending' ? '⏳ Pendente' : 'Não Iniciado';

  setText('burpStatus', statusDisplay);
  
  const statsContainer = document.getElementById('burpStats');
  statsContainer.innerHTML = `
    <div class="stat-badge">
      Achados
      <strong>${findings}</strong>
    </div>
    <div class="stat-badge">
      Alvos
      <strong>${targets}</strong>
    </div>
  `;
}

// ── Main Initialization ────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const loadingState = document.getElementById('loadingState');
  const errorState = document.getElementById('errorState');
  const mainContent = document.getElementById('mainContent');

  try {
    const report = await loadEasmReport();

    // Render all sections
    renderHeader(report);
    renderEasmRating(report);
    renderVulnerabilities(report);
    renderRecommendations(report);
    renderAssets(report);
    renderToolExecution(report);
    renderActivityMetrics(report);
    renderRemediation(report);
    renderBurpAsync(report);

    // Show content, hide loading
    loadingState.style.display = 'none';
    mainContent.style.display = 'block';
  } catch (err) {
    console.error(err);
    loadingState.style.display = 'none';
    errorState.style.display = 'block';
    document.getElementById('errorMessage').textContent = esc(err.message);
  }
});
