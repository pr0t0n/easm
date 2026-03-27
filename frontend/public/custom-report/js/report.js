/* ============================================================
   REPORT.JS — Carrega API (/api/scans/{id}/report) e renderiza
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

const SEV_CONFIG = {
  critical: { label: 'Crítico', icon: 'fa-skull-crossbones', cls: 'sev-critical', order: 0 },
  high:     { label: 'Alto', icon: 'fa-exclamation-triangle', cls: 'sev-high', order: 1 },
  medium:   { label: 'Médio', icon: 'fa-exclamation-circle', cls: 'sev-medium', order: 2 },
  low:      { label: 'Baixo', icon: 'fa-info-circle', cls: 'sev-low', order: 3 },
  info:     { label: 'Info', icon: 'fa-search', cls: 'sev-info', order: 4 },
};

function getSevConfig(sev) {
  return SEV_CONFIG[String(sev || 'info').toLowerCase()] || SEV_CONFIG.info;
}

function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(value) {
  try {
    return new Date(value).toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' });
  } catch {
    return '-';
  }
}

function truncate(str, max = 400) {
  const s = String(str || '');
  return s.length <= max ? s : `${s.slice(0, max)}...`;
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value == null ? '-' : String(value);
}

function computeDisplayedSummary(v2Summary, vulnerabilityTable) {
  const rows = Array.isArray(vulnerabilityTable) ? vulnerabilityTable : [];
  if (!rows.length) {
    return {
      total: Number(v2Summary?.total || 0),
      critical: Number(v2Summary?.critical || 0),
      high: Number(v2Summary?.high || 0),
      medium: Number(v2Summary?.medium || 0),
      low: Number(v2Summary?.low || 0),
      info: Number(v2Summary?.info || 0),
    };
  }

  const acc = { total: rows.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const row of rows) {
    const sev = String(row?.severity || "info").toLowerCase();
    if (sev === "critical") acc.critical += 1;
    else if (sev === "high") acc.high += 1;
    else if (sev === "medium") acc.medium += 1;
    else if (sev === "low") acc.low += 1;
    else acc.info += 1;
  }
  return acc;
}

function fmtCurrencyUSD(value) {
  const num = Number(value || 0);
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 0,
  }).format(num);
}

function computeGrade(score) {
  const n = Number(score || 0);
  if (n >= 90) return 'A';
  if (n >= 80) return 'B';
  if (n >= 70) return 'C';
  if (n >= 60) return 'D';
  return 'F';
}

function calculateCriFromCounts(severityCounts) {
  const critical = Number(severityCounts?.critical || 0);
  const high = Number(severityCounts?.high || 0);

  let health = 100;
  let baseFormula = '100';

  if (critical >= 1) {
    health = 40 - ((critical - 1) * 5);
    baseFormula = `40 - ((${critical} - 1) x 5)`;
  }
  if (high >= 1) {
    if (critical === 0) {
      health = 60;
      baseFormula = '60';
    }
    health = health - ((high - 1) * 2);
  }

  const highAdditionalPenalty = high >= 2 ? (high - 1) * 2 : 0;
  const finalScore = Math.max(5, Math.min(100, Math.round(health)));

  return {
    critical,
    high,
    baseFormula,
    highAdditionalPenalty,
    finalScore,
    humanReadable: high >= 1
      ? `score = max(5, ${baseFormula} - ((${high} - 1) x 2)) = ${finalScore}`
      : `score = max(5, ${baseFormula}) = ${finalScore}`,
  };
}

function hasRealFindings(v2) {
  const summary = v2.summary || {};
  const calc = (v2.segment_benchmark || {}).calculation || {};
  const sev = calc.severity_counts || {};
  return (
    Number(summary.total || 0) > 0 ||
    Number(summary.critical || 0) > 0 ||
    Number(summary.high || 0) > 0 ||
    Number(summary.medium || 0) > 0 ||
    Number(summary.low || 0) > 0 ||
    Number(sev.critical || 0) > 0 ||
    Number(sev.high || 0) > 0 ||
    Number(sev.medium || 0) > 0 ||
    Number(sev.low || 0) > 0
  );
}

function renderFairAndBenchmark(report) {
  const v2 = (report?.state_data || {}).report_v2 || {};
  const fair = v2.fair || {};
  const benchmark = v2.segment_benchmark || {};
  const calc = benchmark.calculation || {};
  const summary = v2.summary || {};

  // Os índices FAIR e CRI só fazem sentido com findings reais
  const hasData = hasRealFindings(v2);
  const noDataPlaceholder = (id) => setText(id, 'N/A — scan sem findings');

  setText('fairAvgScore', hasData ? Number(fair.fair_avg_score || 0).toFixed(2) : '-');
  setText('fairAleOpen', hasData ? fmtCurrencyUSD(fair.ale_total_open_usd || 0) : '-');
  setText('fairDailyImpact', hasData ? fmtCurrencyUSD(fair.daily_impact_open_usd || 0) : '-');
  setText('fairMitigation', hasData ? fmtCurrencyUSD(fair.mitigation_cost_estimate_open_usd || 0) : '-');

  if (!hasData) {
    ['benchmarkCriScore', 'benchmarkGrade', 'benchmarkAssessment',
     'calcCritical', 'calcHigh', 'calcMedium', 'calcLow',
     'calcBaseFormula', 'calcPenalty', 'calcHuman'].forEach((id) => setText(id, '-'));
    setText('benchmarkSegment', benchmark.segment || 'Digital Services');
    const factorsTable = document.getElementById('ratingFactorsTable');
    if (factorsTable) factorsTable.innerHTML = 'Sem dados — scan não concluído ou sem findings.';
    const timelineBox = document.getElementById('ratingTimelineBox');
    if (timelineBox) timelineBox.innerHTML = 'Sem curva temporal disponível.';
    return;
  }

  const severityCounts = calc.severity_counts || {
    critical: Number(summary.critical || 0),
    high: Number(summary.high || 0),
    medium: Number(summary.medium || 0),
    low: Number(summary.low || 0),
  };

  const fallbackCalc = calculateCriFromCounts(severityCounts);
  const finalScore = Number(benchmark.target_cri_score ?? calc.final_score ?? fallbackCalc.finalScore);
  const grade = computeGrade(finalScore);

  const assessmentMap = {
    melhor_que_o_benchmark: 'Melhor que o benchmark',
    acima_do_benchmark: 'Acima do benchmark (maior exposição)',
    similar_ao_benchmark: 'Similar ao benchmark',
  };

  setText('benchmarkCriScore', finalScore);
  setText('benchmarkGrade', grade);
  setText('benchmarkSegment', benchmark.segment || 'Digital Services');
  setText('benchmarkAssessment', assessmentMap[benchmark.assessment] || benchmark.assessment || 'N/A');

  setText('calcCritical', severityCounts.critical);
  setText('calcHigh', severityCounts.high);
  setText('calcMedium', severityCounts.medium);
  setText('calcLow', severityCounts.low);
  setText('calcBaseFormula', calc.base_formula || fallbackCalc.baseFormula);
  setText('calcPenalty', calc.critical_high_penalty_points ?? fallbackCalc.highAdditionalPenalty);
  setText('calcHuman', calc.human_readable || fallbackCalc.humanReadable);

  const continuous = v2.continuous_rating || {};
  const timeline = Array.isArray(v2.rating_timeline) ? v2.rating_timeline : [];
  setText('contRatingScore', continuous.score != null ? Number(continuous.score).toFixed(2) : '-');
  setText('contRatingGrade', continuous.grade || '-');
  setText('contRatingMethod', continuous.methodology || '-');
  setText('contRatingFactors', Array.isArray(continuous.factors) ? continuous.factors.length : 0);

  const factorsTable = document.getElementById('ratingFactorsTable');
  if (factorsTable) {
    const factors = Array.isArray(continuous.factors) ? continuous.factors : [];
    if (!factors.length) {
      factorsTable.innerHTML = 'Sem decomposição disponível.';
    } else {
      factorsTable.innerHTML = `
        <table class="method-table" aria-label="Decomposição formal do rating contínuo">
          <thead><tr><th>Fator</th><th>Peso</th><th>Score</th><th>Impacto</th></tr></thead>
          <tbody>
            ${factors.map((f) => `<tr><td>${esc(f.name || '-')}</td><td>${Math.round((Number(f.weight || 0) * 100))}%</td><td>${Number(f.score || 0).toFixed(2)}</td><td>${Number(f.impact_points || 0).toFixed(2)}</td></tr>`).join('')}
          </tbody>
        </table>`;
    }
  }

  const timelineBox = document.getElementById('ratingTimelineBox');
  if (timelineBox) {
    if (!timeline.length) {
      timelineBox.innerHTML = 'Sem curva temporal disponível.';
    } else {
      const latest = timeline.slice(-8).reverse();
      timelineBox.innerHTML = latest
        .map((row) => `Scan #${esc(row.scan_id)} | score ${Number(row.rating_score || 0).toFixed(2)} | penalidade persistência ${Number(row.persistence_penalty || 0).toFixed(2)}`)
        .join('<br/>');
    }
  }
}

function renderBenchmarkComparison(report) {
  const v2 = (report?.state_data || {}).report_v2 || {};
  const benchmark = v2.segment_benchmark || {};

  setText('benchmarkSegmentName', benchmark.segment || 'Digital Services');
  setText('benchmarkSegmentSource', benchmark.source || 'WEF Global Cybersecurity Outlook (referencia setorial)');

  const comparisonTable = document.getElementById('benchmarkComparisonTable');

  // Só exibir comparativo quando o scan tiver findings reais
  if (!hasRealFindings(v2)) {
    const emptyMsg = '<tr><td colspan="5" style="text-align:center;padding:28px 16px;color:#64748b;font-size:0.85rem;">' +
      '<span style="display:block;margin-bottom:6px;font-size:1.2rem;">&#8212;</span>' +
      'Benchmark indisponível — execute um scan completo para gerar os índices comparativos.' +
      '</td></tr>';
    if (comparisonTable) comparisonTable.innerHTML = emptyMsg;
    ['benchmarkSegmentAssessment', 'avgTarget', 'avgBenchmark', 'avgDiff', 'avgGrade',
     'detailTargetCRI', 'detailBenchmarkCRI', 'detailCRIDiff',
     'detailExpectedCRIGrade', 'detailCRIInterpretation'].forEach((id) => setText(id, '-'));
    return;
  }

  const assessmentMap = {
    melhor_que_o_benchmark: 'Melhor que o benchmark (menor exposição)',
    acima_do_benchmark: 'Acima do benchmark (maior exposição)',
    similar_ao_benchmark: 'Similar ao benchmark',
  };
  setText('benchmarkSegmentAssessment', assessmentMap[benchmark.assessment] || benchmark.assessment || 'N/A');

  // Renderizar tabela de comparação
  if (!comparisonTable) return;

  const indices = [
    {
      label: 'Cyber Readiness Index',
      target: benchmark.target_cyber_readiness_index,
      segment: benchmark.segment_cyber_readiness_index,
      higherIsBetter: true,  // mais readiness = melhor
    },
    {
      label: 'Financial Loss Exposure Index',
      target: benchmark.target_financial_loss_exposure_index,
      segment: benchmark.segment_financial_loss_exposure_index,
      higherIsBetter: false, // mais exposição financeira = pior
    },
    {
      label: 'Data Sensitivity Risk Index',
      target: benchmark.target_data_sensitivity_risk_index,
      segment: benchmark.segment_data_sensitivity_risk_index,
      higherIsBetter: false, // mais sensibilidade = pior
    },
    {
      label: 'Reliability/Safety Impact Index',
      target: benchmark.target_reliability_safety_impact_index,
      segment: benchmark.segment_reliability_safety_impact_index,
      higherIsBetter: false, // mais impacto = pior
    },
    {
      label: 'External Exposure Index',
      target: benchmark.target_external_exposure_index,
      segment: benchmark.segment_external_exposure_index || benchmark.segment_external_exposure_reference,
      higherIsBetter: false, // mais exposição externa = pior
    },
  ];

  const rows = indices.map((item) => {
    const targetVal = Number(item.target || 0);
    const segmentVal = Number(item.segment || 0);
    const diff = targetVal - segmentVal;
    // Regra solicitada: diferença positiva (target > benchmark) = MELHOR.
    const isBetter = diff > 0;
    const isWorse  = diff < 0;
    const status = isBetter ? 'Melhor' : isWorse ? 'Pior' : 'Similar';
    const statusColor = isBetter ? '#16a34a' : isWorse ? '#dc2626' : '#ea580c';

    return `<tr>
      <td>${esc(item.label)}</td>
      <td style="text-align:center;font-weight:bold;">${targetVal}</td>
      <td style="text-align:center;font-weight:bold;">${segmentVal}</td>
      <td style="text-align:center;font-weight:bold;color:${statusColor};">${diff > 0 ? '+' : ''}${diff}</td>
      <td style="text-align:center;color:${statusColor};font-weight:600;">${status}</td>
    </tr>`;
  }).join('');

  comparisonTable.innerHTML = rows || '<tr><td colspan="5">Sem dados de benchmark disponível.</td></tr>';

  // Media comparativa e nota
  const valid = indices
    .map((item) => ({
      target: Number(item.target || 0),
      benchmark: Number(item.segment || 0),
    }))
    .filter((row) => Number.isFinite(row.target) && Number.isFinite(row.benchmark));

  const avgTarget = valid.length ? (valid.reduce((acc, row) => acc + row.target, 0) / valid.length) : 0;
  const avgBenchmark = valid.length ? (valid.reduce((acc, row) => acc + row.benchmark, 0) / valid.length) : 0;
  const avgDiff = avgTarget - avgBenchmark;
  const comparativeScore = avgBenchmark > 0 ? Math.max(0, Math.min(100, (avgTarget / avgBenchmark) * 100)) : 100;
  const comparativeGrade = computeGrade(comparativeScore);

  setText('avgTarget', avgTarget.toFixed(1));
  setText('avgBenchmark', avgBenchmark.toFixed(1));
  setText('avgDiff', `${avgDiff > 0 ? '+' : ''}${avgDiff.toFixed(1)}`);
  setText('avgGrade', `${comparativeGrade} (${comparativeScore.toFixed(1)})`);

  // Detalhes do CRI
  setText('detailTargetCRI', Number(benchmark.target_cri_score || 0));
  setText('detailBenchmarkCRI', Number(benchmark.segment_cri_score || 0));
  
  const criDiff = Number(benchmark.target_cri_score || 0) - Number(benchmark.segment_cri_score || 0);
  setText('detailCRIDiff', criDiff > 0 ? `+${criDiff}` : `${criDiff}`);
  const expectedCriGrade = computeGrade(Number(benchmark.segment_cri_score || 0));
  setText('detailExpectedCRIGrade', expectedCriGrade);

  let criInterpretation = '';
  if (criDiff > 0) {
    criInterpretation = 'Postura melhor que o benchmark setorial — exposição abaixo do esperado para o setor.';
  } else if (criDiff < 0) {
    criInterpretation = 'Postura acima do benchmark setorial — exposição maior que o esperado para o setor. Requer atenção prioritária.';
  } else {
    criInterpretation = 'Postura similar ao benchmark setorial — alinhada com expectativas para o setor.';
  }
  setText('detailCRIInterpretation', criInterpretation);
}

function resolveReportTarget(report, v2) {
  return report?.target
    || report?.scan_target
    || v2?.domain
    || v2?.target
    || (report?.totals || {}).target
    || '-';
}

function validateReportData(report) {
  const v2 = (report?.state_data || {}).report_v2 || {};
  const resolvedTarget = resolveReportTarget(report, v2);
  const missing = [];
  if (!report?.scan_id) missing.push('scan_id');
  if (!resolvedTarget || resolvedTarget === '-') missing.push('target');
  if (!v2.summary) missing.push('state_data.report_v2.summary');
  if (!Array.isArray(v2.vulnerability_table)) missing.push('state_data.report_v2.vulnerability_table');
  if (!Array.isArray(v2.category_scores)) missing.push('state_data.report_v2.category_scores');

  if (missing.length) {
    console.warn('Campos ausentes no relatório:', missing);
    const warn = document.createElement('div');
    warn.className = 'no-print';
    warn.style.cssText = 'position:fixed;top:16px;left:16px;z-index:9999;background:#7f1d1d;color:#fecaca;border:1px solid #b91c1c;padding:10px 12px;border-radius:8px;font-size:12px;max-width:560px';
    warn.textContent = `Atenção: campos ausentes no payload (${missing.join(', ')}). O relatório exibirá fallback.`;
    document.body.appendChild(warn);
  }
}

function normalizeCategoryScores(rawCategoryScores) {
  const list = Array.isArray(rawCategoryScores)
    ? rawCategoryScores
    : Object.entries(rawCategoryScores || {}).map(([category, value]) => ({ category, ...(value || {}) }));

  return list
    .map((item) => {
      const score = Number(item?.score);
      const findings = Number(item?.findings ?? item?.count ?? item?.total ?? 0);
      return {
        category: item?.category || '-',
        score: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : null,
        findings: Number.isFinite(findings) ? Math.max(0, findings) : 0,
      };
    })
    .filter((item) => item.category && item.category !== '-');
}

function renderCategoryBars(rawCategoryScores = [], total = 0) {
  const container = document.getElementById('categoryContainer');
  if (!container) return;
  const categoryScores = normalizeCategoryScores(rawCategoryScores);
  if (categoryScores.length === 0) {
    container.innerHTML = '<div class="section-intro">Sem dados de categorias no payload.</div>';
    return;
  }

  const rows = categoryScores
    .slice()
    .sort((a, b) => Number(b?.findings || 0) - Number(a?.findings || 0))
    .map((c, idx) => {
      const count = Number(c?.findings || 0);
      const pct = Number.isFinite(c?.score) && c?.score != null
        ? c.score
        : (total > 0 ? Math.round((count / total) * 100) : 0);

      let level = 'Crítico';
      let cls = 'score-critical';
      if (pct >= 85) {
        level = 'Excelente';
        cls = 'score-excellent';
      } else if (pct >= 70) {
        level = 'Bom';
        cls = 'score-good';
      } else if (pct >= 50) {
        level = 'Atenção';
        cls = 'score-warning';
      }

      return `
      <tr class="category-row" style="--score:${Math.max(1, pct)}%">
        <td class="category-index">${idx + 1}</td>
        <td class="category-name">${esc(c?.category || '-')}</td>
        <td class="category-score-cell">
          <div class="category-score-wrap">
            <div class="category-score-value">${pct}%</div>
            <div class="category-score-track">
              <div class="category-score-fill"></div>
            </div>
          </div>
        </td>
        <td class="category-findings">${count}</td>
        <td class="category-level"><span class="score-pill ${cls}">${level}</span></td>
      </tr>`;
    })
    .join('');

  container.innerHTML = `
    <div class="category-table-wrap">
      <table class="category-table" aria-label="Tabela de categorias de risco">
        <thead>
          <tr>
            <th>#</th>
            <th>Categoria</th>
            <th>Score</th>
            <th>Achados</th>
            <th>Nível</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>`;
}

function renderVulnCard(vuln, index) {
  const sev = getSevConfig(vuln.severity);
  const cvss = vuln.cvss && vuln.cvss !== '-' ? Number(vuln.cvss).toFixed(1) : '-';
  const cve = vuln.cve && vuln.cve !== '-' ? vuln.cve : null;
  const id = `vuln-${index}`;

  // Consolidação: usa target_summary quando disponível (contém resumo de todos os alvos)
  const displayTarget = vuln.target_summary || vuln.target || vuln.asset || '-';
  const affectedAssets = Array.isArray(vuln.affected_assets) ? vuln.affected_assets.filter(Boolean) : [];
  const affectedCount = Number(vuln.affected_count || 0);
  const affectedPorts = Array.isArray(vuln.affected_ports) ? vuln.affected_ports.filter(p => p && p !== '-') : [];

  const evidence = vuln.evidence && vuln.evidence !== '-' ? vuln.evidence : null;
  const payload = vuln.payload && vuln.payload !== '-' ? vuln.payload : null;
  const rec = vuln.recommendation || 'Ver documentação do achado.';
  const validation = Array.isArray(vuln?.recommendation_validation) && vuln.recommendation_validation.length
    ? vuln.recommendation_validation.join(' | ')
    : '-';

  // Bloco de alvos afetados — exibido quando há mais de 1 ativo afetado
  const affectedBlock = affectedCount > 1 ? `
      <div class="vuln-affected-box">
        <div class="vuln-detail-label"><i class="fas fa-sitemap"></i> Alvos afetados (${affectedCount})</div>
        <div class="vuln-affected-pills">
          ${affectedAssets.map(a => `<span class="affected-pill">${esc(a)}</span>`).join('')}
          ${affectedPorts.length ? `<span class="affected-pill affected-pill-port"><i class="fas fa-plug"></i> ${esc(affectedPorts.join(', '))}</span>` : ''}
        </div>
      </div>` : '';

  // data-search inclui todos os alvos para que o filtro de texto funcione
  const searchAttr = [vuln.name || vuln.problem, displayTarget, cve || '', ...affectedAssets].join(' ');

  return `
<div class="vuln-card ${sev.cls}" data-sev="${String(vuln.severity || 'info').toLowerCase()}" data-search="${esc(searchAttr)}" id="${id}">
  <div class="vuln-card-header" onclick="toggleVuln('${id}')">
    <div>
      <span class="vuln-sev-badge"><i class="fas ${sev.icon}"></i> ${sev.label}</span>
    </div>
    <div>
      <div class="vuln-title">${esc(vuln.name || vuln.problem || 'Achado sem descrição')}</div>
      <div class="vuln-target">${esc(displayTarget)}${affectedCount > 1 ? ` <span class="affected-count-badge">${affectedCount} alvos</span>` : ''}</div>
    </div>
    <div class="vuln-cvss">CVSS ${cvss}</div>
    <div class="vuln-toggle"><i class="fas fa-chevron-down"></i></div>
  </div>
  <div class="vuln-card-body">
    <div class="vuln-detail-grid">
      <div class="vuln-detail-item">
        <div class="vuln-detail-label"><i class="fas fa-tag"></i> ID do Achado</div>
        <div class="vuln-detail-value">${esc(vuln.id || '-')} ${cve ? `| <strong style="color:#f87171">${esc(cve)}</strong>` : ''}</div>
      </div>
      <div class="vuln-detail-item">
        <div class="vuln-detail-label"><i class="fas fa-layer-group"></i> Categoria</div>
        <div class="vuln-detail-value">${esc(vuln.category || '-')}</div>
      </div>
      <div class="vuln-detail-item">
        <div class="vuln-detail-label"><i class="fas fa-route"></i> Etapa do Scan</div>
        <div class="vuln-detail-value">${esc(vuln.step || '-')} | Node: <code>${esc(vuln.node || '-')}</code></div>
      </div>
      <div class="vuln-detail-item">
        <div class="vuln-detail-label"><i class="fas fa-tools"></i> Ferramenta</div>
        <div class="vuln-detail-value">${esc(vuln.tool || '-')}</div>
      </div>
      ${affectedBlock}
      ${evidence ? `
      <div class="vuln-evidence-box">
        <div class="vuln-detail-label"><i class="fas fa-microscope"></i> Evidência</div>
        <div class="vuln-code">${esc(truncate(evidence, 800))}</div>
      </div>` : ''}
      ${payload && payload !== evidence ? `
      <div class="vuln-evidence-box" style="border-left-color:#facc15">
        <div class="vuln-detail-label" style="color:#facc15"><i class="fas fa-terminal"></i> Payload</div>
        <div class="vuln-code" style="color:#facc15">${esc(truncate(payload, 500))}</div>
      </div>` : ''}
      <div class="vuln-rec-box">
        <div class="vuln-detail-label"><i class="fas fa-wrench"></i> Recomendação</div>
        <div class="vuln-detail-value">${esc(rec)}</div>
      </div>
      <div class="vuln-detail-item">
        <div class="vuln-detail-label"><i class="fas fa-check-double"></i> Validação Pós-Remediação</div>
        <div class="vuln-detail-value">${esc(validation)}</div>
      </div>
    </div>
  </div>
</div>`;
}

function renderGroupHeader(problem, count, sev) {
  const cfg = getSevConfig(sev);
  return `
<div class="vuln-group-header">
  <span class="vuln-sev-badge ${cfg.cls}">
    <i class="fas ${cfg.icon}"></i> ${cfg.label}
  </span>
  <span class="vgh-name">${esc(problem)}</span>
  <span class="vgh-count">${count} afetado${count > 1 ? 's' : ''}</span>
</div>`;
}

let allVulns = [];
let currentFilter = 'all';
let currentSearch = '';

window.toggleVuln = function(id) {
  const card = document.getElementById(id);
  if (!card) return;
  card.classList.toggle('expanded');
};

window.filterVulns = function(sev) {
  currentFilter = sev;
  document.querySelectorAll('.chip').forEach((c) => c.classList.remove('active'));
  const activeChip = document.querySelector(`.chip-${sev === 'all' ? 'all' : sev}`);
  if (activeChip) activeChip.classList.add('active');
  renderFiltered();
};

function renderFiltered() {
  const container = document.getElementById('vulnContainer');
  if (!container) return;

  const filtered = allVulns
    .filter((v) => {
      const sevMatch = currentFilter === 'all' || String(v.severity || 'info').toLowerCase() === currentFilter;
      const search = currentSearch.toLowerCase();
      const searchMatch = !search
        || String(v.name || v.problem || '').toLowerCase().includes(search)
        || String(v.target || '').toLowerCase().includes(search)
        || String(v.cve || '').toLowerCase().includes(search)
        || String(v.category || '').toLowerCase().includes(search);
      return sevMatch && searchMatch;
    })
    .sort((a, b) => {
      const ao = getSevConfig(a.severity).order;
      const bo = getSevConfig(b.severity).order;
      if (ao !== bo) return ao - bo;
      return String(a.name || a.problem || '').localeCompare(String(b.name || b.problem || ''));
    });

  const summary = document.getElementById('filterSummary');
  if (summary) {
    const counts = {
      critical: filtered.filter((v) => String(v.severity || '').toLowerCase() === 'critical').length,
      high: filtered.filter((v) => String(v.severity || '').toLowerCase() === 'high').length,
      medium: filtered.filter((v) => String(v.severity || '').toLowerCase() === 'medium').length,
      low: filtered.filter((v) => String(v.severity || '').toLowerCase() === 'low').length,
      info: filtered.filter((v) => !['critical', 'high', 'medium', 'low'].includes(String(v.severity || '').toLowerCase())).length,
    };
    summary.innerHTML = `<strong>${filtered.length}</strong> achados exibidos`;
    Object.entries(counts).forEach(([k, v]) => {
      if (v > 0) summary.innerHTML += ` | <span style="color:var(--${k})">${v} ${k}</span>`;
    });
  }

  if (filtered.length === 0) {
    container.innerHTML = '<div style="text-align:center;padding:40px;color:#64748b">Nenhum achado encontrado para o filtro atual.</div>';
    return;
  }

  const grouped = {};
  filtered.forEach((v) => {
    const key = v.name || v.problem || 'Outros';
    if (!grouped[key]) grouped[key] = { sev: v.severity, items: [] };
    grouped[key].items.push(v);
  });

  let html = '';
  let globalIdx = 0;
  Object.entries(grouped).forEach(([problem, group]) => {
    html += '<div class="vuln-group" style="margin-bottom:16px">';
    html += renderGroupHeader(problem, group.items.length, group.sev);
    group.items.forEach((v) => {
      html += renderVulnCard(v, globalIdx++);
    });
    html += '</div>';
  });

  container.innerHTML = html;
}

async function loadReportFromApi() {
  const token = await ensureAccessToken();

  const limits = [100, 50, 10];
  let lastError = null;

  for (const limit of limits) {
    const res = await fetch(`${API_BASE_URL}/api/scans/${SCAN_ID}/report?prioritized_limit=${limit}&prioritized_offset=0`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      return res.json();
    }
    let detail = '';
    try {
      const body = await res.json();
      detail = body?.detail ? ` - ${body.detail}` : '';
    } catch {
      detail = '';
    }
    lastError = new Error(`Falha ao buscar ${API_BASE_URL}/api/scans/${SCAN_ID}/report?prioritized_limit=${limit} (HTTP ${res.status}${detail})`);
  }

  throw lastError || new Error(`Falha ao buscar ${API_BASE_URL}/api/scans/${SCAN_ID}/report`);
}

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
    `Sem token de acesso. Faça login na aplicação principal ou abra com parametros email/senha e opcionalmente api_url. Exemplo: ?scan_id=${SCAN_ID}&api_url=${encodeURIComponent(API_BASE_URL)}&email=admin@example.com&password=admin123`,
  );
}

function applyTopVariables(report) {
  const v2 = (report?.state_data || {}).report_v2 || {};
  const summary = v2.summary || {};
  const displayed = computeDisplayedSummary(summary, v2.vulnerability_table);

  const org = resolveReportTarget(report, v2);
  const createdAt = report?.created_at || new Date().toISOString();

  setText('orgName', org);
  setText('scanDate', fmtDate(createdAt));
  setText('scanRef', `scan_${report?.scan_id || SCAN_ID}_report`);

  setText('kpiCritical', displayed.critical);
  setText('kpiHigh', displayed.high);
  setText('kpiMedium', displayed.medium);
  setText('kpiLow', displayed.low);
  setText('kpiInfo', displayed.info);

  const total = Number(displayed.total || 0);
  const intro = `Esta avaliação de segurança identificou ${total} achados na superfície de ataque externa do domínio ${org}. A análise consolidada foi carregada diretamente da base de dados via API do backend.`;
  setText('execIntroText', intro);

  renderCategoryBars(v2.category_scores || [], total);
  renderFairAndBenchmark(report);
  renderBenchmarkComparison(report);

  setText('footerOrg', org);
  setText('footerDate', fmtDate(createdAt));
  setText('footerScanId', report?.scan_id || SCAN_ID);
  setText('footerTotal', total);
}

function renderLLMRisk(report) {
  const v2 = (report?.state_data || {}).report_v2 || {};
  const llm = v2.llm_risk || {};

  setText('llmRiskStatus', llm.status || (llm.enabled === false ? 'disabled' : '-'));
  setText('llmRiskLevel', llm.risk_level || '-');
  setText('llmRiskTotal', llm.total_tests ?? '-');
  setText('llmRiskFailed', llm.failed_tests ?? '-');
  setText('llmRiskPassRate', llm.pass_rate != null ? `${llm.pass_rate}%` : '-');
  setText('llmRiskStrategies', Array.isArray(llm.strategies) ? llm.strategies.join(', ') : '-');

  const container = document.getElementById('llmRiskFindings');
  if (!container) return;
  const findings = Array.isArray(llm.findings) ? llm.findings : [];
  if (!findings.length) {
    container.innerHTML = '<div class="section-intro">Sem achados de LLM Risk para este scan.</div>';
    return;
  }

  container.innerHTML = findings.slice(0, 20).map((row) => `
    <div class="llm-risk-row">
      <div class="llm-risk-row-top">
        <strong>${esc(row.strategy || '-')}</strong>
        <span class="llm-risk-sev">${esc(row.severity || 'low')}</span>
      </div>
      <div class="llm-risk-reason">${esc(row.reason || '-')}</div>
    </div>
  `).join('');
}

function assignPageNumbers() {
  document.querySelectorAll('.page').forEach((p, i) => {
    p.setAttribute('data-page', `Pág. ${i + 1}`);
  });
}

function injectPrintButton() {
  const box = document.createElement('div');
  box.className = 'no-print';
  box.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px';
  box.innerHTML = `
    <button onclick="window.printReport()" style="background:linear-gradient(135deg,#3b82f6,#22d3ee);border:none;color:#fff;font-weight:700;padding:12px 20px;border-radius:8px;cursor:pointer;font-family:inherit;font-size:0.85rem;display:flex;align-items:center;gap:8px;box-shadow:0 4px 24px rgba(59,130,246,0.4)">
      <i class="fas fa-print"></i> Imprimir / PDF
    </button>
    <button onclick="window.toggleAll()" style="background:#1e293b;border:1px solid #334155;color:#94a3b8;font-weight:600;padding:8px 16px;border-radius:8px;cursor:pointer;font-family:inherit;font-size:0.78rem;display:flex;align-items:center;gap:6px">
      <i class="fas fa-expand-alt"></i> Expandir Todos
    </button>
  `;
  document.body.appendChild(box);
}

let allExpanded = false;
window.toggleAll = function() {
  allExpanded = !allExpanded;
  document.querySelectorAll('.vuln-card').forEach((c) => {
    c.classList.toggle('expanded', allExpanded);
  });
};

window.printReport = function() {
  document.querySelectorAll('.vuln-card').forEach((card) => card.classList.add('expanded'));
  setTimeout(() => window.print(), 250);
};

function injectGroupStyles() {
  const style = document.createElement('style');
  style.textContent = `
    .vuln-group-header {display:flex;align-items:center;gap:10px;padding:8px 12px;background:rgba(255,255,255,0.02);border:1px solid #1e293b;border-radius:6px;margin-bottom:6px}
    .vgh-name {flex:1;font-size:0.82rem;font-weight:600;color:#f1f5f9}
    .vgh-count {font-size:0.72rem;color:#64748b;background:rgba(255,255,255,0.04);padding:3px 10px;border-radius:20px;border:1px solid #1e293b}
  `;
  document.head.appendChild(style);
}

document.addEventListener('DOMContentLoaded', async () => {
  assignPageNumbers();
  injectPrintButton();
  injectGroupStyles();

  const searchInput = document.getElementById('filterSearch');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      currentSearch = e.target.value;
      renderFiltered();
    });
  }

  try {
    const report = await loadReportFromApi();
    validateReportData(report);
    applyTopVariables(report);
    renderLLMRisk(report);
    const v2 = (report?.state_data || {}).report_v2 || {};
    allVulns = Array.isArray(v2.vulnerability_table)
      ? v2.vulnerability_table
      : (Array.isArray(report?.findings) ? report.findings : []);
    renderFiltered();
  } catch (err) {
    console.error(err);
    const container = document.getElementById('vulnContainer');
    if (container) {
      container.innerHTML = `<div style="text-align:center;padding:40px;color:#94a3b8"><i class="fas fa-exclamation-circle" style="font-size:2rem;color:#ef4444;margin-bottom:12px;display:block"></i><strong>Não foi possível carregar os dados do relatório.</strong><br><span style="font-size:0.8rem;color:#64748b">${esc(err.message)}</span></div>`;
    }
  }
});