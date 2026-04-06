// Pentest.io Dashboard Components - FAIR Pillars, Temporal Curves, Score Highlight

function aggregationSubtitle(mode, targets) {
  const n = Number(targets || 1);
  if (mode === "target") {
    return `Contexto: Alvo (${n} alvo)`;
  }
  if (mode === "group_avg") {
    return `Contexto: Media do Grupo (${n} alvos)`;
  }
  return `Contexto: Global (media dos scanners, ${n} alvos)`;
}

export function EASMRatingCard({ rating, grade, aggregationMode = "global", aggregationTargets = 1 }) {
  const gradeColors = {
    A: "text-emerald-400 border-emerald-500/50",
    B: "text-cyan-400 border-cyan-500/50",
    C: "text-yellow-400 border-yellow-500/50",
    D: "text-orange-400 border-orange-500/50",
    F: "text-red-400 border-red-500/50",
  };

  const color = gradeColors[grade] || gradeColors.F;
  const scoreColor = rating >= 80 ? "text-emerald-400" : rating >= 60 ? "text-yellow-400" : "text-red-400";

  return (
    <div className={`rounded-2xl border ${color} bg-slate-900/60 p-6`}>
      <p className="text-xs uppercase tracking-widest text-slate-400">Pentest.io Rating</p>
      <p className="mt-1 text-xs text-slate-500">{aggregationSubtitle(aggregationMode, aggregationTargets)}</p>
      <div className="mt-3 flex items-baseline gap-3">
        <p className={`text-5xl font-bold ${scoreColor}`}>{rating.toFixed(1)}</p>
      </div>
      <div className="mt-4 h-2 rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full ${scoreColor === "text-emerald-400" ? "bg-emerald-500" : scoreColor === "text-yellow-400" ? "bg-yellow-500" : "bg-red-500"}`}
          style={{ width: `${rating}%` }}
        />
      </div>
    </div>
  );
}

export function FAIRPillarsCard({ decomposition }) {
  if (!decomposition || !decomposition.pillars) {
    return <div className="text-slate-500">Sem dados de pillares FAIR</div>;
  }

  const pillarNames = {
    perimeter_resilience: "Resiliência Perímetro",
    patching_hygiene: "Higiene Patching",
    osint_exposure: "Exposição OSINT",
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
      <p className="text-xs uppercase tracking-widest text-slate-400">FAIR Decomposition</p>
      <div className="mt-4 space-y-3">
        {decomposition.pillars.map((pillar) => (
          <div key={pillar.id}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium text-slate-300">
                {pillarNames[pillar.id] || pillar.name}
              </span>
              <span className="text-sm font-bold text-cyan-400">{pillar.score.toFixed(1)}</span>
            </div>
            <div className="h-2 rounded-full bg-slate-800">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-cyan-400"
                style={{ width: `${(pillar.score / 100) * 100}%` }}
              />
            </div>
            <div className="mt-1 flex items-center justify-between">
              <span className="text-xs text-slate-500">{pillar.finding_count} achados</span>
              <span className="text-xs text-slate-400">{pillar.weight_pct} peso</span>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 rounded border border-slate-700 bg-slate-900/40 p-3">
        <p className="text-xs text-slate-400">
          <strong>Score Total:</strong> {decomposition.score.toFixed(2)} ({decomposition.grade})
        </p>
        <p className="mt-1 text-xs text-slate-500">{decomposition.n_assets} assets analisados</p>
      </div>
    </div>
  );
}

export function TemporalCurveCard({ trends }) {
  if (!trends) {
    return <div className="text-slate-500">Sem dados temporais</div>;
  }

  const velocity = trends.remediation_velocity || {};
  const posture = trends.posture_deviation || {};
  const forecast = trends.forecast_30d || {};

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
      <p className="text-xs uppercase tracking-widest text-slate-400">Temporal Analysis</p>

      <div className="mt-4 grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs text-slate-400">Remediation Velocity</p>
          <p className="text-2xl font-bold text-emerald-400">
            {(velocity.velocity_pct || 0).toFixed(1)}%
          </p>
          <p className="text-xs text-slate-500 capitalize">{velocity.trend || "unknown"}</p>
        </div>
        <div>
          <p className="text-xs text-slate-400">Rating Deviation (24h)</p>
          <p className={`text-2xl font-bold ${posture.deviation < 0 ? "text-red-400" : "text-emerald-400"}`}>
            {posture.deviation > 0 ? "+" : ""}{posture.deviation?.toFixed(1) || 0}
          </p>
          <p className="text-xs text-slate-500">{posture.cause || "stable"}</p>
        </div>
      </div>

      {forecast.current_rating && (
        <div className="mt-4 rounded border border-slate-700 bg-slate-900/40 p-3">
          <p className="text-xs text-slate-400">
            Forecast 30 dias:{" "}
            <strong className="text-cyan-400">
              {forecast.current_rating?.toFixed(1)} → {forecast.forecast_30d?.toFixed(1)}
            </strong>
          </p>
          <p className="text-xs text-slate-500 mt-1">Drivers: {forecast.key_drivers?.join(", ") || "N/A"}</p>
        </div>
      )}
    </div>
  );
}

export function ExecutiveSummaryCard({ easm_rating, easm_grade, ratingTimeline = [] }) {
  const score = Number(easm_rating || 0);
  const grade = String(easm_grade || "F");
  const scoreColor = score >= 80 ? "text-emerald-300" : score >= 60 ? "text-yellow-300" : "text-rose-300";

  return (
    <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-cyan-900/30 to-blue-900/30 p-6">
      <p className="text-xs uppercase tracking-widest text-slate-300">Pentest.io</p>
      <p className="mt-2 text-sm text-slate-300">Nota consolidada da analise principal</p>
      <div className="mt-4 flex items-end justify-between gap-4">
        <div className="flex items-baseline gap-3">
          <p className={`text-6xl font-bold font-display ${scoreColor}`}>{score.toFixed(1)}</p>
          <p className="text-2xl font-semibold text-cyan-200">/100</p>
        </div>
        <div className="rounded-lg border border-cyan-400/40 bg-cyan-500/10 px-3 py-2 text-right">
          <p className="text-xs uppercase tracking-widest text-cyan-200">Grade</p>
          <p className="text-3xl font-bold text-cyan-100">{grade}</p>
        </div>
      </div>
    </div>
  );
}

export function AlertsCard({ alerts }) {
  if (!alerts || alerts.length === 0) {
    return null;
  }

  const severityColor = {
    critical: "bg-red-500/20 border-red-500/50 text-red-400",
    high: "bg-orange-500/20 border-orange-500/50 text-orange-400",
    medium: "bg-yellow-500/20 border-yellow-500/50 text-yellow-400",
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
      <p className="text-xs uppercase tracking-widest text-slate-400">Active Alerts ({alerts.length})</p>
      <div className="mt-4 space-y-2">
        {alerts.slice(0, 5).map((alert) => (
          <div key={alert.id} className={`rounded border p-3 ${severityColor[alert.severity] || severityColor.medium}`}>
            <p className="text-sm font-medium">{alert.title}</p>
            <p className="text-xs mt-1 opacity-80">{alert.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AssetListCard({ assets }) {
  if (!assets || assets.length === 0) {
    return <div className="text-slate-500">Nenhum asset registrado</div>;
  }

  const gradeColor = (grade) => {
    const map = {
      A: "text-emerald-400",
      B: "text-cyan-400",
      C: "text-yellow-400",
      D: "text-orange-400",
      F: "text-red-400",
    };
    return map[grade] || "text-slate-400";
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
      <p className="text-xs uppercase tracking-widest text-slate-400 mb-4">Top Assets (Pentest.io Rating)</p>
      <div className="space-y-2">
        {assets.slice(0, 10).map((asset) => (
          <div key={asset.id} className="flex items-center justify-between rounded border border-slate-700 p-3 hover:bg-slate-800/40 transition">
            <div>
              <p className="text-sm font-medium text-slate-300">{asset.domain_or_ip}</p>
              <p className="text-xs text-slate-500">
                {asset.open_critical > 0 && <span className="text-red-400">{asset.open_critical} crítica(s) </span>}
                {asset.open_high > 0 && <span className="text-orange-400">{asset.open_high} alta(s) </span>}
              </p>
            </div>
            <div className="text-right">
              <p className={`text-lg font-bold ${gradeColor(asset.easm_grade)}`}>
                {asset.easm_grade}
              </p>
              <p className="text-xs text-slate-500">{asset.easm_rating.toFixed(0)}/100</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
