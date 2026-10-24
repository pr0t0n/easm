// API Security module — standalone OWASP API Top 10 testing.
// Sibling to SCAN and BAS. Takes a base URL + an API spec
// (OpenAPI/Swagger/Postman/HAR/GraphQL) and runs only the API security phase
// (P16): BOLA, BFLA, broken auth, injection, mass assignment, SSRF, etc.
// Backend: POST /api/apitest (a ScanJob with mode="api", scan_level="api").
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";
import { toastError, toastSuccess } from "../utils/toast";

const SPEC_TYPES = [
  { value: "openapi", label: "OpenAPI / Swagger (JSON)" },
  { value: "postman", label: "Postman Collection" },
  { value: "har", label: "HAR (tráfego capturado)" },
  { value: "graphql", label: "GraphQL (introspection)" },
];

const TERMINAL = new Set(["completed", "completed_with_gaps", "failed", "stopped", "cancelled", "canceled"]);
const STOPPABLE = new Set(["queued", "running", "retrying", "paused"]);
const FINALIZABLE = new Set(["blocked", "waiting_for_auth"]);

function statusColor(status) {
  const s = String(status || "").toLowerCase();
  if (s === "completed") return "var(--sev-low-text, #16a34a)";
  if (s === "completed_with_gaps") return "var(--sev-medium-text, #d97706)";
  if (s === "failed" || s === "blocked") return "var(--sev-high-text, #dc2626)";
  if (s === "running" || s === "queued" || s === "retrying") return "var(--brand, #2563eb)";
  return "var(--ink-muted, #64748b)";
}

export default function ApiScanPage() {
  const navigate = useNavigate();
  const [targetUrl, setTargetUrl] = useState("");
  const [specMode, setSpecMode] = useState("paste"); // "paste" | "url"
  const [specUrl, setSpecUrl] = useState("");
  const [specJson, setSpecJson] = useState("");
  const [specType, setSpecType] = useState("openapi");
  const [allowMutations, setAllowMutations] = useState(false);
  const [attested, setAttested] = useState(false);
  const [accessGroupId, setAccessGroupId] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const [tests, setTests] = useState([]);
  const [loading, setLoading] = useState(true);
  const pollRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const { data } = await client.get("/api/apitest");
      setTests(Array.isArray(data) ? data : []);
    } catch (err) {
      // keep the previous list on transient errors
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 5000);
    return () => pollRef.current && clearInterval(pollRef.current);
  }, [load]);

  const specValid = useMemo(() => {
    if (specMode === "url") return specUrl.trim().length > 0;
    const t = specJson.trim();
    if (!t) return false;
    try { JSON.parse(t); return true; } catch { return false; }
  }, [specMode, specUrl, specJson]);

  const canSubmit = targetUrl.trim() && specValid && attested && !submitting;

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    let payload;
    try {
      payload = {
        target_url: targetUrl.trim(),
        spec_type: specType,
        allow_mutations: allowMutations,
        active_level: "safe",
        scope_authorization_attested: attested,
        access_group_id: accessGroupId ? Number(accessGroupId) : undefined,
      };
      if (specMode === "url") payload.spec_url = specUrl.trim();
      else payload.spec_payload = JSON.parse(specJson);
    } catch (err) {
      toastError("Spec JSON inválido.");
      return;
    }
    setSubmitting(true);
    try {
      const { data } = await client.post("/api/apitest", payload);
      toastSuccess(`Teste de API #${data.id} criado — ingestão e OWASP API Top 10 em execução.`);
      setSpecJson(""); setSpecUrl("");
      load();
    } catch (err) {
      const detail = err?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : (detail?.reason || "Falha ao criar teste de API."));
    } finally {
      setSubmitting(false);
    }
  }

  async function act(id, action) {
    try {
      await client.post(`/api/apitest/${id}/${action}`);
      toastSuccess(`Teste #${id}: ${action === "stop" ? "interrompido" : "finalizado"}.`);
      load();
    } catch (err) {
      const detail = err?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : `Falha ao ${action}.`);
    }
  }

  const card = { background: "var(--surface, #fff)", border: "1px solid var(--border, #e2e8f0)", borderRadius: 12, padding: 18 };
  const label = { display: "block", fontSize: 12, fontWeight: 700, color: "var(--ink-muted)", marginBottom: 5 };
  const input = { width: "100%", padding: "9px 11px", borderRadius: 8, border: "1px solid var(--border, #e2e8f0)", background: "var(--surface-2, #f8fafc)", color: "var(--ink)", fontSize: 13 };

  return (
    <div style={{ padding: "22px 26px", maxWidth: 1180, margin: "0 auto" }}>
      <div style={{ marginBottom: 16 }}>
        <div className="sk-eyebrow">Módulo</div>
        <h1 style={{ margin: "2px 0 4px", fontSize: 22, fontWeight: 800, color: "var(--ink)" }}>API Security</h1>
        <p style={{ margin: 0, fontSize: 13, color: "var(--ink-muted)", maxWidth: 760 }}>
          Teste de segurança de API orientado por spec — OWASP API Top 10 (BOLA, BFLA, broken authentication,
          injection, mass assignment, SSRF, etc.). Informe a URL base e a especificação (OpenAPI/Swagger, Postman,
          HAR ou GraphQL). Só a fase de API é executada — sem recon/port-scan.
        </p>
      </div>

      <form onSubmit={submit} style={{ ...card, marginBottom: 20 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div>
            <label style={label}>URL base da API *</label>
            <input style={input} placeholder="api.exemplo.com.br ou https://api.exemplo.com.br"
              value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} />
          </div>
          <div>
            <label style={label}>Escopo / empresa</label>
            <CompanyScopeSelect value={accessGroupId} onChange={setAccessGroupId} />
          </div>
        </div>

        <div style={{ marginTop: 14 }}>
          <div style={{ display: "flex", gap: 14, alignItems: "center", marginBottom: 8 }}>
            <label style={{ ...label, marginBottom: 0 }}>Especificação *</label>
            <div className="sk-mono" style={{ display: "flex", gap: 6, fontSize: 11 }}>
              <button type="button" onClick={() => setSpecMode("paste")}
                style={{ padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border)", cursor: "pointer",
                  background: specMode === "paste" ? "var(--brand, #2563eb)" : "transparent",
                  color: specMode === "paste" ? "#fff" : "var(--ink-muted)" }}>Colar JSON</button>
              <button type="button" onClick={() => setSpecMode("url")}
                style={{ padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border)", cursor: "pointer",
                  background: specMode === "url" ? "var(--brand, #2563eb)" : "transparent",
                  color: specMode === "url" ? "#fff" : "var(--ink-muted)" }}>URL do spec</button>
            </div>
            <select style={{ ...input, width: "auto", marginLeft: "auto" }} value={specType} onChange={(e) => setSpecType(e.target.value)}>
              {SPEC_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          {specMode === "url" ? (
            <input style={input} placeholder="https://api.exemplo.com.br/openapi.json"
              value={specUrl} onChange={(e) => setSpecUrl(e.target.value)} />
          ) : (
            <textarea style={{ ...input, minHeight: 150, fontFamily: "monospace", fontSize: 12 }}
              placeholder='Cole aqui o conteúdo do Swagger/OpenAPI/Collection/JSON…'
              value={specJson} onChange={(e) => setSpecJson(e.target.value)} />
          )}
          {specMode === "paste" && specJson.trim() && !specValid && (
            <div style={{ color: "var(--sev-high-text, #dc2626)", fontSize: 11, marginTop: 4 }}>JSON inválido.</div>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 18, marginTop: 14, flexWrap: "wrap" }}>
          <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5, color: "var(--ink)", cursor: "pointer" }}>
            <input type="checkbox" checked={allowMutations} onChange={(e) => setAllowMutations(e.target.checked)} />
            Permitir mutações (DAST ativo: POST/PUT/DELETE)
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5, color: "var(--ink)", cursor: "pointer" }}>
            <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
            Declaro autorização para testar este alvo *
          </label>
          <button type="submit" disabled={!canSubmit}
            style={{ marginLeft: "auto", padding: "9px 20px", borderRadius: 8, border: "none", fontWeight: 800, fontSize: 13,
              cursor: canSubmit ? "pointer" : "not-allowed", background: canSubmit ? "var(--brand, #2563eb)" : "var(--border, #cbd5e1)",
              color: "#fff" }}>
            {submitting ? "Criando…" : "Iniciar teste de API"}
          </button>
        </div>
        {allowMutations && (
          <div style={{ color: "var(--sev-medium-text, #d97706)", fontSize: 11, marginTop: 8 }}>
            ⚠ Mutações habilitadas: o DAST ativo pode criar/alterar/remover dados na API de produção.
          </div>
        )}
      </form>

      <div style={card}>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 12 }}>
          <h2 style={{ margin: 0, fontSize: 15, fontWeight: 800, color: "var(--ink)" }}>Testes de API</h2>
          <span className="sk-mono" style={{ marginLeft: 8, fontSize: 11, color: "var(--ink-muted)" }}>{tests.length}</span>
        </div>
        {loading ? (
          <div style={{ color: "var(--ink-muted)", fontSize: 13, padding: "20px 0" }}>Carregando…</div>
        ) : tests.length === 0 ? (
          <div style={{ color: "var(--ink-muted)", fontSize: 13, padding: "20px 0" }}>Nenhum teste de API ainda. Crie o primeiro acima.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="sk-mono" style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--ink-muted)", borderBottom: "1px solid var(--border)" }}>
                  <th style={{ padding: "7px 8px" }}>#</th>
                  <th style={{ padding: "7px 8px" }}>Alvo</th>
                  <th style={{ padding: "7px 8px" }}>Status</th>
                  <th style={{ padding: "7px 8px" }}>Progresso</th>
                  <th style={{ padding: "7px 8px" }}>Achados</th>
                  <th style={{ padding: "7px 8px" }}>Ações</th>
                </tr>
              </thead>
              <tbody>
                {tests.map((t) => {
                  const s = String(t.status || "").toLowerCase();
                  const sev = [
                    t.open_critical ? `${t.open_critical}C` : null,
                    t.open_high ? `${t.open_high}H` : null,
                    t.open_medium ? `${t.open_medium}M` : null,
                    t.open_low ? `${t.open_low}L` : null,
                  ].filter(Boolean).join(" · ") || "—";
                  return (
                    <tr key={t.id} style={{ borderBottom: "1px solid var(--border)" }}>
                      <td style={{ padding: "7px 8px", fontWeight: 800 }}>{t.id}</td>
                      <td style={{ padding: "7px 8px", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={t.target_query}>{t.target_query}</td>
                      <td style={{ padding: "7px 8px", fontWeight: 800, color: statusColor(s) }}>{t.status}</td>
                      <td style={{ padding: "7px 8px" }}>{t.mission_progress}%</td>
                      <td style={{ padding: "7px 8px", color: t.open_critical ? "var(--sev-high-text, #dc2626)" : "var(--ink)" }}>{sev}</td>
                      <td style={{ padding: "7px 8px", display: "flex", gap: 6 }}>
                        {TERMINAL.has(s) && (
                          <button type="button" onClick={() => navigate(`/relatorios/tecnico/${t.id}`)}
                            style={{ padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border)", background: "transparent", color: "var(--brand, #2563eb)", cursor: "pointer", fontWeight: 700 }}>Relatório</button>
                        )}
                        {STOPPABLE.has(s) && (
                          <button type="button" onClick={() => act(t.id, "stop")}
                            style={{ padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border)", background: "transparent", color: "var(--sev-high-text, #dc2626)", cursor: "pointer" }}>Parar</button>
                        )}
                        {FINALIZABLE.has(s) && (
                          <button type="button" onClick={() => act(t.id, "finalize")}
                            style={{ padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border)", background: "transparent", color: "var(--sev-medium-text, #d97706)", cursor: "pointer" }}>Finalizar</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
