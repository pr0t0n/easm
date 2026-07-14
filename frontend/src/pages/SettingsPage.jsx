import { useEffect, useState } from "react";
import client from "../api/client";
import { toastError, toastSuccess } from "../utils/toast";

const ROW = { display: "flex", alignItems: "center", gap: 12, marginBottom: 16 };
const LABEL = { width: 160, fontSize: 13, color: "var(--ink-muted)", flexShrink: 0 };
const INPUT = {
  flex: 1, padding: "8px 12px", borderRadius: 8,
  border: "1px solid var(--line)", background: "var(--canvas)",
  fontSize: 13, color: "var(--ink)", fontFamily: "monospace",
};
const BTN = (variant = "primary") => ({
  padding: "8px 18px", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 13,
  background: variant === "primary" ? "var(--brand-600)" : variant === "danger" ? "#b91c1c" : "var(--surface-alt)",
  color: variant === "primary" || variant === "danger" ? "#fff" : "var(--ink)",
});
const CHIP = (ok) => ({
  display: "inline-block", padding: "2px 10px", borderRadius: 99, fontSize: 11,
  background: ok ? "#dcfce7" : "#fee2e2", color: ok ? "#15803d" : "#b91c1c",
});
const CARD = {
  background: "var(--surface)", borderRadius: 12, padding: "24px 28px",
  border: "1px solid var(--line)", marginBottom: 24,
};

export default function SettingsPage() {
  // ── Limpeza operacional ───────────────────────────────────────────────────
  const [resettingOperational, setResettingOperational] = useState(false);
  const [resetSummary, setResetSummary] = useState(null);

  const resetOperationalData = async () => {
    const confirmation = window.prompt(
      "Esta ação remove scans executados, vulnerabilidades, alvos/ativos descobertos, logs e evidências associadas. Agendamentos e configurações serão preservados.\n\nDigite LIMPAR para confirmar."
    );
    if (confirmation !== "LIMPAR") return;

    setResettingOperational(true);
    try {
      const { data } = await client.post("/api/scans/reset-operational");
      setResetSummary(data);
      const deleted = data.deleted || {};
      const preserved = data.preserved || {};
      toastSuccess(
        `Limpeza concluída: ${deleted.scan_jobs || 0} scans, ${deleted.vulnerabilities || 0} vulnerabilidades e ${deleted.assets || 0} alvos/ativos removidos. ${preserved.enabled_schedules || 0} agendamentos preservados.`
      );
    } catch (e) {
      toastError(e?.response?.data?.detail || "Falha ao limpar scans e vulnerabilidades.");
    } finally {
      setResettingOperational(false);
    }
  };

  // ── Shodan ────────────────────────────────────────────────────────────────
  const [shodanKey, setShodanKey] = useState("");
  const [shodanStatus, setShodanStatus] = useState(null); // {configured, enabled, status}
  const [shodanSaving, setShodanSaving] = useState(false);

  const loadShodan = async () => {
    try {
      const { data } = await client.get("/api/config/shodan");
      setShodanStatus(data);
      if (data.api_key) setShodanKey(data.api_key);
    } catch {
      setShodanStatus({ configured: false, enabled: false });
    }
  };

  const saveShodan = async (e) => {
    e.preventDefault();
    if (!shodanKey.trim()) { toastError("Informe a API key do Shodan."); return; }
    setShodanSaving(true);
    try {
      await client.put("/api/config/shodan", { api_key: shodanKey.trim() });
      toastSuccess("Shodan API key salva.");
      loadShodan();
    } catch { toastError("Erro ao salvar API key."); }
    finally { setShodanSaving(false); }
  };

  useEffect(() => { loadShodan(); }, []);

  const shodanOk = shodanStatus?.configured && shodanStatus?.enabled !== false;

  // ── SSO corporativo (Okta / Azure AD) ───────────────────────────────────────
  const SSO_META = {
    okta:  { label: "Okta SSO", swatch: "linear-gradient(135deg,#007dc1,#003a6b)", domainLabel: "Domínio Okta" },
    azure: { label: "Azure AD", swatch: "linear-gradient(135deg,#0078d4,#004b8d)", domainLabel: "Tenant ID" },
  };
  const [sso, setSso] = useState({ okta: {}, azure: {} });
  const [ssoSaving, setSsoSaving] = useState(false);

  const loadSso = async () => {
    try {
      const { data } = await client.get("/api/config/sso");
      setSso(data.providers || { okta: {}, azure: {} });
    } catch { /* mantém vazio */ }
  };
  useEffect(() => { loadSso(); }, []);

  const setSsoField = (prov, field, val) =>
    setSso((s) => ({ ...s, [prov]: { ...s[prov], [field]: val } }));

  const saveSso = async (e) => {
    e.preventDefault();
    setSsoSaving(true);
    try {
      const providers = {};
      for (const p of ["okta", "azure"]) {
        const c = sso[p] || {};
        providers[p] = {
          enabled: !!c.enabled,
          client_id: c.client_id || "",
          tenant_or_domain: c.tenant_or_domain || "",
          metadata_url: c.metadata_url || "",
          ...(c.client_secret ? { client_secret: c.client_secret } : {}),
        };
      }
      await client.put("/api/config/sso", { providers });
      toastSuccess("Configuração de SSO salva.");
      loadSso();
    } catch { toastError("Erro ao salvar SSO."); }
    finally { setSsoSaving(false); }
  };

  // ── Arsenal Kali (módulos click-to-install) ─────────────────────────────────
  const [modules, setModules] = useState([]);
  const [modulesLoading, setModulesLoading] = useState(false);
  const [modulesError, setModulesError] = useState("");
  const [openLog, setOpenLog] = useState(null); // id do módulo com log aberto
  const [moduleBusy, setModuleBusy] = useState({}); // id -> bool

  const loadModules = async () => {
    setModulesLoading(true);
    setModulesError("");
    try {
      const { data } = await client.get("/api/kali-runner/modules");
      setModules(data.modules || []);
    } catch {
      setModulesError("Runner Kali indisponível.");
    } finally {
      setModulesLoading(false);
    }
  };
  useEffect(() => { loadModules(); }, []);

  // Poll enquanto houver algum módulo instalando.
  const anyInstalling = modules.some((m) => m.status === "installing");
  useEffect(() => {
    if (!anyInstalling) return undefined;
    const t = setInterval(loadModules, 3000);
    return () => clearInterval(t);
  }, [anyInstalling]);

  const installModule = async (id) => {
    setModuleBusy((b) => ({ ...b, [id]: true }));
    try {
      await client.post(`/api/kali-runner/modules/${id}/install`);
      toastSuccess(`Instalação de "${id}" iniciada.`);
      setOpenLog(id);
      loadModules();
    } catch (e) {
      toastError(e?.response?.data?.detail || "Falha ao iniciar instalação.");
    } finally {
      setModuleBusy((b) => ({ ...b, [id]: false }));
    }
  };

  const uninstallModule = async (id) => {
    if (!window.confirm(`Remover o módulo "${id}"? As ferramentas serão apagadas do volume.`)) return;
    setModuleBusy((b) => ({ ...b, [id]: true }));
    try {
      await client.post(`/api/kali-runner/modules/${id}/uninstall`);
      toastSuccess(`Módulo "${id}" removido.`);
      loadModules();
    } catch (e) {
      toastError(e?.response?.data?.detail || "Falha ao remover.");
    } finally {
      setModuleBusy((b) => ({ ...b, [id]: false }));
    }
  };

  const MODULE_STATUS = {
    installed:     { label: "✓ Instalado",   color: "#15803d", bg: "#dcfce7" },
    installing:    { label: "⟳ Instalando…", color: "#b45309", bg: "#fef3c7" },
    failed:        { label: "✗ Falhou",      color: "#b91c1c", bg: "#fee2e2" },
    partial:       { label: "⚠ Incompleto",  color: "#b45309", bg: "#fef3c7" },
    not_installed: { label: "Não instalado", color: "var(--ink-muted)", bg: "var(--surface-alt)" },
  };

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", padding: "32px 24px" }}>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>Configurações</h1>
      <p style={{ fontSize: 13, color: "var(--ink-muted)", marginBottom: 28 }}>
        Integrações e chaves de API utilizadas pelos scanners.
      </p>

      {/* ── Manutenção operacional ──────────────────────────────────── */}
      <div style={CARD}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>Manutenção operacional</span>
          <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--ink-muted)" }}>
            somente administradores
          </span>
        </div>
        <p style={{ fontSize: 13, color: "var(--ink-muted)", marginBottom: 18, lineHeight: 1.5 }}>
          Limpa scans já executados, vulnerabilidades, alvos/ativos descobertos, logs,
          evidências e trilhas de agentes associadas. A configuração de agendamento,
          integrações, usuários e parâmetros da plataforma permanece intacta.
        </p>

        {resetSummary && (
          <div style={{
            border: "1px solid var(--line)", borderRadius: 10, padding: "12px 14px",
            marginBottom: 14, background: "var(--surface-alt)",
          }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Última limpeza</div>
            <div style={{ fontSize: 12.5, color: "var(--ink-muted)", lineHeight: 1.5 }}>
              Scans removidos: {resetSummary.deleted?.scan_jobs || 0} · Vulnerabilidades removidas: {resetSummary.deleted?.vulnerabilities || 0} · Alvos/ativos removidos: {resetSummary.deleted?.assets || 0} ·
              Agendamentos preservados: {resetSummary.preserved?.enabled_schedules || 0} · Scans em fila preservados: {resetSummary.preserved?.queued_scans || 0}
            </div>
          </div>
        )}

        <button type="button" style={BTN("danger")} onClick={resetOperationalData} disabled={resettingOperational}>
          {resettingOperational ? "Limpando…" : "Limpar scans e vulnerabilidades"}
        </button>
      </div>

      {/* ── Shodan ──────────────────────────────────────────────────── */}
      <div style={CARD}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>Shodan</span>
          {shodanStatus && (
            <span style={CHIP(shodanOk)}>
              {shodanOk ? "✓ Configurado" : "✗ Não configurado"}
            </span>
          )}
          <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--ink-muted)" }}>
            Fase P18 (OSINT)
          </span>
        </div>

        <p style={{ fontSize: 13, color: "var(--ink-muted)", marginBottom: 18, lineHeight: 1.5 }}>
          Usado na fase P18 para levantamento de IPs/ASN, banners de serviços e exposições
          passivas. Sem a key, o Shodan é ignorado e o OSINT roda sem essa fonte.
        </p>

        <form onSubmit={saveShodan}>
          <div style={ROW}>
            <span style={LABEL}>API Key</span>
            <input
              style={INPUT}
              type="password"
              placeholder="••••••••••••••••••••••••••••••••"
              value={shodanKey}
              onChange={(e) => setShodanKey(e.target.value)}
              autoComplete="off"
            />
          </div>
          {shodanStatus?.status && (
            <div style={{ ...ROW, marginBottom: 20 }}>
              <span style={LABEL}>Status</span>
              <span style={{ fontSize: 13, color: "var(--ink-muted)" }}>{shodanStatus.status}</span>
            </div>
          )}
          <div style={{ display: "flex", gap: 10 }}>
            <button type="submit" style={BTN("primary")} disabled={shodanSaving}>
              {shodanSaving ? "Salvando…" : "Salvar"}
            </button>
            <button type="button" style={BTN("secondary")} onClick={loadShodan}>
              Recarregar
            </button>
          </div>
        </form>
      </div>

      {/* ── SSO corporativo ──────────────────────────────────────────── */}
      <div style={CARD}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>SSO corporativo</span>
          <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--ink-muted)" }}>
            provedores da tela de login
          </span>
        </div>
        <p style={{ fontSize: 13, color: "var(--ink-muted)", marginBottom: 18, lineHeight: 1.5 }}>
          Habilite e configure os provedores de identidade exibidos na tela de login
          (<strong>Okta SSO</strong> e <strong>Azure AD</strong>). O segredo é gravado de
          forma mascarada; deixe em branco para preservar o valor já salvo.
        </p>

        <form onSubmit={saveSso}>
          {["okta", "azure"].map((p) => {
            const meta = SSO_META[p];
            const c = sso[p] || {};
            return (
              <div key={p} style={{ border: "1px solid var(--line)", borderRadius: 10, padding: "16px 18px", marginBottom: 16 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                  <span style={{ width: 16, height: 16, borderRadius: 5, background: meta.swatch, flexShrink: 0 }} />
                  <span style={{ fontSize: 14, fontWeight: 600 }}>{meta.label}</span>
                  {c.configured && <span style={CHIP(true)}>✓ Configurado</span>}
                  <label style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 7, fontSize: 12.5, color: "var(--ink-soft)", cursor: "pointer" }}>
                    <input type="checkbox" checked={!!c.enabled} onChange={(e) => setSsoField(p, "enabled", e.target.checked)} />
                    Habilitado
                  </label>
                </div>
                <div style={ROW}>
                  <span style={LABEL}>Client ID</span>
                  <input style={INPUT} value={c.client_id || ""} placeholder="application / client id"
                    onChange={(e) => setSsoField(p, "client_id", e.target.value)} autoComplete="off" />
                </div>
                <div style={ROW}>
                  <span style={LABEL}>Client Secret</span>
                  <input style={INPUT} type="password"
                    placeholder={c.client_secret_set ? "•••••••• (mantém atual)" : "client secret"}
                    value={c.client_secret || ""}
                    onChange={(e) => setSsoField(p, "client_secret", e.target.value)} autoComplete="off" />
                </div>
                <div style={ROW}>
                  <span style={LABEL}>{meta.domainLabel}</span>
                  <input style={INPUT} value={c.tenant_or_domain || ""}
                    placeholder={p === "okta" ? "suaempresa.okta.com" : "tenant id (GUID)"}
                    onChange={(e) => setSsoField(p, "tenant_or_domain", e.target.value)} autoComplete="off" />
                </div>
                <div style={{ ...ROW, marginBottom: 0 }}>
                  <span style={LABEL}>Metadata URL</span>
                  <input style={INPUT} value={c.metadata_url || ""}
                    placeholder="https://.../.well-known/openid-configuration"
                    onChange={(e) => setSsoField(p, "metadata_url", e.target.value)} autoComplete="off" />
                </div>
              </div>
            );
          })}
          <div style={{ display: "flex", gap: 10 }}>
            <button type="submit" style={BTN("primary")} disabled={ssoSaving}>
              {ssoSaving ? "Salvando…" : "Salvar SSO"}
            </button>
            <button type="button" style={BTN("secondary")} onClick={loadSso}>Recarregar</button>
          </div>
        </form>
      </div>

      {/* ── Arsenal Kali (módulos click-to-install) ──────────────────── */}
      <div style={CARD}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>Arsenal Kali</span>
          <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--ink-muted)" }}>
            instalação modular sob demanda
          </span>
        </div>
        <p style={{ fontSize: 13, color: "var(--ink-muted)", marginBottom: 18, lineHeight: 1.5 }}>
          A imagem base sobe enxuta (só ferramentas apt). Os módulos pesados
          (suite Go, sqlmap, nuclei, trivy…) são instalados aqui sob demanda, num
          volume persistente — sobrevivem a reinício e ficam disponíveis para os scans.
        </p>

        {modulesError && (
          <div style={{ fontSize: 13, color: "#b91c1c", marginBottom: 14 }}>{modulesError}</div>
        )}

        {modules.map((m) => {
          const st = MODULE_STATUS[m.status] || MODULE_STATUS.not_installed;
          const busy = !!moduleBusy[m.id];
          const installing = m.status === "installing";
          const installed = m.status === "installed";
          return (
            <div key={m.id} style={{ border: "1px solid var(--line)", borderRadius: 10, padding: "14px 16px", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>{m.name}</span>
                <span style={{ ...CHIP(installed), background: st.bg, color: st.color }}>{st.label}</span>
                <span style={{ marginLeft: "auto", fontSize: 11.5, color: "var(--ink-muted)" }}>
                  {m.provides?.length || 0} ferramentas
                </span>
              </div>
              <p style={{ fontSize: 12.5, color: "var(--ink-muted)", margin: "0 0 10px", lineHeight: 1.5 }}>
                {m.description}
              </p>

              {installing && (
                <div style={{ fontSize: 12, color: "#b45309", marginBottom: 10 }}>
                  Passo {m.step_index || 0}/{m.total_steps}: {m.current_step || "iniciando…"}
                </div>
              )}
              {m.status === "failed" && m.error && (
                <div style={{ fontSize: 12, color: "#b91c1c", marginBottom: 10 }}>{m.error}</div>
              )}

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {!installed && (
                  <button style={BTN("primary")} disabled={busy || installing} onClick={() => installModule(m.id)}>
                    {installing ? "Instalando…" : busy ? "…" : "Instalar"}
                  </button>
                )}
                {installed && (
                  <>
                    <button style={BTN("primary")} disabled={busy} onClick={() => installModule(m.id)}>
                      Reinstalar
                    </button>
                    <button style={BTN("secondary")} disabled={busy} onClick={() => uninstallModule(m.id)}>
                      Remover
                    </button>
                  </>
                )}
                {(m.log?.length > 0 || installing) && (
                  <button style={BTN("secondary")} onClick={() => setOpenLog(openLog === m.id ? null : m.id)}>
                    {openLog === m.id ? "Ocultar log" : "Ver log"}
                  </button>
                )}
              </div>

              {openLog === m.id && (
                <pre style={{
                  marginTop: 10, maxHeight: 220, overflow: "auto", fontSize: 11, lineHeight: 1.45,
                  background: "var(--canvas)", border: "1px solid var(--line)", borderRadius: 8,
                  padding: "10px 12px", color: "var(--ink-soft)", whiteSpace: "pre-wrap",
                }}>
                  {(m.log || []).join("\n") || "(sem saída ainda)"}
                </pre>
              )}
            </div>
          );
        })}

        <div style={{ display: "flex", gap: 10, marginTop: 4 }}>
          <button type="button" style={BTN("secondary")} onClick={loadModules} disabled={modulesLoading}>
            {modulesLoading ? "Atualizando…" : "Recarregar"}
          </button>
        </div>
      </div>

      {/* ── Info box: OSINT phase ────────────────────────────────────── */}
      <div style={{ ...CARD, background: "var(--surface-alt)", border: "1px solid var(--line)" }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 10 }}>
          Sobre o OSINT (P18)
        </div>
        <p style={{ fontSize: 13, color: "var(--ink-muted)", lineHeight: 1.6, margin: 0 }}>
          A fase P18 roda imediatamente ao iniciar um scan (sem dependências de gate).
          Inclui: <strong>Shodan</strong> (com API key), <strong>theHarvester</strong>,
          <strong> gitleaks / trufflehog</strong> (busca de segredos), e
          <strong> h8mail</strong> (vazamento de credenciais).
          <br /><br />
          O painel de Cockpit mostra "OSINT não rodou ainda" enquanto nenhum item de P18
          foi concluído para o scan selecionado. Ao iniciar um novo scan, P18 enfileira
          automaticamente.
        </p>
      </div>
    </div>
  );
}
