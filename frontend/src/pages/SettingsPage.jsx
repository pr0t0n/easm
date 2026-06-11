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
  background: variant === "primary" ? "var(--accent)" : "var(--surface-alt)",
  color: variant === "primary" ? "#fff" : "var(--ink)",
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

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", padding: "32px 24px" }}>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>Configurações</h1>
      <p style={{ fontSize: 13, color: "var(--ink-muted)", marginBottom: 28 }}>
        Integrações e chaves de API utilizadas pelos scanners.
      </p>

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
