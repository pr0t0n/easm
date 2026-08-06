import { useEffect, useRef, useState } from "react";
import client, { getWsBaseUrl } from "../api/client";

// Operator-driven login capture: streams a server-side browser's screen into
// this canvas via CDP screencast, forwards mouse/keyboard back over the same
// WebSocket. No separate window, no certificate to trust — the browser runs
// in the backend_runner container, not on the operator's machine.
export default function CredentialCaptureModal({ scanId, onClose, onCaptured }) {
  const canvasRef = useRef(null);
  const wsRef = useRef(null);
  const captureIdRef = useRef(null);
  const confirmedRef = useRef(false);
  const [identityKey, setIdentityKey] = useState("");
  const [role, setRole] = useState("");
  const [phase, setPhase] = useState("form"); // form | connecting | active | error
  const [statusInfo, setStatusInfo] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const cleanupWs = () => {
    wsRef.current?.close();
    wsRef.current = null;
  };

  useEffect(() => () => {
    cleanupWs();
    // Modal unmounted without an explicit confirm/cancel (e.g. operator
    // closed the browser tab) — best-effort cancel so the browser context
    // doesn't sit alive server-side indefinitely.
    if (captureIdRef.current && !confirmedRef.current) {
      client.post(
        `/api/scans/${scanId}/identities/capture/${captureIdRef.current}/cancel`,
        {},
        { _skipToast: true }
      ).catch(() => {});
    }
  }, [scanId]);

  const drawFrame = (base64Jpeg) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const img = new Image();
    img.onload = () => {
      if (canvas.width !== img.naturalWidth || canvas.height !== img.naturalHeight) {
        canvas.width = img.naturalWidth;
        canvas.height = img.naturalHeight;
      }
      ctx.drawImage(img, 0, 0);
    };
    img.src = `data:image/jpeg;base64,${base64Jpeg}`;
  };

  const startCapture = async () => {
    if (!identityKey.trim()) { setError("Informe um identificador para essa identidade."); return; }
    setBusy(true);
    setError("");
    try {
      const { data } = await client.post(`/api/scans/${scanId}/identities/capture/start`, {
        identity_key: identityKey.trim(),
        role: role.trim(),
      });
      captureIdRef.current = data.capture_session_id;
      setPhase("connecting");

      const token = localStorage.getItem("token") || "";
      const wsUrl = `${getWsBaseUrl()}${data.ws_url_path}?token=${token}`;
      let ws;
      try {
        ws = new WebSocket(wsUrl);
      } catch (wsErr) {
        setError(`Falha ao abrir WebSocket: ${wsErr?.message || wsErr}`);
        setPhase("form");
        return;
      }
      wsRef.current = ws;
      ws.onopen = () => setPhase("active");
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === "frame") drawFrame(msg.data);
        } catch { /* ignore malformed frame */ }
      };
      ws.onerror = () => setError("Conexão de streaming falhou (veja o console do navegador para detalhes).");
      ws.onclose = (closeEvent) => {
        if (confirmedRef.current) return;
        // Bug fixed here: previously only "active" -> "error" was handled, so
        // a handshake rejected before ever opening (still "connecting") left
        // the modal stuck on "Conectando..." forever with no visible error.
        setPhase((p) => {
          if (p === "active" || p === "connecting") {
            setError(`Conexão fechada (código ${closeEvent.code}${closeEvent.reason ? ": " + closeEvent.reason : ""}).`);
            return "error";
          }
          return p;
        });
      };
    } catch (err) {
      console.error("startCapture failed:", err);
      setError(err?.response?.data?.detail || err?.message || "Falha ao iniciar captura.");
      setPhase("form");
    } finally {
      setBusy(false);
    }
  };

  // ── Poll capture status (headers/cookies count, current URL) ─────────────
  useEffect(() => {
    if (phase !== "active" || !captureIdRef.current) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const { data } = await client.get(
          `/api/scans/${scanId}/identities/capture/${captureIdRef.current}/status`,
          { _skipToast: true }
        );
        if (!cancelled) setStatusInfo(data);
      } catch { /* silencioso */ }
    };
    poll();
    const t = setInterval(poll, 2000);
    return () => { cancelled = true; clearInterval(t); };
  }, [phase, scanId]);

  const sendInputEvent = (event) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.send(JSON.stringify(event));
  };

  const toCanvasCoords = (e) => {
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width || 1;
    const scaleY = canvas.height / rect.height || 1;
    return { x: (e.clientX - rect.left) * scaleX, y: (e.clientY - rect.top) * scaleY };
  };

  const handleMouse = (eventType) => (e) => {
    const { x, y } = toCanvasCoords(e);
    sendInputEvent({ type: "mouse", eventType, x, y, button: "left", clickCount: 1 });
  };
  const handleWheel = (e) => {
    const { x, y } = toCanvasCoords(e);
    sendInputEvent({ type: "wheel", x, y, deltaX: e.deltaX, deltaY: e.deltaY });
  };
  const handleKey = (eventType) => (e) => {
    e.preventDefault();
    sendInputEvent({ type: "key", eventType, key: e.key, code: e.code, text: eventType === "keyDown" ? e.key : undefined });
  };

  const confirm = async () => {
    setBusy(true);
    setError("");
    try {
      const { data } = await client.post(`/api/scans/${scanId}/identities/capture/${captureIdRef.current}/confirm`);
      confirmedRef.current = true;
      cleanupWs();
      onCaptured?.(data);
      onClose();
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao confirmar a captura.");
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    setBusy(true);
    try {
      if (captureIdRef.current) {
        await client.post(`/api/scans/${scanId}/identities/capture/${captureIdRef.current}/cancel`, {}, { _skipToast: true });
      }
    } catch { /* silencioso */ }
    confirmedRef.current = true; // prevents the unmount effect from cancelling twice
    cleanupWs();
    onClose();
  };

  return (
    <div
      style={{ position: "fixed", inset: 0, zIndex: 300, background: "rgba(0,0,0,0.45)", display: "grid", placeItems: "center", padding: 24 }}
      onClick={(e) => { if (e.target === e.currentTarget && phase === "form") onClose(); }}
    >
      <div className="sk-panel" style={{ width: "min(920px, 96vw)", maxHeight: "92vh", display: "flex", flexDirection: "column", padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div style={{ fontSize: 14, fontWeight: 700 }}>Capturar sessão autenticada</div>
          <button onClick={phase === "form" ? onClose : cancel} style={{ border: "none", background: "transparent", fontSize: 18, cursor: "pointer" }}>✕</button>
        </div>

        {phase === "form" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <p style={{ fontSize: 12, color: "var(--ink-muted)" }}>
              Complete o login (incluindo MFA/SSO) na tela abaixo — tudo acontece dentro da plataforma,
              nenhum programa externo é aberto.
            </p>
            <label style={{ fontSize: 11, fontWeight: 600 }}>Identificador da identidade
              <input value={identityKey} onChange={(e) => setIdentityKey(e.target.value)} placeholder="ex.: org_a_admin"
                style={{ width: "100%", marginTop: 4, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)" }} />
            </label>
            <label style={{ fontSize: 11, fontWeight: 600 }}>Papel (opcional)
              <input value={role} onChange={(e) => setRole(e.target.value)} placeholder="ex.: admin"
                style={{ width: "100%", marginTop: 4, padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)" }} />
            </label>
            {error && <div style={{ color: "var(--sev-critical-solid)", fontSize: 12 }}>{error}</div>}
            <button className="btn-primary" onClick={startCapture} disabled={busy}>Iniciar captura</button>
          </div>
        )}

        {(phase === "connecting" || phase === "active" || phase === "error") && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <canvas
              ref={canvasRef}
              tabIndex={0}
              style={{ width: "100%", maxHeight: "60vh", objectFit: "contain", background: "#111", borderRadius: 8, cursor: "default" }}
              onMouseDown={handleMouse("mousePressed")}
              onMouseUp={handleMouse("mouseReleased")}
              onMouseMove={handleMouse("mouseMoved")}
              onWheel={handleWheel}
              onKeyDown={handleKey("keyDown")}
              onKeyUp={handleKey("keyUp")}
            />
            <div style={{ fontSize: 11, color: "var(--ink-muted)", display: "flex", justifyContent: "space-between" }}>
              <span>{phase === "connecting" ? "Conectando…" : statusInfo?.current_url || ""}</span>
              {statusInfo && (
                <span>{statusInfo.in_scope_headers_count} header(s) · sessão ativa há {Math.round(statusInfo.idle_seconds)}s sem interação</span>
              )}
            </div>
            {error && <div style={{ color: "var(--sev-critical-solid)", fontSize: 12 }}>{error}</div>}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button className="btn-secondary" onClick={cancel} disabled={busy}>Cancelar</button>
              <button className="btn-primary" onClick={confirm} disabled={busy || phase !== "active"}>Confirmar e salvar sessão</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
