import { useEffect, useState } from "react";

export default function ToastCenter() {
  const [toasts, setToasts] = useState([]);

  useEffect(() => {
    const onToast = (event) => {
      const payload = event.detail || {};
      const id = Date.now() + Math.floor(Math.random() * 1000);
      const item = {
        id,
        type: payload.type || "info",
        message: payload.message || "",
      };
      setToasts((prev) => [...prev, item]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4200);
    };

    window.addEventListener("app:toast", onToast);
    return () => window.removeEventListener("app:toast", onToast);
  }, []);

  const styleByType = {
    success: "border-emerald-500/40 bg-emerald-500/15 text-emerald-100",
    error: "border-rose-500/40 bg-rose-500/15 text-rose-100",
    info: "border-cyan-500/40 bg-cyan-500/15 text-cyan-100",
  };

  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 space-y-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`pointer-events-auto w-80 rounded-xl border px-3 py-2 text-sm shadow-lg backdrop-blur ${styleByType[toast.type] || styleByType.info}`}
        >
          {toast.message}
        </div>
      ))}
    </div>
  );
}
