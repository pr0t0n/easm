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
    success: "border-emerald-300 bg-emerald-50 text-emerald-800",
    error: "border-rose-300 bg-rose-50 text-rose-800",
    info: "border-blue-300 bg-blue-50 text-blue-800",
  };

  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 space-y-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`pointer-events-auto w-80 rounded-lg border px-3 py-2 text-sm shadow-[0_8px_20px_rgba(0,0,0,0.22)] backdrop-blur ${styleByType[toast.type] || styleByType.info}`}
        >
          {toast.message}
        </div>
      ))}
    </div>
  );
}
