import { useEffect, useState } from "react";
import client from "../api/client";

/* Dropdown de scans reutilizável (Joias, Vulnerabilidades, Superfície).
   Lista real de /api/scans. value="" = todos os scans. */
export default function ScanSelect({ value, onChange, allLabel = "Todos os scans", accessGroupId = "" }) {
  const [scans, setScans] = useState([]);
  useEffect(() => {
    client
      .get("/api/scans")
      .then(({ data }) => setScans(Array.isArray(data) ? data : []))
      .catch(() => setScans([]));
  }, []);
  return (
    <select
      className="scan-select"
      value={value || ""}
      onChange={(e) => onChange(e.target.value)}
      aria-label="Selecionar scan"
    >
      <option value="">{allLabel}</option>
      {scans
        .filter((s) => !accessGroupId || String(s.access_group_id || "") === String(accessGroupId))
        .map((s) => (
        <option key={s.id} value={s.id}>
          #{s.id} {s.target_query}{s.status ? ` · ${s.status}` : ""}
        </option>
      ))}
    </select>
  );
}
