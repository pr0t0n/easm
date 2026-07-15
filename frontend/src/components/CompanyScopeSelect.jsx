import { useEffect, useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";

export default function CompanyScopeSelect({
  value,
  onChange,
  allLabel = "Todas as empresas",
  className = "company-scope-select cockpit-top-select",
  label = "Visão da empresa",
  style,
}) {
  const isAdmin = Boolean(authStore.me?.is_admin);
  const [groups, setGroups] = useState([]);

  useEffect(() => {
    if (!isAdmin) return;
    client
      .get("/api/access-groups", { _skipToast: true })
      .then(({ data }) => setGroups(Array.isArray(data) ? data : []))
      .catch(() => setGroups([]));
  }, [isAdmin]);

  if (!isAdmin) return null;

  return (
    <div className={className} style={style}>
      <label>{label}</label>
      <select value={value || ""} onChange={(event) => onChange(event.target.value)} aria-label={label}>
        <option value="">{allLabel}</option>
        {groups.map((group) => (
          <option key={group.id} value={group.id}>{group.name}</option>
        ))}
      </select>
    </div>
  );
}
