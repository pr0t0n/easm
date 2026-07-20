function cookieMap(raw) {
  return Object.fromEntries(String(raw || "").split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const idx = part.indexOf("=");
    return idx > 0 ? [part.slice(0, idx).trim(), part.slice(idx + 1).trim()] : [part, ""];
  }));
}

export function buildScannerAuthConfig(enabled, config = {}) {
  if (!enabled) return null;
  if (config.multiIdentity) {
    const identities = config.type === "bearer" ? [
      { id: "user_a", role: "user", auth_type: "bearer", bearer_token: config.token },
      { id: "user_b", role: "user", auth_type: "bearer", bearer_token: config.tokenB },
    ] : config.type === "cookie" ? [
      { id: "user_a", role: "user", auth_type: "cookie", cookies: cookieMap(config.cookie) },
      { id: "user_b", role: "user", auth_type: "cookie", cookies: cookieMap(config.cookieB) },
    ] : config.type === "basic" ? [
      { id: "user_a", role: "user", auth_type: "basic", username: config.username, password: config.password },
      { id: "user_b", role: "user", auth_type: "basic", username: config.usernameB, password: config.passwordB },
    ] : [
      { id: "user_a", role: "user", auth_type: "header", headers: { [config.headerName]: config.headerValue } },
      { id: "user_b", role: "user", auth_type: "header", headers: { [config.headerName]: config.headerValueB } },
    ];
    const missing = identities.some((identity) => !identity.bearer_token && !identity.username && !Object.keys(identity.cookies || {}).length && !Object.values(identity.headers || {}).some(Boolean));
    return missing ? null : { type: config.type, required: true, identities };
  }
  if (config.type === "bearer" && config.token) return { type: "bearer", token: config.token };
  if (config.type === "cookie" && config.cookie) return { type: "cookie", cookie: config.cookie };
  if (config.type === "basic" && config.username) return { type: "basic", username: config.username, password: config.password };
  if (config.type === "header" && config.headerName) return { type: "header", headers: { [config.headerName]: config.headerValue } };
  return null;
}
