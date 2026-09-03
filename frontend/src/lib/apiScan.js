export function apiCredentialPlan(authPayload) {
  const identities = Array.isArray(authPayload?.identities) ? authPayload.identities : [];
  if (identities.length >= 2) {
    return {
      credentialCount: 2,
      strategy: "anonymous_authenticated_ab",
      label: "Anônimo + autenticado A/B",
      contexts: ["anonymous", "authenticated:user_a", "authenticated:user_b"],
    };
  }
  if (authPayload) {
    return {
      credentialCount: 1,
      strategy: "anonymous_authenticated",
      label: "Anônimo + autenticado",
      contexts: ["anonymous", "authenticated:user_a"],
    };
  }
  return {
    credentialCount: 0,
    strategy: "anonymous_only",
    label: "Somente anônimo",
    contexts: ["anonymous"],
  };
}

export function buildApiScanConfig(enabled, config = {}, authPayload = null) {
  if (!enabled) return null;
  const specUrl = String(config.specUrl || "").trim();
  const inlineText = String(config.specJson || "").trim();
  const plan = apiCredentialPlan(authPayload);
  const payload = {
    enabled: true,
    spec_url: specUrl,
    spec_type: config.specType || "openapi",
    active_level: config.activeLevel || "safe",
    allow_mutations: Boolean(config.allowMutations),
    expected_auth_strategy: plan.strategy,
  };
  if (inlineText) {
    payload.spec_payload = JSON.parse(inlineText);
  }
  return payload;
}
