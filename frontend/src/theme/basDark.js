// Shared dark "ops" palette for BAS pages -- graphite surfaces + the
// platform's real brand red as accent, NOT the mockup's own black/purple
// identity (this repo's real design tokens live in index.css; see
// BasControlCenterPage.jsx's header comment for why this page stays dark
// while the rest of the app is light). Originally private to
// BasOperationsCenterPage.jsx; extracted so BasControlCenterPage.jsx can
// share the exact same look instead of drifting into a second dark palette.
export const TV = {
  bg: "#1f242c", surface: "#262c36", surface2: "#2d343f",
  border: "#2f3743", text: "#e8eaed", muted: "#8a93a3", label: "#6b7384",
};

export const SEVERITY_COLOR = {
  critical: "#d64545", high: "#fe7b02", medium: "#d4a500", low: "#1f8a59", info: "#4b73ff",
};

export const RISK_COLOR = { high: "#d64545", medium: "#d4a500", low: "#1f8a59" };

// Real, resolved outcomes only -- see backend/app/services/bas_reporting.py's
// module docstring for why there is no "detected" state to color here.
export const OUTCOME_COLOR = {
  proven: "#d64545", unproven: "#8a93a3", blocked: "#1f8a59", not_tested: "#2f3743",
};
