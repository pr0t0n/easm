/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#fdf2f2",
          100: "#fbd7d7",
          300: "#f3a6a6",
          500: "#e96363", // primary CTA — red team brand
          600: "#d04848",
          700: "#a83232",
          900: "#5e1c1c",
        },
        accent: {
          blue: "#4b73ff",
          pink: "#ff66f4",
        },
        canvas: {
          DEFAULT: "#fcfbf8",
          muted: "#f0ebe7",
          surface: "#ffffff",
          soft: "#faf8f4",
        },
        ink: {
          DEFAULT: "#1c1c1c",
          soft: "#3d3d3d",
          muted: "#6b6b6b",
        },
        line: {
          DEFAULT: "#e5dcd5",
          strong: "#d8cdc4",
          soft: "#efe7e0",
        },
        sidebar: {
          bg: "#1f242c",
          surface: "#262c36",
          surface2: "#2d343f",
          border: "#2f3743",
          text: "#e8eaed",
          muted: "#8a93a3",
          group: "#6b7384",
        },
        sev: {
          critical: "#d64545",
          high: "#fe7b02",
          medium: "#d4a500",
          low: "#229160",
          info: "#4b73ff",
        },
        grade: {
          a: "#10b981",
          b: "#06b6d4",
          c: "#eab308",
          d: "#f97316",
          f: "#ef4444",
        },
      },
      fontFamily: {
        display: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        body: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "Menlo", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(28,28,28,0.04), 0 4px 12px rgba(28,28,28,0.04)",
        elevate: "0 2px 6px rgba(28,28,28,0.06), 0 8px 24px rgba(28,28,28,0.06)",
        cta: "0 2px 6px rgba(233,99,99,0.30)",
        "cta-hover": "0 6px 20px rgba(233,99,99,0.45)",
        focus: "0 0 0 3px rgba(233,99,99,0.25)",
      },
      borderRadius: {
        DEFAULT: "8px",
      },
    },
  },
  plugins: [],
};
