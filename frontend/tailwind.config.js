/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#fff5eb",
          100: "#ffe4cc",
          300: "#ffb070",
          500: "#fe7b02",
          600: "#e96a00",
          700: "#c25500",
          900: "#8a3c00",
        },
        accent: {
          blue: "#4b73ff",
          pink: "#ff66f4",
        },
        canvas: {
          DEFAULT: "#fcfbf8",
          muted: "#f0ebe7",
          surface: "#ffffff",
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
      },
      fontFamily: {
        display: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(28,28,28,0.04), 0 4px 12px rgba(28,28,28,0.04)",
        elevate: "0 2px 6px rgba(28,28,28,0.06), 0 8px 24px rgba(28,28,28,0.06)",
      },
    },
  },
  plugins: [],
};
