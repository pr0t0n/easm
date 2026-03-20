/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#f4f8ff",
          500: "#0ea5e9",
          700: "#0369a1"
        }
      },
      fontFamily: {
        display: ["Montserrat", "sans-serif"],
        mono: ["Montserrat", "sans-serif"]
      }
    },
  },
  plugins: [],
};
