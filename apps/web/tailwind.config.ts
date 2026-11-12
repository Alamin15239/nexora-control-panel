import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        // Deep enterprise navy used by the product shell (sidebar, customer top bar).
        navy: {
          700: "#1b2a4a",
          800: "#14213c",
          900: "#0f1930",
          950: "#0a1122",
        },
        brand: {
          50: "#eef4ff",
          100: "#dfe9ff",
          200: "#c5d6fe",
          300: "#a1bcfc",
          400: "#7b99f8",
          500: "#5b78f1",
          600: "#4057e4",
          700: "#3443c9",
          800: "#2c3aa1",
          900: "#2a357f",
        },
        canvas: "#f5f7fb",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(15, 23, 42, 0.04), 0 8px 24px -12px rgba(15, 23, 42, 0.12)",
        lift: "0 2px 4px rgba(15, 23, 42, 0.05), 0 16px 40px -16px rgba(15, 23, 42, 0.18)",
        soft: "0 12px 36px rgba(15,23,42,.06)",
      },
    },
  },
  plugins: [],
};
export default config;
