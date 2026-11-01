import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: { extend: { colors: { brand: "#3157d5", canvas: "#f5f7fb" }, boxShadow: { soft: "0 12px 36px rgba(15,23,42,.06)" } } },
  plugins: [],
};
export default config;
