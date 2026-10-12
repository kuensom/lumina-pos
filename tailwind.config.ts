import type { Config } from "tailwindcss";

export default {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        ink: "#17211b",
        forest: "#174d37",
        cream: "#f7f4eb",
        gold: "#d9a441",
      },
    },
  },
  plugins: [],
} satisfies Config;
