import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/integration/**/*.test.ts"],
    fileParallelism: false,
    sequence: {
      concurrent: false,
    },
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
