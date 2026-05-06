import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/Ace_bin_analyzer/",
  plugins: [react()],
  test: {
    environment: "jsdom",
  },
});

