import { defineConfig } from "vitest/config";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@vadrex/shared": resolve(here, "../shared/src/index.ts"),
      "@vadrex/merkle/sqlite": resolve(here, "../merkle/src/sqlite.ts"),
      "@vadrex/merkle": resolve(here, "../merkle/src/index.ts")
    }
  },
  test: {
    include: ["test/**/*.test.ts"]
  }
});
