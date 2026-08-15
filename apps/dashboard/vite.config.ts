import { fileURLToPath, URL } from "node:url";

import vue from "@vitejs/plugin-vue";
import { defineConfig, loadEnv, type Plugin } from "vite";

const dashboardRoot = fileURLToPath(new URL(".", import.meta.url));
const productionForbiddenModuleMarkers = [
  "/src/data/sources/mock-data-source.",
  "/src/data/sources/mock-data.",
  "/src/data/sources/preview",
  "/src/data/sources/replay",
  "/src/data/sources/hybrid",
  "/tests/fixtures/runtime_supervision/",
] as const;

export function findForbiddenPreviewModules(moduleIds: Iterable<string>): string[] {
  return [...moduleIds]
    .map((moduleId) => moduleId.replaceAll("\\", "/"))
    .filter((moduleId) =>
      productionForbiddenModuleMarkers.some((marker) => moduleId.includes(marker)),
    )
    .sort();
}

function excludePreviewModulesFromProduction(): Plugin {
  return {
    name: "agentguard-dashboard-production-preview-exclusion",
    apply: "build",
    enforce: "post",
    generateBundle(_outputOptions, bundle) {
      const moduleIds = Object.values(bundle).flatMap((output) =>
        output.type === "chunk" ? Object.keys(output.modules) : [],
      );
      const forbiddenModules = findForbiddenPreviewModules(moduleIds);
      if (forbiddenModules.length) {
        this.error(
          `Production Dashboard bundle contains Preview-only modules:\n${forbiddenModules.join("\n")}`,
        );
      }
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, dashboardRoot, "");
  const backendTarget = env.VITE_BACKEND_TARGET || "http://127.0.0.1:8088";

  return {
    envDir: dashboardRoot,
    plugins: [vue(), excludePreviewModulesFromProduction()],
    resolve: {
      alias: {
        "@": fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
    server: {
      proxy: {
        "/api": {
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ""),
          target: backendTarget,
        },
      },
    },
    worker: {
      format: "es",
    },
  };
});
