import js from "@eslint/js";
import eslintConfigPrettier from "eslint-config-prettier/flat";
import pluginVue from "eslint-plugin-vue";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "playwright-report/**",
      "test-results/**",
      "*.tsbuildinfo",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...pluginVue.configs["flat/recommended"],
  {
    files: ["**/*.{ts,vue}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
      parserOptions: {
        extraFileExtensions: [".vue"],
        parser: tseslint.parser,
        sourceType: "module",
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "vue/attributes-order": "warn",
      "vue/html-self-closing": [
        "warn",
        {
          html: {
            component: "always",
            normal: "never",
            void: "never",
          },
          math: "always",
          svg: "always",
        },
      ],
      "vue/max-attributes-per-line": "off",
      "vue/multi-word-component-names": "off",
      "vue/singleline-html-element-content-newline": "off",
    },
  },
  eslintConfigPrettier,
);
