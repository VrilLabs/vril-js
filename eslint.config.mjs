import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
  {
    ignores: [
      ".vril/**",
      ".vercel/**",
      "node_modules/**",
      "dist/**",
      "build/**",
      "coverage/**",
      "*.config.mjs",
      "src/lib/vril/framework/cli.mjs",
      "src/lib/vril/security/crypto/native-pqc/*.js",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    plugins: {
      "react-hooks": reactHooks,
    },
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // TypeScript performs symbol resolution more accurately for TS/TSX than ESLint no-undef.
      "no-undef": "off",
      // The existing codebase intentionally uses terse empty catch blocks for best-effort browser APIs.
      "no-empty": "off",
      // Existing UI text/highlighter regexes use explicit escapes for readability across string contexts.
      "no-useless-escape": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports", fixStyle: "inline-type-imports" },
      ],
    },
  },
);
