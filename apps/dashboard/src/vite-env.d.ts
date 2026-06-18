/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_BACKEND_TARGET?: string;
  readonly VITE_ENABLE_API_MOCK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
