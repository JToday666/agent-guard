/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_BACKEND_TARGET?: string;
  readonly VITE_API_MOCK_DELAY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
