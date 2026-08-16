/// <reference types="vite/client" />

declare module "@fontsource/ibm-plex-mono/latin-400.css";
declare module "@fontsource/ibm-plex-mono/latin-500.css";
declare module "@fontsource/ibm-plex-mono/latin-600.css";

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_API_HEALTH_URL?: string;
  readonly VITE_BACKEND_TARGET?: string;
  readonly VITE_API_MOCK_DELAY?: string;
  readonly VITE_API_REQUEST_TIMEOUT_MS?: string;
  readonly VITE_RUNTIME_SUPERVISION_S1_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
