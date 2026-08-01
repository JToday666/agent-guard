/// <reference types="vite/client" />

declare module "@fontsource/ibm-plex-mono/latin-400.css";
declare module "@fontsource/ibm-plex-mono/latin-500.css";
declare module "@fontsource/ibm-plex-mono/latin-600.css";

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_BACKEND_TARGET?: string;
  readonly VITE_API_MOCK_DELAY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
