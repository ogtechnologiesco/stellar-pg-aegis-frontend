/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string
  readonly VITE_DOH_API?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
