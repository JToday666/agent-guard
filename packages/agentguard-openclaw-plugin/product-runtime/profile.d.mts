import type { OpenClawConfig } from "openclaw/plugin-sdk/plugin-entry";
import type { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";
export interface ProductSecretRef {
  readonly source: "env";
  readonly provider: "default";
  readonly id: string;
}
export interface ProductProfileProvider {
  readonly id: "agentguard-acceptance";
  readonly modelId: string;
  readonly baseUrl: string;
  readonly api?: "openai-completions";
  readonly apiKey: ProductSecretRef;
}
export interface ProductAssetCommitments {
  readonly schemaVersion: 1;
  readonly command: "node marker.mjs";
  readonly markerDigest: string;
  readonly nodePath: string;
  readonly nodeDigest: string;
  readonly shellPath: string;
  readonly shellDigest: string;
  readonly configDigest: string;
  readonly profileDigest: string;
  readonly execApprovalsDigest: string;
}
declare const profileBrand: unique symbol;
export interface FrozenProductProfile {
  readonly [profileBrand]: true;
  readonly root: string;
  readonly stateDir: string;
  readonly workspaceDir: string;
  readonly agentDir: string;
  readonly configPath: string;
  readonly profilePath: string;
  readonly runManifestPath: string;
  readonly agentId: string;
  readonly sessionId: string;
  readonly sessionKey: string;
  readonly scopeSessionId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly inboxUrl: string;
  readonly inboxTarget: string;
  readonly nodePath: string;
  readonly shellPath: string;
  readonly config: OpenClawConfig;
  readonly env: Readonly<Record<string, string>>;
  readonly toolOptions: NonNullable<
    Parameters<typeof createOpenClawCodingTools>[0]
  >;
  readonly assetCommitments: ProductAssetCommitments;
}
export declare const PRODUCT_FIXTURE_PLUGIN_ID: "agentguard-product-runtime-fixture";
export declare const PRODUCT_FIXTURE_CHANNEL_ID: "agentguard-fixture";
export declare const PRODUCT_TOOL_IDS: readonly string[];
export declare const PRODUCT_MARKER_COMMAND: "node marker.mjs";
export declare function createProductRuntimeProfile(options: {
  root: string;
  inboxUrl: string;
  provider: ProductProfileProvider;
  runManifestPath: string;
}): Promise<FrozenProductProfile>;
export declare function loadProductRuntimeProfile(
  configPath: string,
): Promise<FrozenProductProfile>;
export declare function loadProductRuntimeProfileSync(
  configPath: string,
): FrozenProductProfile;
export declare function assertProductRuntimeAssets(
  profile: FrozenProductProfile,
): void;
export declare function isProductRuntimeProfile(
  value: unknown,
): value is FrozenProductProfile;
