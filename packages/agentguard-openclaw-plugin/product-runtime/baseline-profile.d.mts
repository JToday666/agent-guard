import type { OpenClawConfig } from "openclaw/plugin-sdk/plugin-entry";
import type { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";
export declare const PRODUCT_FIXTURE_PLUGIN_ID: "agentguard-product-runtime-fixture";
export declare const PRODUCT_FIXTURE_CHANNEL_ID: "agentguard-fixture";
export declare const PRODUCT_TOOL_IDS: readonly string[];
export declare function createBaselineRuntimeProfile(options: {
  root: string;
  inboxUrl: string;
  modelBaseUrl: string;
  modelId?: string;
  modelApiKey?: string;
  fixturePluginPath?: string;
}): Promise<{
  config: OpenClawConfig;
  configPath: string;
  stateDir: string;
  workspaceDir: string;
  agentDir: string;
  agentId: string;
  sessionKey: string;
  sessionId: string;
  env: Record<string, string>;
  toolOptions: NonNullable<Parameters<typeof createOpenClawCodingTools>[0]>;
}>;
