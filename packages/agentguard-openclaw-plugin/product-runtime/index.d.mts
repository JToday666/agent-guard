import type {
  AnyAgentTool,
  OpenClawPluginDefinition,
} from "openclaw/plugin-sdk/plugin-entry";
import type { ChannelPlugin } from "openclaw/plugin-sdk/channel-core";
import type { ProductMessagePermitBridge } from "./message-permits.mjs";
export { createMessagePermitBridge } from "./message-permits.mjs";
export { createFixtureMemory, FixtureError } from "./memory.mjs";
export { startFixtureInbox } from "./inbox.mjs";
export declare const PLUGIN_ID: "agentguard-product-runtime-fixture";
export declare const CHANNEL_ID: "agentguard-fixture";
export declare const TOOL_NAMES: readonly string[];
export interface FixtureConfig {
  readonly acceptanceRoot: string;
  readonly inboxUrl: string;
  readonly inboxTarget: string;
}
export declare function buildFixtureConfig(value: unknown): FixtureConfig;
export declare function createFixtureTools(
  config: FixtureConfig,
  options?: { productMode?: boolean },
): AnyAgentTool[];
export declare function createFixtureChannel(
  config: FixtureConfig,
  options?: {
    productMode?: boolean;
    messagePermitBridge?: ProductMessagePermitBridge;
  },
): ChannelPlugin;
export declare function createFixturePlugin(options?: {
  productMode?: boolean;
  messagePermitBridge?: ProductMessagePermitBridge;
}): OpenClawPluginDefinition;
declare const plugin: OpenClawPluginDefinition;
export default plugin;
