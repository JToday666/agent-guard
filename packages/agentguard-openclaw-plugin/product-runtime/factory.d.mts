import type {
  AnyAgentTool,
  OpenClawPluginDefinition,
  OpenClawPluginToolFactory,
} from "openclaw/plugin-sdk/plugin-entry";
import type { ChannelPlugin } from "openclaw/plugin-sdk/channel-core";
import type { FrozenProductProfile } from "./profile.mjs";
import type { ProductMessagePermitBridge } from "./message-permits.mjs";
export interface FullRegistrationWitness {
  readonly pluginId: "agentguard-product-runtime-fixture";
  readonly mode: "full";
  /** Immutable blueprints; each factory returns a fresh Host-wrappable shell. */
  readonly memoryTools: readonly AnyAgentTool[];
  readonly memoryFactories: readonly OpenClawPluginToolFactory[];
  readonly channel: ChannelPlugin;
  readonly outbound: Readonly<{
    prepareSendPayload: NonNullable<
      NonNullable<ChannelPlugin["actions"]>["prepareSendPayload"]
    >;
    sendPayload: NonNullable<
      NonNullable<ChannelPlugin["outbound"]>["sendPayload"]
    >;
    sendText: NonNullable<NonNullable<ChannelPlugin["outbound"]>["sendText"]>;
  }>;
}
export declare function createProductFixturePlugin(options: {
  profile: FrozenProductProfile;
  messagePermitBridge: ProductMessagePermitBridge;
}): Readonly<{
  plugin: OpenClawPluginDefinition;
  registrationWitness(): FullRegistrationWitness;
}>;
