import type { OpenClawProductActionRuntime } from "../runtime/product-action-runtime.js";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";

import { GuardApiClient, buildPluginConfig } from "../guard-api-client.js";
import type { RuntimeOutcomeDelivery } from "../runtime/outcome-delivery.js";
import type {
  EvidenceDegradationTracker,
  SessionState,
  ToolCallState,
} from "../runtime/state.js";

type PluginApi = Parameters<
  NonNullable<OpenClawPluginDefinition["register"]>
>[0];

export type HookContext = {
  api: PluginApi;
  /** Trusted composition only; never constructed from plugin JSON. */
  productActions?: OpenClawProductActionRuntime;
  config: ReturnType<typeof buildPluginConfig>;
  makeClient: () => GuardApiClient;
  outcomeDelivery: RuntimeOutcomeDelivery;
  sessionState: Map<string, SessionState>;
  toolCallState: Map<string, ToolCallState>;
  degradations: EvidenceDegradationTracker;
};

/** Detect authority configuration without invoking any legacy client factory. */
export function hasProductConfiguration({
  config,
}: Pick<HookContext, "config">): boolean {
  return Boolean(
    config.officialProfileId ||
    config.officialProfileDigest ||
    config.productManifestPath ||
    config.productReceiptDirectory ||
    config.productReceiptKeyPath ||
    config.restrictedAskReleaseEnabled,
  );
}
