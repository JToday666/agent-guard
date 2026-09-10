import {
  buildFixtureConfig,
  createFixtureTools,
  createFixtureChannel,
  PLUGIN_ID,
} from "./index.mjs";
import { isMessagePermitBridge } from "./message-permits.mjs";
import {
  assertProductRuntimeAssets,
  isProductRuntimeProfile,
} from "./profile.mjs";
import { FixtureError } from "./memory.mjs";
import { canonical, freeze, ownObject } from "./strict.mjs";

/** One private bridge and one set of actual tool/channel factories per assembly. */
export function createProductFixturePlugin(options) {
  const { profile, messagePermitBridge } = ownObject(options, [
    "profile",
    "messagePermitBridge",
  ]);
  if (
    !isProductRuntimeProfile(profile) ||
    !isMessagePermitBridge(messagePermitBridge)
  )
    throw new FixtureError("product_fixture_assembly_invalid");
  assertProductRuntimeAssets(profile);
  const config = buildFixtureConfig({
    acceptanceRoot: profile.workspaceDir,
    inboxUrl: profile.inboxUrl,
    inboxTarget: profile.inboxTarget,
  });
  const memoryTools = freeze(createFixtureTools(config, { productMode: true }));
  const memoryFactories = Object.freeze(
    // The pinned Host returns an execution-scope wrapper from a Proxy get trap.
    // Its target's execute must therefore remain configurable. Each request gets
    // a fresh shell around the same private, immutable descriptor and callback.
    memoryTools.map((tool) => (_context) => ({ ...tool })),
  );
  const channel = freeze(
    createFixtureChannel(config, { productMode: true, messagePermitBridge }),
  );
  let witness;
  const plugin = Object.freeze({
    id: PLUGIN_ID,
    name: "AgentGuard Product Runtime Fixture",
    version: "0.1.0-rc.1",
    register(api) {
      const mode = api.registrationMode ?? "full";
      if (!["full", "discovery", "tool-discovery"].includes(mode)) return;
      if (
        canonical(ownObject(api.pluginConfig, ["runManifestPath"])) !==
        canonical({ runManifestPath: profile.runManifestPath })
      )
        throw new FixtureError("product_fixture_config_mismatch");
      assertProductRuntimeAssets(profile);
      if (mode === "full" && witness)
        throw new FixtureError("product_fixture_already_registered");
      for (let index = 0; index < memoryTools.length; index++)
        api.registerTool(memoryFactories[index], {
          name: memoryTools[index].name,
        });
      if (mode !== "tool-discovery") api.registerChannel({ plugin: channel });
      if (mode === "full")
        witness = Object.freeze({
          pluginId: PLUGIN_ID,
          mode,
          memoryTools,
          memoryFactories,
          channel,
          outbound: Object.freeze({
            prepareSendPayload: channel.actions.prepareSendPayload,
            sendPayload: channel.outbound.sendPayload,
            sendText: channel.outbound.sendText,
          }),
        });
    },
  });
  return Object.freeze({
    plugin,
    registrationWitness() {
      if (!witness)
        throw new FixtureError("product_fixture_registration_missing");
      return witness;
    },
  });
}
