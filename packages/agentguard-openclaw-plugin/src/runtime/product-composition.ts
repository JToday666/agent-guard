import { realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  OpenClawPluginApi,
  OpenClawPluginDefinition,
} from "openclaw/plugin-sdk/plugin-entry";
import {
  getGlobalPluginRegistry,
  type PluginHookHandlerMap,
} from "openclaw/plugin-sdk/plugin-runtime";
import { resolveSecretRefValues } from "openclaw/plugin-sdk/secret-ref-runtime";
import {
  loadProductRuntimeProfileSync,
  assertProductRuntimeAssets,
  PRODUCT_FIXTURE_PLUGIN_ID,
  type FrozenProductProfile,
} from "../../product-runtime/profile.mjs";
import {
  createProductFixturePlugin,
  type FullRegistrationWitness,
} from "../../product-runtime/factory.mjs";
import { createMessagePermitBridge } from "../../product-runtime/message-permits.mjs";
import { GuardApiClient, buildPluginConfig } from "../guard-api-client.js";
import { OpenClawProductActionRuntime } from "./product-action-runtime.js";
import { OpenClawProductContentRuntime } from "./product-content-runtime.js";
import {
  OpenClawProductNativeStream,
  verifyProductNativeWirePayload,
} from "./product-native-stream.js";
import { createProductContextConsumer } from "./product-context-plan.js";
import {
  collectOpenClawProductInventory,
  type OpenClawProductInventory,
} from "./product-inventory.js";
import {
  OpenClawProductManifest,
  readOpenClawProductRuntimeObservation,
} from "./product-manifest.js";
import {
  verifyInstalledOpenClawCandidate,
  type VerifiedInstalledOpenClawCandidate,
} from "./product-candidate.js";
import { readProductRunManifest } from "./product-run-manifest.js";
import { restrictedDigest } from "./canonical.js";
import {
  productAbsolutePath,
  productCompositionError,
} from "./product-protected-file.js";
import type { OpenClawProductReceiptOutbox } from "./product-receipt-outbox.js";
import { prepareProductRuntimeConfig } from "./product-runtime-config.js";
import {
  assertPinnedOpenClawHostLoader,
  loadPinnedOpenClawHostRegistry,
} from "./product-host-loader.js";

type Provider = Parameters<OpenClawPluginApi["registerProvider"]>[0];
type Middleware = Parameters<
  OpenClawPluginApi["registerAgentToolResultMiddleware"]
>[0];
type RegistryRow = { pluginId: string; source: string; rootDir?: string };
type FullRegistry = Omit<
  NonNullable<ReturnType<typeof getGlobalPluginRegistry>>,
  "plugins"
> & {
  plugins: {
    id: string;
    status: "loaded" | "disabled" | "error";
    source: string;
    rootDir?: string;
    enabled: boolean;
    activated?: boolean;
    imported?: boolean;
  }[];
  providers: (RegistryRow & { provider: Provider })[];
  agentToolResultMiddlewares: (RegistryRow & {
    rawHandler: Middleware;
    runtimes?: readonly string[];
  })[];
  tools: (RegistryRow & {
    factory: FullRegistrationWitness["memoryFactories"][number];
  })[];
  channels: (RegistryRow & { plugin: FullRegistrationWitness["channel"] })[];
  channelSetups: (RegistryRow & {
    plugin: FullRegistrationWitness["channel"];
    enabled: boolean;
  })[];
  runtimeLifecycles: (RegistryRow & {
    lifecycle: { cleanup: () => Promise<void> };
  })[];
};
const registry = () => getGlobalPluginRegistry() as FullRegistry | null;
type RuntimeState =
  "created" | "ready" | "running" | "completed" | "closed" | "blocked";
const ROOT = realpathSync(fileURLToPath(new URL("../../", import.meta.url)));
const ENTRY = join(ROOT, "product-runtime", "product", "index.mjs");
const ENTRY_ROOT = join(ROOT, "product-runtime", "product");
// Native require in the installed entry preserves this one ESM instance across the
// Host's loader. These private associations are never a cross-plugin bridge.
const REGISTERED = new WeakMap<object, ProductComposition>();
let runningOwner: ProductComposition | undefined;
let preparing = false;
function reservePreparation(): () => void {
  if (preparing || runningOwner) fail("product_runtime_already_selected");
  preparing = true;
  return () => {
    preparing = false;
  };
}
const RESIDUALS = Object.freeze([
  "openclaw_has_no_authoritative_invocation_start_hook",
  "openclaw_hook_cannot_atomically_replace_and_seal_final_action",
  "openclaw_message_sending_host_exception_or_timeout_can_fail_open",
  "openclaw_non_tool_memory_write_has_no_native_pre_execution_hook",
  "openclaw_sync_persistence_hooks_cannot_await_remote_decision_or_rollback",
]);
const CONSUMERS = Object.freeze(
  [
    {
      event_type: "context_assembled",
      enforcement: "pre_execution_c1",
      residual_boundaries: [],
    },
    {
      event_type: "memory_write_proposed",
      enforcement: "pre_execution_c1",
      residual_boundaries: [RESIDUALS[0], RESIDUALS[1], RESIDUALS[3]],
    },
    {
      event_type: "message_send_proposed",
      enforcement: "pre_execution_c1",
      residual_boundaries: [RESIDUALS[0], RESIDUALS[1], RESIDUALS[2]],
    },
    {
      event_type: "model_input_prepared",
      enforcement: "pre_execution_c1",
      residual_boundaries: [],
    },
    {
      event_type: "model_output_produced",
      enforcement: "post_execution_isolation",
      residual_boundaries: [],
    },
    {
      event_type: "tool_call_proposed",
      enforcement: "pre_execution_c1",
      residual_boundaries: [RESIDUALS[0], RESIDUALS[1]],
    },
    {
      event_type: "tool_result_produced",
      enforcement: "post_execution_isolation",
      residual_boundaries: [RESIDUALS[4]],
    },
  ].map((e) =>
    Object.freeze({
      ...e,
      residual_boundaries: Object.freeze(e.residual_boundaries),
    }),
  ),
);
const REPLAY = Object.freeze({
  sanitizeMode: "images-only" as const,
  sanitizeToolCallIds: false,
  repairToolUseResultPairing: false,
  dropThinkingBlocks: false,
  dropReasoningFromHistory: false,
  applyAssistantFirstOrderingFix: false,
  validateGeminiTurns: false,
  validateAnthropicTurns: false,
  allowSyntheticToolResults: false,
});
function fail(code = "product_composition_unavailable"): never {
  return productCompositionError(code);
}
function ownRunPath(api: OpenClawPluginApi): string {
  const input = api.pluginConfig;
  if (!input || Object.keys(input).join("|") !== "runManifestPath") fail();
  return productAbsolutePath(input.runManifestPath);
}
function checkEnvironment(profile: FrozenProductProfile): void {
  for (const [key, value] of Object.entries(profile.env))
    if (process.env[key] !== value) fail("product_environment_changed");
  for (const key of [
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "PI_CODING_AGENT_DIR",
  ])
    if (process.env[key]) fail("product_environment_invalid");
  for (const key of Object.keys(process.env))
    if (
      key.startsWith("OPENCLAW_") &&
      !Object.hasOwn(profile.env, key) &&
      process.env[key]
    )
      fail("product_environment_invalid");
}
function selectEnvironment(profile: FrozenProductProfile): void {
  if (runningOwner && runningOwner.profile.configPath !== profile.configPath)
    fail("product_runtime_already_selected");
  for (const key of [
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "PI_CODING_AGENT_DIR",
  ])
    if (process.env[key]) fail("product_environment_invalid");
  for (const key of Object.keys(process.env))
    if (
      key.startsWith("OPENCLAW_") &&
      !Object.hasOwn(profile.env, key) &&
      process.env[key]
    )
      fail("product_environment_invalid");
  Object.assign(process.env, profile.env);
}
export type OpenClawProductRuntimeSnapshot = Readonly<{
  state: RuntimeState;
  ready: boolean;
  active: boolean;
  c3AtomicReplaceAndSeal: false;
  modelAttempts: number;
  delivery?: ReturnType<OpenClawProductReceiptOutbox["status"]>;
  errorCode?: string;
}>;
export interface OpenClawProductRuntime {
  start(): Promise<void>;
  snapshot(): OpenClawProductRuntimeSnapshot;
  status(): OpenClawProductRuntimeSnapshot;
  run(): Promise<
    Readonly<{ status: "completed"; payloads: readonly unknown[] }>
  >;
  close(): Promise<void>;
}
export type OpenClawProductRuntimeInspection = Readonly<{
  inventory: {
    tools: OpenClawProductInventory["tools"];
    input_schemas: OpenClawProductInventory["inputSchemas"];
    plugin_order: readonly string[];
  };
  digests: OpenClawProductInventory["digests"];
  modelVisibleTools: readonly {
    name: string;
    description: string;
    parameters: unknown;
  }[];
  execution: {
    root: string;
    memory_namespace: string;
    inbox_url: string;
    script_digest: string;
  };
  capabilityConsumers: typeof CONSUMERS;
  residualBoundaries: readonly string[];
  packageVersion: string;
  artifactDigest: string;
  runtimeVersion: string;
  active: false;
}>;
class ProductComposition {
  readonly profile: FrozenProductProfile;
  readonly runManifestPath: string;
  #fixture: ReturnType<typeof createProductFixturePlugin>;
  #witness?: FullRegistrationWitness;
  #bridge: ReturnType<typeof createMessagePermitBridge>;
  #provider: Provider;
  #middleware: Middleware;
  #hooks = new Map<string, unknown>();
  #cleanup: () => Promise<void>;
  #state: RuntimeState = "created";
  #error?: string;
  #start?: Promise<void>;
  #client?: GuardApiClient;
  #action?: OpenClawProductActionRuntime;
  #content?: OpenClawProductContentRuntime;
  #stream?: OpenClawProductNativeStream;
  #outbox?: OpenClawProductReceiptOutbox;
  #candidate?: VerifiedInstalledOpenClawCandidate;
  #runConfig?: ReturnType<typeof readProductRunManifest>;
  #inventoryDigest?: string;
  #runtimeConfig?: Awaited<ReturnType<typeof prepareProductRuntimeConfig>>;
  #abort = new AbortController();
  #modelAttempts = 0;
  constructor(api: OpenClawPluginApi) {
    this.runManifestPath = ownRunPath(api);
    this.profile = loadProductRuntimeProfileSync(
      productAbsolutePath(process.env.OPENCLAW_CONFIG_PATH),
    );
    if (this.profile.runManifestPath !== this.runManifestPath) fail();
    checkEnvironment(this.profile);
    this.#bridge = createMessagePermitBridge({
      sessionKey: this.profile.sessionKey,
      inboxTarget: this.profile.inboxTarget,
      accountId: "default",
    });
    this.#fixture = createProductFixturePlugin({
      profile: this.profile,
      messagePermitBridge: this.#bridge,
    });
    this.#provider = {
      id: this.profile.providerId,
      label: "AgentGuard guarded OpenAI-compatible transport",
      auth: [],
      buildReplayPolicy: () => REPLAY,
      wrapStreamFn: (ctx) => async (model, context, options) => {
        try {
          this.assertCurrent();
          if (this.#state !== "running" || !this.#stream) fail();
          const wrapped = this.#stream.wrapStreamFn(ctx);
          if (!wrapped) fail();
          return await wrapped(model, context, options);
        } catch {
          this.block();
          throw new Error("product_native_stream_failed");
        }
      },
    };
    this.#middleware = async (event, context) => {
      try {
        this.assertCurrent();
        if (!this.#action || this.#state !== "running") fail();
        const result = await this.#action.observeToolResultMiddleware(
          event,
          context,
        );
        this.assertCurrent();
        return result as Awaited<ReturnType<Middleware>>;
      } catch {
        this.block();
        throw new Error("product_tool_result_withheld");
      }
    };
    this.#cleanup = () => this.close();
    this.#fixture.plugin.register!(api);
    if (api.registrationMode !== "full") return;
    this.#witness = this.#fixture.registrationWitness();
    api.registerProvider(this.#provider);
    api.registerAgentToolResultMiddleware(this.#middleware, {
      runtimes: ["openclaw"],
    });
    const register = <K extends keyof PluginHookHandlerMap>(
      name: K,
      callback: PluginHookHandlerMap[K],
    ) => {
      this.#hooks.set(name, callback);
      api.on(name, callback, { priority: 1000 });
    };
    register("before_tool_call", async (event, context) => {
      try {
        this.assertCurrent();
        if (!this.#action || this.#state !== "running") fail();
        const result = await this.#action.before(event, context);
        this.assertCurrent();
        return result;
      } catch {
        this.block();
        return { block: true, blockReason: "Product action withheld" };
      }
    });
    register("after_tool_call", async (event, context) => {
      try {
        this.assertCurrent();
        if (!this.#action) fail();
        await this.#action.after(event, context);
      } catch {
        this.block();
      }
    });
    register("tool_result_persist", (event, context) => {
      try {
        this.assertCurrent();
        if (!this.#action) fail();
        return this.#action.resultForPersistence(event, context) as ReturnType<
          PluginHookHandlerMap["tool_result_persist"]
        >;
      } catch {
        this.block();
        throw new Error("product_tool_result_withheld");
      }
    });
    register("message_sending", async (event, context) => {
      try {
        this.assertCurrent();
        if (!this.#action || this.#state !== "running") fail();
        const result = await this.#action.messageSending(event, context);
        this.assertCurrent();
        return result;
      } catch {
        this.block();
        return { cancel: true };
      }
    });
    // Native notifications do not authorise a model call or publish its output.
    register("llm_input", () => {
      this.assertCurrent();
    });
    register("llm_output", () => {
      this.assertCurrent();
    });
    register("agent_end", (event, context) => {
      this.assertCurrent();
      if (!this.#action || this.#state !== "running") fail();
      if (
        event.runId !== undefined &&
        context.runId !== undefined &&
        event.runId !== context.runId
      )
        fail("product_run_identity_mismatch");
      // A Host run ending without its terminal callback preserves unknown;
      // agent_end itself is never evidence that the released tool completed.
      this.#action.onRunEnd(context.runId ?? event.runId);
    });
    api.lifecycle.registerRuntimeLifecycle({
      id: "agentguard-product-composition",
      cleanup: this.#cleanup,
    });
    REGISTERED.set(this.#provider.wrapStreamFn!, this);
  }
  assertRegistry(): void {
    const r = registry(),
      w = this.#witness;
    const selected = r?.plugins.filter(
      (p) => p.id === PRODUCT_FIXTURE_PLUGIN_ID,
    );
    const knownSurfaces = new Set([
      "plugins",
      "diagnostics",
      "providers",
      "agentToolResultMiddlewares",
      "typedHooks",
      "hooks",
      "tools",
      "channels",
      "channelSetups",
      "runtimeLifecycles",
    ]);
    const owned = (v: {
      pluginId?: string;
      source: string;
      rootDir?: string;
    }) =>
      v.pluginId === PRODUCT_FIXTURE_PLUGIN_ID &&
      v.source === ENTRY &&
      v.rootDir === ENTRY_ROOT;
    if (
      !r ||
      !w ||
      selected?.length !== 1 ||
      selected[0]?.status !== "loaded" ||
      selected[0]?.enabled !== true ||
      selected[0]?.activated !== true ||
      selected[0]?.source !== ENTRY ||
      selected[0]?.rootDir !== ENTRY_ROOT ||
      new Set(r.plugins.map((p) => p.id)).size !== r.plugins.length ||
      r.plugins.some(
        (p) =>
          p.id !== PRODUCT_FIXTURE_PLUGIN_ID &&
          (p.status !== "disabled" ||
            p.enabled !== false ||
            p.activated !== false ||
            p.imported === true),
      ) ||
      Object.entries(r).some(
        ([name, value]) =>
          !knownSurfaces.has(name) &&
          (Array.isArray(value)
            ? value.length !== 0
            : !value ||
              typeof value !== "object" ||
              Object.keys(value).length !== 0),
      ) ||
      r.providers.length !== 1 ||
      !owned(r.providers[0]!) ||
      r.providers[0]?.provider.wrapStreamFn !== this.#provider.wrapStreamFn ||
      r.providers[0]?.provider.buildReplayPolicy !==
        this.#provider.buildReplayPolicy ||
      r.agentToolResultMiddlewares.length !== 1 ||
      !owned(r.agentToolResultMiddlewares[0]!) ||
      r.agentToolResultMiddlewares[0]?.rawHandler !== this.#middleware ||
      r.agentToolResultMiddlewares[0]?.runtimes?.join("|") !== "openclaw" ||
      r.typedHooks.length !== this.#hooks.size ||
      new Set(r.typedHooks.map((h) => h.hookName)).size !== this.#hooks.size ||
      r.typedHooks.some(
        (h) =>
          h.pluginId !== PRODUCT_FIXTURE_PLUGIN_ID ||
          h.source !== ENTRY ||
          this.#hooks.get(h.hookName) !== h.handler ||
          h.priority !== 1000,
      ) ||
      r.hooks.length !== 0 ||
      r.tools.length !== 2 ||
      new Set(r.tools.map((t) => t.factory)).size !== 2 ||
      r.tools.some(
        (t) => !owned(t) || !w.memoryFactories.includes(t.factory),
      ) ||
      r.channels.length !== 1 ||
      !owned(r.channels[0]!) ||
      r.channels[0]?.plugin.id !== w.channel.id ||
      r.channels[0]?.plugin.config !== w.channel.config ||
      r.channels[0]?.plugin.actions !== w.channel.actions ||
      r.channels[0]?.plugin.outbound !== w.channel.outbound ||
      r.channels[0]?.plugin.actions?.prepareSendPayload !==
        w.outbound.prepareSendPayload ||
      r.channels[0]?.plugin.outbound?.sendPayload !== w.outbound.sendPayload ||
      r.channels[0]?.plugin.outbound?.sendText !== w.outbound.sendText ||
      r.channelSetups.length !== 1 ||
      !owned(r.channelSetups[0]!) ||
      r.channelSetups[0]?.enabled !== true ||
      r.channelSetups[0]?.plugin !== r.channels[0]?.plugin ||
      r.runtimeLifecycles.length !== 1 ||
      !owned(r.runtimeLifecycles[0]!) ||
      r.runtimeLifecycles[0]?.lifecycle.cleanup !== this.#cleanup
    )
      fail("product_registration_incomplete");
  }
  assertCurrent(): void {
    assertPinnedOpenClawHostLoader();
    if (this.#state === "closed" || this.#state === "blocked") fail();
    checkEnvironment(this.profile);
    assertProductRuntimeAssets(this.profile);
    this.assertRegistry();
    this.#runConfig?.assertCurrent();
    this.#candidate?.assertCurrent();
    this.#runtimeConfig?.assertCurrent();
    if (this.#outbox?.status().breakerOpen) fail("product_delivery_blocked");
  }
  async inventory() {
    this.assertCurrent();
    const sdk = await import("openclaw/plugin-sdk/agent-harness");
    const tools = sdk.createOpenClawCodingTools(this.profile.toolOptions);
    const pluginOrder = [
      ...new Set(
        tools.map((t) => sdk.getPluginToolMeta(t)?.pluginId ?? "openclaw-core"),
      ),
    ];
    const inventory = await collectOpenClawProductInventory({
      runtimeVersion: "2026.7.1-2",
      sdk,
      toolOptions: this.profile.toolOptions,
      pluginOrder,
      normalizationOptions: {
        provider: this.profile.providerId,
        allowProviderRuntimePluginLoad: false,
      },
    });
    const modelVisibleTools = tools
      .map((t) => ({
        name: t.name,
        description: t.description,
        parameters: inventory.inputSchemas[t.name],
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    return { inventory, modelVisibleTools };
  }
  async inspect(
    candidateTgzPath: string,
  ): Promise<OpenClawProductRuntimeInspection> {
    const candidate = await verifyInstalledOpenClawCandidate(candidateTgzPath);
    const actual = await this.inventory();
    return Object.freeze({
      inventory: {
        tools: actual.inventory.tools,
        input_schemas: actual.inventory.inputSchemas,
        plugin_order: actual.inventory.pluginOrder,
      },
      digests: actual.inventory.digests,
      modelVisibleTools: actual.modelVisibleTools,
      execution: Object.freeze({
        root: this.profile.workspaceDir,
        memory_namespace: join(this.profile.workspaceDir, "memory.sqlite"),
        inbox_url: this.profile.inboxUrl,
        script_digest: this.profile.assetCommitments.markerDigest,
      }),
      capabilityConsumers: CONSUMERS,
      residualBoundaries: RESIDUALS,
      packageVersion: candidate.packageVersion,
      artifactDigest: candidate.artifactDigest,
      runtimeVersion: candidate.runtimeVersion,
      active: false as const,
    });
  }
  start(): Promise<void> {
    if (this.#state === "closed" || this.#state === "blocked")
      return Promise.reject(new Error("product_composition_unavailable"));
    if (preparing)
      return Promise.reject(new Error("product_composition_preparing"));
    this.#start ??= this.#initialize();
    return this.#start;
  }
  async #initialize(): Promise<void> {
    try {
      this.assertCurrent();
      if (runningOwner && runningOwner !== this)
        fail("product_runtime_already_selected");
      runningOwner = this;
      const config = (this.#runConfig = readProductRunManifest(
          this.runManifestPath,
        )),
        d = config.data;
      if (d.profileConfigPath !== this.profile.configPath) fail();
      this.#candidate = await verifyInstalledOpenClawCandidate(
        d.candidateTgzPath,
      );
      const manifest = await OpenClawProductManifest.fromFile(
        d.activationManifestPath,
      );
      await manifest.assertInstalledVersions();
      if (manifest.data.agent_id !== this.profile.agentId) fail();
      const secret = await resolveSecretRefValues([d.adapterTokenRef], {
        config: this.profile.config,
        env: process.env,
      });
      const token = secret.values().next().value;
      if (secret.size !== 1 || typeof token !== "string" || !token)
        fail("product_credentials_unavailable");
      this.assertCurrent();
      this.#runtimeConfig = await prepareProductRuntimeConfig(
        this.profile,
        this.#abort.signal,
      );
      this.assertCurrent();
      const base = buildPluginConfig({
        guardApiBaseUrl: d.guardApiBaseUrl,
        adapterToken: token,
        agentId: this.profile.agentId,
        runtimeBindingId: manifest.data.runtime_binding_id,
        diagnosticLogging: false,
      });
      const client = (this.#client = new GuardApiClient({
        config: {
          ...base,
          officialProfileId: manifest.data.profile_id,
          officialProfileDigest: manifest.data.profile_digest,
          productManifestPath: d.activationManifestPath,
          productReceiptDirectory: d.productReceiptDirectory,
          productReceiptKeyPath: d.productReceiptKeyPath,
          restrictedAskReleaseEnabled: true,
        },
      }));
      const initial = await this.inventory();
      this.#inventoryDigest = restrictedDigest(initial);
      const observe = async () => {
        this.assertCurrent();
        const actual = await this.inventory();
        if (restrictedDigest(actual) !== this.#inventoryDigest)
          fail("product_inventory_changed");
        const report = {
          schema_version: "2.0",
          runtime: "openclaw",
          agent_id: this.profile.agentId,
          runtime_binding_id: base.runtimeBindingId,
          profile_id: manifest.data.profile_id,
          supported: true,
          active: true,
          c0_registration: true,
          c1_pre_execution_interception: true,
          c2_correlation: true,
          c3_atomic_replace_and_seal: false,
          c4_outcome_receipts: true,
          events: CONSUMERS.map((e) => ({
            ...e,
            supported: true,
            active: true,
          })),
          residual_boundaries: RESIDUALS,
        };
        const { schema_version: _, ...digests } = actual.inventory.digests;
        return readOpenClawProductRuntimeObservation({
          runtime: "openclaw",
          runtime_version: this.#candidate!.runtimeVersion,
          plugin_version: this.#candidate!.packageVersion,
          loaded: true,
          enforcement_mode: "enforce",
          adapter_artifact_digest: this.#candidate!.artifactDigest,
          ...digests,
          capability_report: {
            ...report,
            report_digest: restrictedDigest(report),
          },
        });
      };
      this.#content = new OpenClawProductContentRuntime({
        client,
        binding: {
          agentId: this.profile.agentId,
          sessionKey: this.profile.scopeSessionId,
          taskId: d.taskId,
          userTask: d.taskText,
          traceId: d.traceId,
          provider: this.profile.providerId,
          modelId: this.profile.modelId,
        },
        tools: initial.modelVisibleTools,
        memoryNamespace: join(this.profile.workspaceDir, "memory.sqlite"),
        ensureStarted: () => this.#action!.start(),
        consumeContext: createProductContextConsumer({
          scopeDigest: d.scopeDigest,
          taskSummary: d.taskText,
        }),
        verifyWirePayload: verifyProductNativeWirePayload,
      });
      const content = this.#content;
      this.#action = new OpenClawProductActionRuntime({
        client,
        observe,
        profile: {
          agentId: this.profile.agentId,
          workspaceRoot: this.profile.workspaceDir,
          memoryNamespace: join(this.profile.workspaceDir, "memory.sqlite"),
          inboxUrl: this.profile.inboxUrl,
        },
        originProvider: (call, signal) => content.originProvider(call, signal),
        resultCheckpoint: (input, signal) =>
          content.resultCheckpoint(input, signal),
        messageBridge: this.#bridge,
      });
      const hooks = content.streamHooks();
      this.#stream = new OpenClawProductNativeStream({
        binding: {
          provider: this.profile.providerId,
          modelId: this.profile.modelId,
          baseUrl:
            this.profile.config.models!.providers![this.profile.providerId]!
              .baseUrl!,
          agentId: this.profile.agentId,
          sessionId: this.profile.sessionId,
          agentDir: this.profile.agentDir,
          workspaceDir: this.profile.workspaceDir,
        },
        hooks: {
          ...hooks,
          beginModelCall: async (input, signal) => {
            const ticket = await hooks.beginModelCall(input, signal);
            this.#modelAttempts++;
            return ticket;
          },
        },
      });
      this.#outbox = await client.openProductDelivery();
      this.#outbox.assertReady();
      await this.#action.start();
      this.assertCurrent();
      await client.snapshotProductAck();
      this.assertCurrent();
      this.#state = "ready";
    } catch {
      this.block();
      await this.#closeParts();
      throw new Error("product_composition_start_failed");
    }
  }
  snapshot(): OpenClawProductRuntimeSnapshot {
    if (this.#state !== "closed" && this.#state !== "blocked")
      try {
        this.assertCurrent();
      } catch {
        this.block();
      }
    return Object.freeze({
      state: this.#state,
      ready: this.#state === "ready",
      active: this.#state === "ready" || this.#state === "running",
      c3AtomicReplaceAndSeal: false,
      modelAttempts: this.#modelAttempts,
      ...(this.#outbox ? { delivery: this.#outbox.status() } : {}),
      ...(this.#error ? { errorCode: this.#error } : {}),
    });
  }
  async run(): Promise<
    Readonly<{ status: "completed"; payloads: readonly unknown[] }>
  > {
    await this.start();
    if (this.#state !== "ready") fail("product_run_unavailable");
    this.assertCurrent();
    this.#outbox!.assertReady();
    this.#state = "running";
    try {
      await this.#client!.snapshotProductAck();
      this.assertCurrent();
      const { agentCommand } =
        await import("openclaw/plugin-sdk/agent-runtime");
      const result = await agentCommand(
        {
          message: this.#runConfig!.data.taskText,
          agentId: this.profile.agentId,
          sessionId: this.profile.sessionId,
          sessionKey: this.profile.sessionKey,
          channel: this.profile.toolOptions.messageChannel,
          accountId: "default",
          messageProvider: this.profile.toolOptions.messageProvider,
          to: this.profile.toolOptions.messageTo,
          workspaceDir: this.profile.workspaceDir,
          cwd: this.profile.workspaceDir,
          senderIsOwner: false,
          oneShotCliRun: true,
          abortSignal: this.#abort.signal,
          toolsAllow: [...this.profile.config.tools!.allow!],
          onActiveModelSelected: ({ provider, model }) => {
            this.assertCurrent();
            if (
              provider !== this.profile.providerId ||
              model !== this.profile.modelId
            )
              fail("product_model_changed");
          },
        },
        {
          log() {},
          error() {},
          exit() {
            fail("product_host_failed");
          },
        },
      );
      this.assertCurrent();
      this.#outbox!.assertReady();
      if (result.meta?.error || !this.#modelAttempts)
        fail("product_run_withheld");
      this.#state = "completed";
      return Object.freeze({
        status: "completed",
        payloads: Object.freeze(result.payloads ?? []),
      });
    } catch {
      this.block();
      throw new Error("product_run_withheld");
    }
  }
  block(): void {
    if (this.#state !== "closed") {
      this.#state = "blocked";
      this.#error = "product_composition_blocked";
      this.#abort.abort();
      this.#stream?.close();
      this.#content?.close();
      this.#client?.closeProductSession();
    }
  }
  async #closeParts(): Promise<void> {
    try {
      this.#stream?.close();
      this.#content?.close();
      this.#bridge.close();
      await this.#action?.close();
    } finally {
      try {
        await this.#client?.closeProductDelivery();
      } finally {
        this.#runtimeConfig?.close();
      }
    }
  }
  async close(): Promise<void> {
    if (this.#state === "closed") return;
    this.#state = "closed";
    this.#abort.abort();
    try {
      await this.#closeParts();
    } finally {
      if (runningOwner === this) runningOwner = undefined;
    }
  }
}
/** Installed Product entry only; actual Host API registration is verified before use. */
export function createOpenClawProductPlugin(): OpenClawPluginDefinition {
  return {
    id: PRODUCT_FIXTURE_PLUGIN_ID,
    name: "AgentGuard Product Runtime",
    register(api) {
      new ProductComposition(api);
    },
  };
}
async function preload(profileConfigPath: string): Promise<ProductComposition> {
  if (runningOwner) fail("product_runtime_already_selected");
  const profile = loadProductRuntimeProfileSync(
    productAbsolutePath(profileConfigPath),
  );
  selectEnvironment(profile);
  await loadPinnedOpenClawHostRegistry(profile);
  const r = registry(),
    callback = r?.providers[0]?.provider.wrapStreamFn;
  const composition = callback ? REGISTERED.get(callback) : undefined;
  if (!composition || composition.profile.configPath !== profile.configPath)
    fail("product_registration_incomplete");
  composition.assertCurrent();
  return composition;
}
/** Pre-admission inspection reports observed wiring with active=false and makes no model/API calls. */
export async function inspectOpenClawProductRuntime(options: {
  profileConfigPath: string;
  candidateTgzPath: string;
}): Promise<OpenClawProductRuntimeInspection> {
  const release = reservePreparation();
  try {
    await verifyInstalledOpenClawCandidate(options.candidateTgzPath);
    return await (
      await preload(options.profileConfigPath)
    ).inspect(options.candidateTgzPath);
  } finally {
    release();
  }
}
/** Explicit complete composition. The legacy plugin/config has no enable bypass. */
export async function createOpenClawProductRuntime(options: {
  runManifestPath: string;
}): Promise<OpenClawProductRuntime> {
  const release = reservePreparation();
  try {
    const path = productAbsolutePath(options.runManifestPath),
      config = readProductRunManifest(path);
    await verifyInstalledOpenClawCandidate(config.data.candidateTgzPath);
    const c = await preload(config.data.profileConfigPath);
    if (c.runManifestPath !== path) fail();
    return Object.freeze({
      start: () => c.start(),
      snapshot: () => c.snapshot(),
      status: () => c.snapshot(),
      run: () => c.run(),
      close: () => c.close(),
    });
  } finally {
    release();
  }
}
