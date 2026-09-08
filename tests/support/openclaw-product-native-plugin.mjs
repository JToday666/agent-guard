/** Test-only trusted assembly. This is never imported by production dist. */
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { createFixturePlugin } from "./openclaw-product-runtime/index.mjs";
import { createMessagePermitBridge } from "./openclaw-product-runtime/message-permits.mjs";

export function createNativeLoopPlugin(preparedPath, runtimePath) {
  const prepared = JSON.parse(readFileSync(preparedPath, "utf8"));
  const { profile, packageRoot } = prepared;
  const runtime = runtimePath
    ? JSON.parse(readFileSync(runtimePath, "utf8"))
    : undefined;
  const tracePath = path.join(prepared.root, "native-events.jsonl");
  const trace = (stage, extra = {}) =>
    appendFileSync(tracePath, JSON.stringify({ stage, ...extra }) + "\n", {
      mode: 0o600,
    });
  const privateFailure = (error) =>
    appendFileSync(
      path.join(prepared.root, "native-private-error.log"),
      String(error?.stack ?? "native failure") + "\n",
      { mode: 0o600 },
    );
  let nativeEventBytes = 0;
  const nativeEvent = (entry) => {
    const encoded = Buffer.from(JSON.stringify(entry) + "\n");
    if (nativeEventBytes + encoded.length > 1024 * 1024) return;
    appendFileSync(
      path.join(prepared.root, "native-model-events.jsonl"),
      encoded,
      { mode: 0o600 },
    );
    nativeEventBytes += encoded.length;
  };
  const bridge = createMessagePermitBridge({ sessionKey: profile.sessionKey });
  const fixture = runtime
    ? createFixturePlugin({ productMode: true, messagePermitBridge: bridge })
    : createFixturePlugin();
  let assembling, ready;
  const url = (name) =>
    pathToFileURL(path.join(packageRoot, "dist", name)).href;
  async function assemble() {
    if (!runtime) throw new Error("native_test_runtime_not_supplied");
    assembling ??= (async () => {
      const [
        clientModule,
        manifestModule,
        actionModule,
        contentModule,
        streamModule,
        planModule,
        inventoryModule,
      ] = await Promise.all([
        import(url("guard-api-client.js")),
        import(url("runtime/product-manifest.js")),
        import(url("runtime/product-action-runtime.js")),
        import(url("runtime/product-content-runtime.js")),
        import(url("runtime/product-native-stream.js")),
        import(url("runtime/product-context-plan.js")),
        import(url("runtime/product-inventory.js")),
      ]);
      const requirePackage = createRequire(
        path.join(packageRoot, "package.json"),
      );
      const sdk = await import(
        pathToFileURL(
          requirePackage.resolve("openclaw/plugin-sdk/agent-harness"),
        ).href
      );
      const config = {
        ...clientModule.buildPluginConfig({
          guardApiBaseUrl: runtime.baseUrl,
          adapterToken: runtime.token,
          agentId: profile.agentId,
          runtimeBindingId:
            runtime.observation.capability_report.runtime_binding_id,
          requestTimeoutMs: 5000,
          diagnosticLogging: false,
        }),
        officialProfileId: "agentguard-openclaw-v2-restricted",
        officialProfileDigest: runtime.profileDigest,
        productManifestPath: runtime.manifestPath,
        productReceiptDirectory: path.join(prepared.root, "receipts"),
        productReceiptKeyPath: path.join(prepared.root, "receipt-keys", "key"),
      };
      const client = new clientModule.GuardApiClient({ config });
      const evaluateProductEvent = client.evaluateProductEvent.bind(client);
      client.evaluateProductEvent = async (event) => {
        const eventType = [
          "context_assembled",
          "model_input_prepared",
          "model_output_produced",
          "tool_call_proposed",
          "tool_result_produced",
          "memory_read_proposed",
          "memory_write_proposed",
          "message_send_proposed",
        ].includes(event.event_type)
          ? event.event_type
          : "unknown";
        trace("evaluation_started", { eventType });
        try {
          const result = await evaluateProductEvent(event);
          const decision = result.evaluation.decision.decision;
          trace("evaluation_returned", {
            eventType,
            decision: ["allow", "ask", "deny"].includes(decision)
              ? decision
              : "unknown",
          });
          return result;
        } catch (error) {
          privateFailure(error);
          trace("evaluation_failed", {
            eventType,
            error: "native_test_evaluate_failed",
          });
          throw error;
        }
      };
      const observe = async () => {
        trace("observation_started");
        const actual = await inventoryModule.collectOpenClawProductInventory({
          runtimeVersion: "2026.7.1-2",
          sdk,
          toolOptions: profile.toolOptions,
          pluginOrder: prepared.inventory.plugin_order,
          normalizationOptions: { allowProviderRuntimePluginLoad: false },
        });
        for (const [key, digest] of Object.entries(actual.digests)) {
          if (key !== "schema_version" && runtime.observation[key] !== digest)
            throw new Error("native_test_inventory_drift");
        }
        const observation =
          manifestModule.readOpenClawProductRuntimeObservation(
            runtime.observation,
          );
        trace("observation_validated");
        return observation;
      };
      let action;
      const content = new contentModule.OpenClawProductContentRuntime({
        client,
        binding: {
          agentId: profile.agentId,
          sessionKey: profile.sessionKey,
          taskId: runtime.taskId,
          userTask: runtime.taskText,
          traceId: runtime.traceId,
          provider: "agentguard-acceptance",
          modelId: prepared.modelId,
        },
        tools: prepared.model_visible_tools,
        memoryNamespace: prepared.execution.memory_namespace,
        ensureStarted: () => action.start(),
        consumeContext: planModule.createProductContextConsumer({
          scopeDigest: runtime.scopeDigest,
          taskSummary: runtime.taskText,
        }),
        verifyWirePayload: streamModule.verifyProductNativeWirePayload,
      });
      action = new actionModule.OpenClawProductActionRuntime({
        client,
        observe,
        profile: {
          agentId: profile.agentId,
          workspaceRoot: profile.workspaceDir,
          memoryNamespace: prepared.execution.memory_namespace,
          inboxUrl: prepared.inboxUrl,
        },
        originProvider: (call, signal) => content.originProvider(call, signal),
        resultCheckpoint: (input, signal) =>
          content.resultCheckpoint(input, signal),
        messageBridge: bridge,
      });
      const bound = content.streamHooks();
      const hooks = Object.freeze({
        async prepareInput(input, signal) {
          trace("stream_input");
          writeFileSync(
            path.join(prepared.root, "native-input.json"),
            JSON.stringify(input),
            { mode: 0o600 },
          );
          try {
            const result = await bound.prepareInput(input, signal);
            trace("input_accepted");
            return result;
          } catch (error) {
            privateFailure(error);
            trace("input_failed", { error: "native_test_input_failed" });
            throw error;
          }
        },
        verifyWirePayload(input, payload) {
          bound.verifyWirePayload(input, payload);
          trace("wire_verified");
        },
        async beginModelCall(input, signal) {
          const result = await bound.beginModelCall(input, signal);
          trace("model_released");
          return result;
        },
        async finishModelCall(ticket, outcome, signal) {
          const result = await bound.finishModelCall(ticket, outcome, signal);
          trace("model_receipts_recorded", { outcome: outcome.status });
          return result;
        },
        block(code) {
          trace("stream_blocked");
          bound.block(code);
        },
      });
      const stream = new streamModule.OpenClawProductNativeStream({
        binding: {
          provider: "agentguard-acceptance",
          modelId: prepared.modelId,
          baseUrl: prepared.modelBaseUrl,
          agentId: profile.agentId,
          sessionId: profile.sessionId,
          agentDir: profile.agentDir,
          workspaceDir: profile.workspaceDir,
        },
        hooks,
      });
      ready = { action, content, stream };
      trace("assembly_ready");
      return ready;
    })();
    return assembling;
  }
  return {
    ...fixture,
    register(api) {
      fixture.register(api);
      api.registerProvider({
        id: "agentguard-acceptance",
        label: "Controlled native Product transport",
        auth: [],
        buildReplayPolicy() {
          // Product inspects complete native history and preserves the original
          // call identities. Host repair must not rewrite the committed graph.
          return {
            sanitizeMode: "images-only",
            sanitizeToolCallIds: false,
            repairToolUseResultPairing: false,
            dropThinkingBlocks: false,
            dropReasoningFromHistory: false,
            applyAssistantFirstOrderingFix: false,
            validateGeminiTurns: false,
            validateAnthropicTurns: false,
            allowSyntheticToolResults: false,
          };
        },
        wrapStreamFn(ctx) {
          trace("provider_registered_wrapper");
          // Observe the real transport without additional iterator/result calls.
          // This private test trace does not synthesize any Host hook or output.
          const observedContext = {
            ...ctx,
            streamFn: async (...args) => {
              const inner = await ctx.streamFn(...args);
              return {
                [Symbol.asyncIterator]() {
                  const iterator = inner[Symbol.asyncIterator]();
                  return {
                    async next(...values) {
                      const item = await iterator.next(...values);
                      nativeEvent({ kind: "next", item });
                      return item;
                    },
                    ...(typeof iterator.return === "function"
                      ? {
                          return(...values) {
                            return iterator.return(...values);
                          },
                        }
                      : {}),
                    ...(typeof iterator.throw === "function"
                      ? {
                          throw(...values) {
                            return iterator.throw(...values);
                          },
                        }
                      : {}),
                    [Symbol.asyncIterator]() {
                      return this;
                    },
                  };
                },
                async result(...values) {
                  const result = await inner.result(...values);
                  nativeEvent({ kind: "result", result });
                  return result;
                },
              };
            },
          };
          return async (model, context, options) => {
            try {
              const { stream } = await assemble();
              return await stream.wrapStreamFn(observedContext)(
                model,
                context,
                options,
              );
            } catch (error) {
              privateFailure(error);
              trace("provider_failed");
              throw new Error("native_test_provider_failed");
            }
          };
        },
      });
      api.registerAgentToolResultMiddleware(
        async (event, context) => {
          trace("native_tool_result_middleware", { tool: event.toolName });
          writeFileSync(
            path.join(prepared.root, "native-tool-result.json"),
            JSON.stringify({ event, context }),
            { mode: 0o600 },
          );
          const { action } = await assemble();
          const result = await action.observeToolResultMiddleware(
            event,
            context,
          );
          trace("middleware_returned");
          return result;
        },
        { runtimes: ["openclaw"] },
      );
      api.on(
        "before_tool_call",
        async (event, context) => {
          trace("before_tool_call", { tool: event.toolName });
          const { action } = await assemble();
          const result = await action.before(event, context);
          trace(result?.block ? "tool_blocked" : "tool_released");
          return result;
        },
        { priority: 1000 },
      );
      api.on(
        "after_tool_call",
        async (event, context) => {
          trace("after_tool_call", { tool: event.toolName });
          const { action } = await assemble();
          await action.after(event, context);
        },
        { priority: 1000 },
      );
      api.on(
        "tool_result_persist",
        (event, context) => {
          trace("tool_result_persist", { tool: event.toolName });
          if (!ready) throw new Error("native_test_runtime_unready");
          return ready.action.resultForPersistence(event, context);
        },
        { priority: 1000 },
      );
      api.on(
        "message_sending",
        async (event, context) =>
          (await assemble()).action.messageSending(event, context),
        { priority: 1000 },
      );
      api.on("llm_input", () => {
        trace("llm_input_notification");
      });
      api.on("llm_output", () => {
        trace("llm_output_notification");
      });
      api.on("agent_end", async () => {
        trace("agent_end_notification");
        if (ready) {
          ready.stream.close();
          ready.content.close();
          await ready.action.close();
        }
      });
    },
  };
}
