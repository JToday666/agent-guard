/** Native-host inventory evidence only; this driver never enables Product Active. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { readFile, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PRODUCT_TOOL_IDS, PRODUCT_FIXTURE_PLUGIN_ID } from "./profile.mjs";
import {
  collectOpenClawProductInventory,
  buildOpenClawProductInventory,
} from "../../../packages/agentguard-openclaw-plugin/dist/runtime/product-inventory.js";
import { restrictedDigest } from "../../../packages/agentguard-openclaw-plugin/dist/runtime/canonical.js";

const HOST_VERSION = "2026.7.1-2";
const MODEL_ID = "inventory-probe";
const MAX_BODY_BYTES = 2 * 1024 * 1024;

function fail(code) {
  throw new Error(`OpenClaw inventory probe: ${code}`);
}

function sortedNames(items, key) {
  const names = items.map((item) => item[key]);
  if (
    names.some((name) => typeof name !== "string") ||
    new Set(names).size !== names.length
  ) {
    fail("invalid_or_duplicate_tool_identity");
  }
  return names.sort();
}

function assertToolSet(items, key, phase) {
  if (
    JSON.stringify(sortedNames(items, key)) !== JSON.stringify(PRODUCT_TOOL_IDS)
  ) {
    fail(`${phase}_tool_set_mismatch`);
  }
}

/** Accept an installed package root or npm prefix, never a guessed version. */
export async function resolvePinnedOpenClaw(openclawRoot) {
  if (typeof openclawRoot !== "string" || !path.isAbsolute(openclawRoot)) {
    fail("absolute_openclaw_root_required");
  }
  for (const candidate of [
    openclawRoot,
    path.join(openclawRoot, "node_modules", "openclaw"),
    path.join(openclawRoot, "lib", "node_modules", "openclaw"),
  ]) {
    let manifest;
    try {
      manifest = JSON.parse(
        await readFile(path.join(candidate, "package.json"), "utf8"),
      );
    } catch {
      continue;
    }
    if (manifest.name !== "openclaw") continue;
    if (manifest.version !== HOST_VERSION) fail("pinned_host_version_mismatch");
    const root = await realpath(candidate);
    const binary =
      typeof manifest.bin === "string" ? manifest.bin : manifest.bin?.openclaw;
    if (typeof binary !== "string") fail("host_cli_entry_missing");
    return {
      root,
      version: manifest.version,
      cliPath: path.join(root, binary),
      requireHost: createRequire(path.join(root, "package.json")),
    };
  }
  fail("installed_openclaw_package_not_found");
}

async function startControlledProvider() {
  const requests = [];
  let rejectedRequests = 0;
  const server = createServer(async (request, response) => {
    const reject = () => {
      rejectedRequests += 1;
      response.writeHead(400, { "content-type": "application/json" });
      response.end('{"error":"inventory_probe_request_rejected"}');
    };
    if (
      request.method !== "POST" ||
      request.url !== "/v1/chat/completions" ||
      requests.length !== 0
    ) {
      request.resume();
      reject();
      return;
    }
    try {
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) throw new Error("request_too_large");
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (body.model !== MODEL_ID || !Array.isArray(body.tools))
        throw new Error("invalid_model_request");
      const tools = body.tools.map((tool) => {
        if (
          tool.type !== "function" ||
          !tool.function ||
          typeof tool.function.name !== "string" ||
          !tool.function.parameters ||
          tool.function.parameters.type !== "object"
        ) {
          throw new Error("invalid_tool_schema");
        }
        return {
          name: tool.function.name,
          parameters: tool.function.parameters,
        };
      });
      // Do not retain prompts, headers, authorization, or any user-visible content.
      requests.push({
        model: body.model,
        tools,
        streamed: body.stream === true,
      });
      const created = Math.floor(Date.now() / 1000);
      if (body.stream === true) {
        response.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-store",
        });
        for (const [delta, finishReason] of [
          [{ role: "assistant", content: "Inventory captured." }, null],
          [{}, "stop"],
        ]) {
          response.write(
            `data: ${JSON.stringify({
              id: "inventory-probe",
              object: "chat.completion.chunk",
              created,
              model: MODEL_ID,
              choices: [{ index: 0, delta, finish_reason: finishReason }],
            })}\n\n`,
          );
        }
        response.end("data: [DONE]\n\n");
      } else {
        response.writeHead(200, {
          "content-type": "application/json",
          "cache-control": "no-store",
        });
        response.end(
          JSON.stringify({
            id: "inventory-probe",
            object: "chat.completion",
            created,
            model: MODEL_ID,
            choices: [
              {
                index: 0,
                message: { role: "assistant", content: "Inventory captured." },
                finish_reason: "stop",
              },
            ],
            usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
          }),
        );
      }
    } catch {
      reject();
    }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.setTimeout(5000, (socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}/v1`,
    requests,
    get rejectedRequests() {
      return rejectedRequests;
    },
    async close() {
      server.closeAllConnections();
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

function isolatedEnvironment(profile) {
  const env = {};
  for (const key of [
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SystemRoot",
    "SYSTEMROOT",
  ]) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  Object.assign(env, profile.env, {
    OPENCLAW_AGENT_DIR: profile.agentDir,
    NO_COLOR: "1",
    FORCE_COLOR: "0",
  });
  return env;
}

async function runNativeAgent(host, profile, timeoutMs) {
  const args = [
    host.cliPath,
    "agent",
    "--local",
    "--agent",
    profile.agentId,
    "--session-key",
    profile.sessionKey,
    "--session-id",
    profile.sessionId,
    "--channel",
    profile.toolOptions.messageChannel,
    "--to",
    profile.toolOptions.messageTo,
    "--message",
    "Return a short acknowledgement without invoking any tools.",
    "--thinking",
    "off",
    "--timeout",
    String(Math.ceil(timeoutMs / 1000)),
    "--json",
  ];
  const logPath = path.join(profile.stateDir, "inventory-native-agent.log");
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: profile.workspaceDir,
      env: isolatedEnvironment(profile),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks = [];
    let size = 0;
    let timedOut = false;
    let exceededOutput = false;
    let killTimer;
    const stop = () => {
      child.kill("SIGTERM");
      killTimer = setTimeout(() => child.kill("SIGKILL"), 1000);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, timeoutMs + 5000);
    const collect = (chunk) => {
      size += chunk.length;
      if (size <= MAX_BODY_BYTES) chunks.push(chunk);
      else if (!exceededOutput) {
        exceededOutput = true;
        stop();
      }
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.once("error", (error) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      resolve({
        code,
        signal,
        timedOut,
        exceededOutput,
        log: Buffer.concat(chunks),
      });
    });
  });
  await writeFile(logPath, result.log, { mode: 0o600, flag: "wx" });
  if (result.timedOut || result.exceededOutput || result.code !== 0) {
    fail(`native_agent_failed_see_${logPath}`);
  }
  return { exit_code: result.code, log_path: logPath };
}

async function importHostFacade(host, relativePath) {
  return import(pathToFileURL(path.join(host.root, relativePath)).href);
}

async function effectiveTools(host, profile) {
  // The pinned build exports the actual Gateway handler from one hashed module.
  // Resolve by its stable build prefix and verify the expected named export.
  const modules = (await readdir(path.join(host.root, "dist"))).filter((name) =>
    /^tools-effective-[A-Za-z0-9_-]+\.js$/u.test(name),
  );
  const candidates = [];
  for (const name of modules) {
    const source = await readFile(path.join(host.root, "dist", name), "utf8");
    if (/export\s*\{[^}]*\btoolsEffectiveHandlers\b/u.test(source))
      candidates.push(name);
  }
  if (candidates.length !== 1)
    fail("pinned_effective_handler_resolution_failed");
  const { toolsEffectiveHandlers } = await importHostFacade(
    host,
    `dist/${candidates[0]}`,
  );
  if (typeof toolsEffectiveHandlers?.["tools.effective"] !== "function")
    fail("effective_handler_missing");
  let result;
  await toolsEffectiveHandlers["tools.effective"]({
    params: { sessionKey: profile.sessionKey, agentId: profile.agentId },
    context: { getRuntimeConfig: () => profile.config },
    respond(ok, payload, error) {
      result = { ok, payload, error };
    },
  });
  if (!result?.ok || !Array.isArray(result.payload?.groups))
    fail("effective_projection_failed");
  if ((result.payload.notices ?? []).length !== 0)
    fail("effective_projection_has_notices");
  const tools = result.payload.groups.flatMap((group) => group.tools);
  assertToolSet(tools, "id", "effective");
  return { tools, handler: `dist/${candidates[0]}` };
}

/**
 * Create one fresh profile after the local provider is bound. The model performs
 * a genuine OpenClaw agent turn, but its controlled completion calls no tools.
 * This is inventory evidence, not an Active, durable, or Gateway-wire gate.
 */
export async function runProductRuntimeInventoryProbe({
  createProfile,
  openclawRoot,
  timeoutMs = 60000,
}) {
  if (
    typeof createProfile !== "function" ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1000 ||
    timeoutMs > 120000
  ) {
    fail("invalid_probe_options");
  }
  const host = await resolvePinnedOpenClaw(openclawRoot);
  const provider = await startControlledProvider();
  const savedEnv = new Map();
  try {
    const profile = await createProfile({
      modelBaseUrl: provider.baseUrl,
      modelId: MODEL_ID,
      modelApiKey: "inventory-probe-local",
    });
    for (const [key, value] of Object.entries({
      ...profile.env,
      OPENCLAW_AGENT_DIR: profile.agentDir,
    })) {
      if (!key.startsWith("OPENCLAW_")) fail("unexpected_profile_environment");
      savedEnv.set(key, process.env[key]);
      process.env[key] = value;
    }
    const configuredProvider =
      profile.config.models?.providers?.[profile.toolOptions.modelProvider];
    if (
      configuredProvider?.baseUrl !== provider.baseUrl ||
      configuredProvider?.api !== "openai-completions" ||
      Object.keys(profile.config.models.providers).length !== 1
    )
      fail("profile_provider_mismatch");
    const nativeRun = await runNativeAgent(host, profile, timeoutMs);
    if (provider.requests.length !== 1 || provider.rejectedRequests !== 0)
      fail("controlled_request_count_mismatch");
    const modelTools = provider.requests[0].tools;
    assertToolSet(modelTools, "name", "model_visible");

    const loader = await importHostFacade(host, "dist/plugins/loader.js");
    const registry = loader.loadOpenClawPlugins({
      config: profile.config,
      workspaceDir: profile.workspaceDir,
      env: isolatedEnvironment(profile),
      cache: false,
      activate: true,
      forceFullRuntimeForChannelPlugins: true,
      onlyPluginIds: [PRODUCT_FIXTURE_PLUGIN_ID],
      throwOnLoadError: true,
    });
    const loadedPlugins = registry.plugins.filter(
      (plugin) => plugin.status === "loaded",
    );
    if (
      loadedPlugins.length !== 1 ||
      loadedPlugins[0].id !== PRODUCT_FIXTURE_PLUGIN_ID
    )
      fail("loaded_plugin_set_mismatch");
    const sdk = await import(
      pathToFileURL(
        host.requireHost.resolve("openclaw/plugin-sdk/agent-harness"),
      ).href
    );
    const factoryTools = sdk.createOpenClawCodingTools(profile.toolOptions);
    assertToolSet(factoryTools, "name", "factory");
    if (sdk.inspectRuntimeToolInputSchemas(factoryTools).length !== 0)
      fail("factory_schema_diagnostics");
    const factoryPluginOrder = [
      ...new Set(
        factoryTools.map(
          (tool) => sdk.getPluginToolMeta(tool)?.pluginId ?? "openclaw-core",
        ),
      ),
    ];
    const effective = await effectiveTools(host, profile);
    const pluginOrder = [
      ...new Set(
        effective.tools.map((tool) => {
          if (tool.source === "core") return "openclaw-core";
          if (tool.source === "plugin" && typeof tool.pluginId === "string")
            return tool.pluginId;
          return fail("unexpected_effective_tool_source");
        }),
      ),
    ];
    if (JSON.stringify(factoryPluginOrder) !== JSON.stringify(pluginOrder))
      fail("catalog_factory_order_mismatch");
    const inventory = await collectOpenClawProductInventory({
      runtimeVersion: host.version,
      sdk,
      toolOptions: profile.toolOptions,
      pluginOrder,
      normalizationOptions: { allowProviderRuntimePluginLoad: false },
    });
    const modelInventory = buildOpenClawProductInventory({
      pluginOrder,
      tools: modelTools.map((tool) => {
        const entry = effective.tools.find(
          (candidate) => candidate.id === tool.name,
        );
        if (
          restrictedDigest(inventory.inputSchemas[tool.name]) !==
          restrictedDigest(tool.parameters)
        ) {
          fail(`model_schema_mismatch_${tool.name}`);
        }
        if (
          tool.name.startsWith("agentguard_memory_") &&
          entry.pluginId !== PRODUCT_FIXTURE_PLUGIN_ID
        ) {
          fail("memory_tool_owner_mismatch");
        }
        return {
          name: tool.name,
          sourcePluginId: entry.pluginId ?? "openclaw-core",
          parameters: tool.parameters,
        };
      }),
    });
    if (
      restrictedDigest(inventory.digests) !==
      restrictedDigest(modelInventory.digests)
    )
      fail("model_inventory_digest_mismatch");
    const fixtureBytes = await readFile(
      new URL("./fixtures.json", import.meta.url),
    );
    const fixtures = JSON.parse(fixtureBytes.toString("utf8"));
    if (fixtures.schema_version !== "1.0" || !Array.isArray(fixtures.tools))
      fail("invalid_fixture_manifest");
    assertToolSet(fixtures.tools, "tool_id", "fixture");
    const AjvModule = host.requireHost("ajv");
    const Ajv = AjvModule.default ?? AjvModule;
    const validator = new Ajv({ allErrors: true, strict: false });
    for (const tool of inventory.tools) {
      const fixture = fixtures.tools.find(
        (candidate) => candidate.tool_id === tool.tool_id,
      );
      if (
        fixture.fixture_id !== tool.fixture_id ||
        fixture.event_type !== tool.event_type
      ) {
        fail("fixture_identity_or_event_type_mismatch");
      }
      if (
        !validator.validate(
          inventory.inputSchemas[tool.tool_id],
          fixture.arguments,
        )
      ) {
        fail(`fixture_arguments_schema_mismatch_${tool.tool_id}`);
      }
    }
    return {
      schema_version: "agentguard-openclaw-product-inventory/1.0",
      status: "PASS",
      phase: "pre_activation_inventory",
      product_active: false,
      runtime_version: host.version,
      host_root: host.root,
      profile_root: profile.stateDir,
      session_key: profile.sessionKey,
      native_agent: nativeRun,
      controlled_model_requests: provider.requests.length,
      external_provider_requests: 0,
      model_mode: "controlled_local_completion_without_tool_execution",
      effective_projection_transport: "in_process_gateway_handler",
      effective_handler: effective.handler,
      effective_tool_sources: effective.tools.map((tool) => ({
        tool_id: tool.id,
        source: tool.source,
        source_plugin_id: tool.pluginId ?? "openclaw-core",
      })),
      loaded_plugin_ids: loadedPlugins.map((plugin) => plugin.id),
      tools: inventory.tools,
      input_schemas: inventory.inputSchemas,
      plugin_order: inventory.pluginOrder,
      digests: inventory.digests,
      fixtures: {
        schema_version: fixtures.schema_version,
        tools: fixtures.tools,
        file_sha256: `sha256:${createHash("sha256").update(fixtureBytes).digest("hex")}`,
        executed: false,
      },
      qualification: {
        product_active: false,
        gateway_wire: false,
        invocation_receipts: false,
        durable_delivery: false,
        internal_rc: false,
      },
    };
  } finally {
    for (const [key, value] of savedEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await provider.close();
  }
}
