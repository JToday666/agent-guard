import { randomUUID } from "node:crypto";
import { lstat, mkdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PRODUCT_FIXTURE_PLUGIN_ID = "agentguard-product-runtime-fixture";
export const PRODUCT_FIXTURE_CHANNEL_ID = "agentguard-fixture";
export const PRODUCT_TOOL_IDS = Object.freeze([
  "agentguard_memory_read",
  "agentguard_memory_write",
  "edit",
  "exec",
  "message",
  "process",
  "read",
  "write",
]);
const FIXTURE_PATH = path.dirname(fileURLToPath(import.meta.url));

function localUrl(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid ${label}`);
  }
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.hash
  ) {
    throw new Error(`${label} must be an explicit loopback HTTP endpoint`);
  }
  return url.href.replace(/\/$/, "");
}

/** Create only a fresh, explicitly selected acceptance profile; never use user state. */
export async function createProductRuntimeProfile({
  root,
  inboxUrl,
  modelBaseUrl,
  modelId = "inventory-probe",
  modelApiKey = "inventory-probe-local",
  fixturePluginPath = FIXTURE_PATH,
}) {
  if (
    typeof root !== "string" ||
    !path.isAbsolute(root) ||
    path.resolve(root) !== root
  )
    throw new Error("Acceptance root must be absolute");
  const stat = await lstat(root);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (await realpath(root)) !== root ||
    (process.getuid && stat.uid !== process.getuid())
  ) {
    throw new Error("Acceptance root must be an owned real directory");
  }
  const providerUrl = localUrl(modelBaseUrl, "Model URL");
  const sinkUrl = localUrl(inboxUrl, "Inbox URL");
  if (!/^[a-zA-Z0-9._-]+$/.test(modelId))
    throw new Error("Invalid model identifier");
  const stateDir = path.join(root, "openclaw-state");
  // Exclusive directory creation rejects reuse of an existing profile.
  await mkdir(stateDir, { mode: 0o700 });
  const workspaceDir = path.join(stateDir, "workspace");
  const agentDir = path.join(stateDir, "agents", "main", "agent");
  await mkdir(workspaceDir, { mode: 0o700 });
  await mkdir(agentDir, { recursive: true, mode: 0o700 });
  const configPath = path.join(stateDir, "openclaw.json");
  const sessionId = randomUUID();
  const agentId = "main";
  const sessionKey = `agent:main:product-runtime-${sessionId}`;
  const providerId = "agentguard-acceptance";
  const config = {
    gateway: {
      mode: "local",
      bind: "loopback",
      auth: { mode: "token", token: randomUUID() },
    },
    agents: {
      defaults: {
        workspace: workspaceDir,
        skipBootstrap: true,
        model: { primary: `${providerId}/${modelId}` },
        sandbox: { mode: "off" },
        memorySearch: { enabled: false },
        compaction: { memoryFlush: { enabled: false } },
      },
      list: [
        {
          id: agentId,
          default: true,
          workspace: workspaceDir,
          agentDir,
          skills: [],
        },
      ],
    },
    models: {
      mode: "replace",
      providers: {
        [providerId]: {
          baseUrl: providerUrl,
          apiKey: modelApiKey,
          api: "openai-completions",
          models: [
            {
              id: modelId,
              name: modelId,
              reasoning: false,
              input: ["text"],
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
              contextWindow: 32768,
              maxTokens: 2048,
            },
          ],
        },
      },
    },
    tools: {
      allow: [...PRODUCT_TOOL_IDS],
      fs: { workspaceOnly: true },
      exec: {
        host: "gateway",
        security: "deny",
        ask: "off",
        applyPatch: { enabled: false },
      },
      elevated: { enabled: false },
      web: { search: { enabled: false }, fetch: { enabled: false } },
    },
    browser: { enabled: false },
    plugins: {
      enabled: true,
      allow: [PRODUCT_FIXTURE_PLUGIN_ID],
      load: { paths: [fixturePluginPath] },
      slots: { memory: "none" },
      entries: {
        [PRODUCT_FIXTURE_PLUGIN_ID]: {
          enabled: true,
          config: {
            acceptanceRoot: workspaceDir,
            inboxUrl: sinkUrl,
            inboxTarget: "fixture-inbox",
          },
        },
      },
    },
    channels: { [PRODUCT_FIXTURE_CHANNEL_ID]: { enabled: true } },
  };
  await writeFile(configPath, JSON.stringify(config, null, 2) + "\n", {
    flag: "wx",
    mode: 0o600,
  });
  return {
    config,
    configPath,
    stateDir,
    workspaceDir,
    agentDir,
    agentId,
    sessionKey,
    sessionId,
    env: {
      OPENCLAW_STATE_DIR: stateDir,
      OPENCLAW_CONFIG_PATH: configPath,
      OPENCLAW_DISABLE_FILE_LOGGING: "1",
      OPENCLAW_NO_RESPAWN: "1",
    },
    toolOptions: {
      config,
      agentId,
      sessionKey,
      sessionId,
      workspaceDir,
      cwd: workspaceDir,
      agentDir,
      modelProvider: providerId,
      modelId,
      modelApi: "openai-completions",
      senderIsOwner: false,
      oneShotCliRun: true,
      requireExplicitMessageTarget: true,
      includeToolSearchControls: false,
      runtimeToolAllowlist: [...PRODUCT_TOOL_IDS],
      messageProvider: PRODUCT_FIXTURE_CHANNEL_ID,
      messageChannel: PRODUCT_FIXTURE_CHANNEL_ID,
      messageTo: "fixture-inbox",
    },
  };
}
