/** Owned, installable Product Host profile. No activation or network request here. */
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  constants,
  closeSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { FixtureError, requireAcceptanceRoot } from "./memory.mjs";
import { validateInboxUrl } from "./inbox.mjs";
import { canonical, ownObject, freeze } from "./strict.mjs";
import {
  PRODUCT_FIXTURE_PLUGIN_ID,
  PRODUCT_FIXTURE_CHANNEL_ID,
  PRODUCT_TOOL_IDS,
} from "./baseline-profile.mjs";

export {
  PRODUCT_FIXTURE_PLUGIN_ID,
  PRODUCT_FIXTURE_CHANNEL_ID,
  PRODUCT_TOOL_IDS,
};
export const PRODUCT_MARKER_COMMAND = "node marker.mjs";
const ENTRY_PATH = fileURLToPath(new URL("./product/", import.meta.url));
const MARKER_PATH = fileURLToPath(new URL("./marker.mjs", import.meta.url));
const PROFILES = new WeakMap();
const NODE_LIMIT = 256 * 1024 * 1024;
const INPUT_KEYS = [
  "schemaVersion",
  "root",
  "sessionId",
  "inboxUrl",
  "provider",
  "runManifestPath",
];

function fail() {
  throw new FixtureError("product_assets_invalid");
}
function sha(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
function absolute(value) {
  if (
    typeof value !== "string" ||
    !path.isAbsolute(value) ||
    path.resolve(value) !== value
  )
    fail();
  return value;
}
function identity(stat) {
  return `${stat.dev}:${stat.ino}:${stat.uid}:${stat.mode}:${stat.nlink}`;
}
function privateDirectory(filename) {
  requireAcceptanceRoot(filename);
  const stat = lstatSync(filename);
  if ((stat.mode & 0o777) !== 0o700) fail();
  // The Host creates session subdirectories during a real run, changing nlink.
  // The directory itself must retain the same inode, owner, and permissions.
  return `${stat.dev}:${stat.ino}:${stat.uid}:${stat.mode}`;
}
function assertCommandOutput(profile) {
  try {
    const stat = lstatSync(
      path.join(profile.workspaceDir, "command-marker.txt"),
    );
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o777) !== 0o600 ||
      (process.getuid && stat.uid !== process.getuid())
    )
      fail();
  } catch (error) {
    if (error?.code !== "ENOENT") fail();
  }
}
function fileState(filename, { privateFile = true, limit = 128 * 1024 } = {}) {
  let fd;
  try {
    fd = openSync(
      filename,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = fstatSync(fd, { bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size > BigInt(limit) ||
      before.size < 1n ||
      (privateFile &&
        ((before.mode & 0o777n) !== 0o600n ||
          (process.getuid && before.uid !== BigInt(process.getuid()))))
    )
      fail();
    // Read at most the admitted size plus one byte. Growth after fstat cannot
    // make a private configuration or candidate asset consume unbounded memory.
    const buffer = Buffer.allocUnsafe(Number(before.size) + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = readSync(fd, buffer, used, buffer.length - used, null);
      if (!count) break;
      used += count;
    }
    const bytes = buffer.subarray(0, used);
    const after = fstatSync(fd, { bigint: true });
    const named = lstatSync(filename, { bigint: true });
    const consistent = (stat) =>
      `${identity(stat)}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
    if (
      named.isSymbolicLink() ||
      consistent(before) !== consistent(after) ||
      consistent(after) !== consistent(named) ||
      BigInt(bytes.length) !== before.size
    )
      fail();
    return { bytes, identity: identity(after), digest: sha(bytes) };
  } catch {
    fail();
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
function readPrivateJson(filename) {
  privateDirectory(path.dirname(filename));
  const file = fileState(filename);
  const raw = file.bytes.toString("utf8");
  const parsed = JSON.parse(raw);
  // Exact canonical bytes reject duplicate decoded keys and alternate encodings.
  if (canonical(parsed) + "\n" !== raw) fail();
  return { parsed, file };
}
function secretRef(value) {
  const ref = ownObject(value, ["source", "provider", "id"]);
  if (
    ref.source !== "env" ||
    ref.provider !== "default" ||
    typeof ref.id !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,127}$/u.test(ref.id)
  )
    fail();
  return { source: "env", provider: "default", id: ref.id };
}
function providerConfig(value) {
  const provider = ownObject(
    value,
    ["id", "modelId", "baseUrl", "apiKey", "api"],
    ["id", "modelId", "baseUrl", "apiKey"],
  );
  if (
    provider.id !== "agentguard-acceptance" ||
    typeof provider.baseUrl !== "string" ||
    provider.baseUrl.length > 2048 ||
    (provider.api !== undefined && provider.api !== "openai-completions") ||
    typeof provider.modelId !== "string" ||
    !/^[A-Za-z0-9._-]{1,128}$/u.test(provider.modelId)
  )
    fail();
  const url = new URL(provider.baseUrl);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !(
      (url.protocol === "http:" &&
        ["127.0.0.1", "[::1]"].includes(url.hostname) &&
        url.port) ||
      (url.protocol === "https:" &&
        !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
    )
  )
    fail();
  return {
    id: provider.id,
    modelId: provider.modelId,
    baseUrl: url.href.replace(/\/$/u, ""),
    api: "openai-completions",
    apiKey: secretRef(provider.apiKey),
  };
}
function inputConfig(value) {
  const input = ownObject(value, INPUT_KEYS);
  if (
    input.schemaVersion !== 1 ||
    typeof input.sessionId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      input.sessionId,
    )
  )
    fail();
  absolute(input.root);
  absolute(input.runManifestPath);
  validateInboxUrl(input.inboxUrl);
  return { ...input, provider: providerConfig(input.provider) };
}
function derive(input) {
  const root = input.root;
  const stateDir = path.join(root, "openclaw-state");
  const workspaceDir = path.join(stateDir, "workspace");
  const agentDir = path.join(stateDir, "agents", "main", "agent");
  const configPath = path.join(stateDir, "openclaw.json");
  const profilePath = path.join(stateDir, "product-profile.json");
  const agentId = "main",
    sessionId = input.sessionId;
  const sessionKey = `agent:main:product-runtime-${sessionId}`;
  const { id: providerId, modelId, baseUrl, apiKey } = input.provider;
  const nodePath = realpathSync(process.execPath);
  const nodeDirectory = path.dirname(nodePath);
  const shellPath = realpathSync("/bin/sh");
  if (realpathSync(path.join(nodeDirectory, "node")) !== nodePath) fail();
  const env = {
    OPENCLAW_STATE_DIR: stateDir,
    OPENCLAW_CONFIG_PATH: configPath,
    OPENCLAW_AGENT_DIR: agentDir,
    OPENCLAW_DISABLE_FILE_LOGGING: "1",
    OPENCLAW_NO_RESPAWN: "1",
    PATH: [...new Set([nodeDirectory, path.dirname(shellPath)])].join(
      path.delimiter,
    ),
    SHELL: shellPath,
  };
  const config = {
    gateway: {
      mode: "local",
      bind: "loopback",
      auth: {
        mode: "token",
        token: {
          source: "env",
          provider: "default",
          id: "AGENTGUARD_PRODUCT_GATEWAY_TOKEN",
        },
      },
    },
    agents: {
      defaults: {
        workspace: workspaceDir,
        skipBootstrap: true,
        envelopeTimestamp: "off",
        model: { primary: `${providerId}/${modelId}`, fallbacks: [] },
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
          baseUrl,
          apiKey,
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
        security: "allowlist",
        ask: "off",
        safeBins: [],
        pathPrepend: [nodeDirectory],
        applyPatch: { enabled: false },
      },
      elevated: { enabled: false },
      web: { search: { enabled: false }, fetch: { enabled: false } },
    },
    browser: { enabled: false },
    plugins: {
      enabled: true,
      allow: [PRODUCT_FIXTURE_PLUGIN_ID],
      load: { paths: [ENTRY_PATH] },
      slots: { memory: "none" },
      entries: {
        [PRODUCT_FIXTURE_PLUGIN_ID]: {
          enabled: true,
          hooks: { allowConversationAccess: true },
          config: { runManifestPath: input.runManifestPath },
        },
      },
    },
    channels: { [PRODUCT_FIXTURE_CHANNEL_ID]: { enabled: true } },
  };
  return {
    root,
    stateDir,
    workspaceDir,
    agentDir,
    configPath,
    profilePath,
    agentId,
    sessionId,
    sessionKey,
    scopeSessionId: sessionKey,
    providerId,
    modelId,
    inboxUrl: input.inboxUrl,
    inboxTarget: "fixture-inbox",
    runManifestPath: input.runManifestPath,
    config,
    env,
    nodePath,
    shellPath,
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
function approvalState(profile) {
  const filename = path.join(profile.stateDir, "exec-approvals.json");
  const file = fileState(filename);
  const raw = file.bytes.toString("utf8");
  const parsed = ownObject(
    JSON.parse(raw),
    ["version", "socket", "defaults", "agents"],
    ["version", "defaults", "agents"],
  );
  // The actual public SDK writer emits exactly this form. Duplicate fields or
  // unrecognised encodings cannot hide a second, uncommitted policy.
  if (JSON.stringify(parsed, null, 2) + "\n" !== raw) fail();
  const policy = {
    security: "allowlist",
    ask: "off",
    askFallback: "deny",
    autoAllowSkills: false,
  };
  const defaults = ownObject(parsed.defaults, Object.keys(policy));
  const agent = ownObject(parsed.agents?.main, [
    ...Object.keys(policy),
    "allowlist",
  ]);
  if (
    parsed.version !== 1 ||
    Object.keys(parsed.agents).join("|") !== "main" ||
    canonical(defaults) !== canonical(policy) ||
    Object.keys(policy).some((key) => agent[key] !== policy[key]) ||
    !Array.isArray(agent.allowlist) ||
    agent.allowlist.length !== 1
  )
    fail();
  const entry = ownObject(
    agent.allowlist[0],
    [
      "id",
      "pattern",
      "source",
      "lastUsedAt",
      "lastUsedCommand",
      "lastResolvedPath",
    ],
    ["id", "pattern", "source"],
  );
  if (
    entry.pattern !==
      `=command:${createHash("sha256").update(PRODUCT_MARKER_COMMAND).digest("hex").slice(0, 16)}` ||
    entry.source !== "allow-always"
  )
    fail();
  if (
    typeof entry.id !== "string" ||
    !/^[0-9a-f-]{36}$/u.test(entry.id) ||
    (entry.lastUsedAt !== undefined &&
      (!Number.isSafeInteger(entry.lastUsedAt) || entry.lastUsedAt < 0)) ||
    (entry.lastUsedCommand !== undefined &&
      entry.lastUsedCommand !== PRODUCT_MARKER_COMMAND) ||
    (entry.lastResolvedPath !== undefined &&
      entry.lastResolvedPath !== profile.nodePath)
  )
    fail();
  let socket = null;
  if (parsed.socket !== undefined) {
    socket = ownObject(parsed.socket, ["path", "token"]);
    if (
      socket.path !== path.join(profile.stateDir, "exec-approvals.sock") ||
      typeof socket.token !== "string" ||
      !/^[A-Za-z0-9_=-]{16,256}$/u.test(socket.token)
    )
      fail();
  }
  // Host usage timestamps and its atomic inode replacement are mutable. Only
  // those declared usage fields may change; policy, command and socket stay bound.
  return {
    identity: "owned-private-exec-policy-v1",
    digest: sha(
      canonical({
        version: parsed.version,
        socket,
        defaults,
        agent: {
          ...policy,
          allowlist: [
            { id: entry.id, pattern: entry.pattern, source: entry.source },
          ],
        },
      }),
    ),
  };
}
function capture(profile) {
  const directories = [
    profile.root,
    profile.stateDir,
    profile.workspaceDir,
    path.join(profile.stateDir, "agents"),
    path.join(profile.stateDir, "agents", "main"),
    profile.agentDir,
  ];
  const directoryIds = directories.map(privateDirectory);
  const marker = fileState(path.join(profile.workspaceDir, "marker.mjs"));
  const packagedMarker = fileState(MARKER_PATH, { privateFile: false });
  if (!marker.bytes.equals(packagedMarker.bytes)) fail();
  const config = fileState(profile.configPath);
  if (config.bytes.toString("utf8") !== canonical(profile.config) + "\n")
    fail();
  const source = fileState(profile.profilePath);
  const node = fileState(profile.nodePath, {
    privateFile: false,
    limit: NODE_LIMIT,
  });
  const shell = fileState(profile.shellPath, {
    privateFile: false,
    limit: NODE_LIMIT,
  });
  const approval = approvalState(profile);
  assertCommandOutput(profile);
  if (canonical(directories.map(privateDirectory)) !== canonical(directoryIds))
    fail();
  return {
    directories,
    directoryIds,
    files: [marker, packagedMarker, config, source, node, approval, shell].map(
      ({ identity, digest }) => ({ identity, digest }),
    ),
  };
}
function seal(profile) {
  const state = capture(profile);
  const [marker, , config, source, node, approval, shell] = state.files;
  const result = freeze({
    ...profile,
    assetCommitments: {
      schemaVersion: 1,
      command: PRODUCT_MARKER_COMMAND,
      markerDigest: marker.digest,
      nodePath: profile.nodePath,
      nodeDigest: node.digest,
      shellPath: profile.shellPath,
      shellDigest: shell.digest,
      configDigest: config.digest,
      profileDigest: source.digest,
      execApprovalsDigest: approval.digest,
    },
  });
  PROFILES.set(result, state);
  return result;
}

/** Re-read actual files; caller-provided expected digests cannot issue a profile. */
export function assertProductRuntimeAssets(profile) {
  try {
    const expected = PROFILES.get(profile);
    if (
      !expected ||
      realpathSync(process.execPath) !== profile.nodePath ||
      realpathSync("/bin/sh") !== profile.shellPath ||
      realpathSync(path.join(path.dirname(profile.nodePath), "node")) !==
        profile.nodePath ||
      canonical(capture(profile)) !== canonical(expected)
    )
      fail();
  } catch {
    fail();
  }
}
export function isProductRuntimeProfile(value) {
  return PROFILES.has(value);
}

const APPROVAL_PROGRAM = `
import fs from 'node:fs';
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const sdk=await import(input.sdk);
const policy={security:'allowlist',ask:'off',askFallback:'deny',autoAllowSkills:false};
const file={version:1,defaults:policy,agents:{main:{...policy,allowlist:[]}}};
sdk.saveExecApprovals(file);
sdk.addDurableCommandApproval(file,'main','node marker.mjs');
const actual=sdk.resolveExecApprovals('main');
if(actual.path!==input.path || actual.agent.security!=='allowlist' || actual.agent.ask!=='off' || actual.allowlist.length!==1 ||
  !sdk.hasExactCommandDurableExecApproval({allowlist:actual.allowlist,commandText:'node marker.mjs'}) ||
  sdk.hasExactCommandDurableExecApproval({allowlist:actual.allowlist,commandText:'node other.mjs'})) process.exit(1);
`;

export async function createProductRuntimeProfile(options) {
  try {
    const fields = ownObject(options, [
      "root",
      "inboxUrl",
      "provider",
      "runManifestPath",
    ]);
    const input = inputConfig({
      ...fields,
      schemaVersion: 1,
      sessionId: randomUUID(),
    });
    privateDirectory(input.root);
    const profile = derive(input);
    mkdirSync(profile.stateDir, { mode: 0o700 });
    mkdirSync(profile.workspaceDir, { mode: 0o700 });
    mkdirSync(profile.agentDir, { recursive: true, mode: 0o700 });
    writeFileSync(
      path.join(profile.workspaceDir, "marker.mjs"),
      fileState(MARKER_PATH, { privateFile: false }).bytes,
      { flag: "wx", mode: 0o600 },
    );
    writeFileSync(profile.configPath, canonical(profile.config) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    writeFileSync(profile.profilePath, canonical(input) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    const sdk = pathToFileURL(
      createRequire(import.meta.url).resolve(
        "openclaw/plugin-sdk/infra-runtime",
      ),
    ).href;
    const child = execFile(
      process.execPath,
      ["--input-type=module", "-e", APPROVAL_PROGRAM],
      {
        env: {
          PATH: profile.env.PATH,
          OPENCLAW_STATE_DIR: profile.stateDir,
          OPENCLAW_NO_RESPAWN: "1",
        },
        timeout: 20000,
        maxBuffer: 8192,
      },
    );
    const completion = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code) =>
        code === 0 ? resolve() : reject(new Error()),
      );
    });
    child.stdin.end(
      JSON.stringify({
        sdk,
        path: path.join(profile.stateDir, "exec-approvals.json"),
      }),
    );
    await completion;
    return seal(profile);
  } catch {
    throw new FixtureError("product_profile_unavailable");
  }
}

export function loadProductRuntimeProfileSync(configPath) {
  try {
    absolute(configPath);
    const { parsed } = readPrivateJson(
      path.join(path.dirname(configPath), "product-profile.json"),
    );
    const profile = derive(inputConfig(parsed));
    if (configPath !== profile.configPath) fail();
    return seal(profile);
  } catch {
    throw new FixtureError("product_profile_unavailable");
  }
}
export async function loadProductRuntimeProfile(configPath) {
  return loadProductRuntimeProfileSync(configPath);
}
