/** Real public Product composition with synthetic test-only RC admission. */
import { appendFileSync } from "node:fs";
import { createRequire } from "node:module";
import {
  access,
  chmod,
  mkdir,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  createSyntheticProductPackage,
  packSyntheticProductPackage,
} from "./openclaw-product-transport-package.mjs";

const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
};
const privateJson = (file, data) =>
  writeFile(file, canonical(data) + "\n", { mode: 0o600, flag: "wx" });
const importPackage = (root, file) =>
  import(pathToFileURL(path.join(root, file)).href);
let stage = "input";
let outputLimitExceeded = false;

async function prepare(input) {
  const root = await realpath(input.root);
  if (root !== input.root) throw new Error("composition_test_root_invalid");
  stage = "candidate";
  const candidate = await createSyntheticProductPackage({
    directory: path.join(root, "synthetic-sdk"),
  });
  const archive = await packSyntheticProductPackage({
    packageRoot: candidate.packageRoot,
    directory: path.join(root, "candidate"),
  });
  await chmod(archive.candidateTgzPath, 0o600);
  const profileRoot = path.join(root, "runtime");
  await mkdir(profileRoot, { mode: 0o700 });
  const runManifestPath = path.join(root, "run-manifest.json");
  const { createProductRuntimeProfile } = await importPackage(
    candidate.packageRoot,
    "product-runtime/profile.mjs",
  );
  stage = "profile";
  const profile = await createProductRuntimeProfile({
    root: profileRoot,
    inboxUrl: input.inboxUrl,
    runManifestPath,
    provider: {
      id: "agentguard-acceptance",
      modelId: input.modelId,
      baseUrl: input.modelBaseUrl,
      apiKey: {
        source: "env",
        provider: "default",
        id: "AGENTGUARD_TEST_MODEL_TOKEN",
      },
    },
  });
  await writeFile(
    path.join(profile.workspaceDir, "fixture.txt"),
    "composition-safe\n",
    { mode: 0o600, flag: "wx" },
  );
  stage = "inspect";
  const { inspectOpenClawProductRuntime } = await importPackage(
    candidate.packageRoot,
    "dist/runtime/product-composition.js",
  );
  const inspected = await inspectOpenClawProductRuntime({
    profileConfigPath: profile.configPath,
    candidateTgzPath: archive.candidateTgzPath,
  });
  const prepared = {
    packageRoot: candidate.packageRoot,
    candidateTgzPath: archive.candidateTgzPath,
    runManifestPath,
    profile: {
      root: profile.root,
      stateDir: profile.stateDir,
      configPath: profile.configPath,
      workspaceDir: profile.workspaceDir,
      agentId: profile.agentId,
      sessionId: profile.sessionId,
      sessionKey: profile.sessionKey,
    },
    inspected,
    syntheticMetadata: true,
    candidateAdmissionEvidence: false,
    externalProviderRequests: 0,
  };
  await privateJson(path.join(root, "composition-prepared.json"), prepared);
  return prepared;
}

async function run(input) {
  const prepared = JSON.parse(
    await readFile(path.join(input.root, "composition-prepared.json"), "utf8"),
  );
  process.env.AGENTGUARD_TEST_MODEL_TOKEN = "synthetic-local-model-token";
  process.env.AGENTGUARD_TEST_ADAPTER_TOKEN = input.token;
  process.env.AGENTGUARD_PRODUCT_GATEWAY_TOKEN =
    "synthetic-local-gateway-token";
  await privateJson(prepared.runManifestPath, {
    schemaVersion: 1,
    activationManifestPath: input.manifestPath,
    candidateTgzPath: prepared.candidateTgzPath,
    profileConfigPath: prepared.profile.configPath,
    guardApiBaseUrl: input.baseUrl,
    adapterTokenRef: {
      source: "env",
      provider: "default",
      id: "AGENTGUARD_TEST_ADAPTER_TOKEN",
    },
    taskId: input.taskId,
    scopeDigest: input.scopeDigest,
    taskText: input.taskText,
    traceId: input.traceId,
    productReceiptDirectory: path.join(input.root, "receipts"),
    productReceiptKeyPath: path.join(input.root, "receipt-key"),
  });
  stage = "create";
  const { createOpenClawProductRuntime, inspectOpenClawProductRuntime } =
    await importPackage(
      prepared.packageRoot,
      "dist/runtime/product-composition.js",
    );
  let runtime;
  const snapshots = [];
  let runOutcomes;
  let activeInspectionOutcomes;
  try {
    runtime = await createOpenClawProductRuntime({
      runManifestPath: prepared.runManifestPath,
    });
    snapshots.push(runtime.snapshot());
    stage = "start";
    if (input.closeDuringStart) {
      const starting = runtime.start().then(
        () => "fulfilled",
        () => "rejected",
      );
      const deadline = Date.now() + 15000;
      while (true) {
        try {
          await access(path.join(input.root, "composition-ack-held"));
          break;
        } catch {
          if (Date.now() >= deadline) throw new Error("heartbeat_hold_missing");
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      }
      const closing = runtime.close();
      await privateJson(path.join(input.root, "composition-ack-release"), {
        released: true,
      });
      await closing;
      runOutcomes = [await starting];
      snapshots.push(runtime.snapshot());
      return {
        snapshots,
        runOutcomes,
        syntheticMetadata: true,
        candidateAdmissionEvidence: false,
        externalProviderRequests: 0,
      };
    }
    await runtime.start();
    const ready = runtime.snapshot();
    snapshots.push(ready);
    await privateJson(path.join(input.root, "composition-ready.json"), ready);
    activeInspectionOutcomes = [];
    for (const attempt of [
      () =>
        inspectOpenClawProductRuntime({
          profileConfigPath: prepared.profile.configPath,
          candidateTgzPath: prepared.candidateTgzPath,
        }),
      () =>
        createOpenClawProductRuntime({
          runManifestPath: prepared.runManifestPath,
        }),
    ]) {
      activeInspectionOutcomes.push(
        await attempt().then(
          () => "fulfilled",
          () => "rejected",
        ),
      );
    }
    if (!runtime.snapshot().ready)
      throw new Error("active_inspection_retired_owner");
    stage = "run";
    if (input.concurrentRun) {
      runOutcomes = (
        await Promise.allSettled([runtime.run(), runtime.run()])
      ).map((result) => result.status);
    } else if (input.captureRunOutcome) {
      try {
        await runtime.run();
        runOutcomes = ["fulfilled"];
      } catch (error) {
        if (error?.message !== "product_run_withheld") throw error;
        runOutcomes = ["rejected"];
      }
    } else {
      await runtime.run();
    }
    snapshots.push(runtime.snapshot());
  } finally {
    if (runtime) {
      await runtime.close();
      snapshots.push(runtime.snapshot());
    }
  }
  return {
    snapshots,
    runOutcomes,
    activeInspectionOutcomes,
    syntheticMetadata: true,
    candidateAdmissionEvidence: false,
    externalProviderRequests: 0,
  };
}

let input;
try {
  let raw = "";
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw) > 512 * 1024) throw new Error("input_limit");
  }
  input = JSON.parse(raw);
  if (!path.isAbsolute(input.root)) throw new Error("root_invalid");
  const writer = process.stdout.write.bind(process.stdout);
  let size = 0;
  // Native SDK logs are private; the protocol writer is retained separately.
  process.stdout.write = (chunk, encoding, callback) => {
    const bytes =
      typeof chunk === "string"
        ? Buffer.from(chunk, typeof encoding === "string" ? encoding : "utf8")
        : Buffer.from(chunk);
    const kept = bytes.subarray(0, Math.max(0, 1024 * 1024 - size));
    if (kept.length !== bytes.length) outputLimitExceeded = true;
    if (kept.length) {
      appendFileSync(path.join(input.root, "composition-host.log"), kept, {
        mode: 0o600,
      });
      size += kept.length;
    }
    const done = typeof encoding === "function" ? encoding : callback;
    if (typeof done === "function") queueMicrotask(done);
    return true;
  };
  const result =
    input.phase === "prepare"
      ? await prepare(input)
      : input.phase === "run"
        ? await run(input)
        : undefined;
  if (!result) throw new Error("phase_invalid");
  writer(JSON.stringify({ ...result, outputLimitExceeded }));
} catch (error) {
  if (input?.root && path.isAbsolute(input.root)) {
    try {
      await writeFile(
        path.join(input.root, "composition-private-error.log"),
        String(error?.stack ?? "failed"),
        { mode: 0o600 },
      );
      const requirePackage = createRequire(
        path.join(input.root, "synthetic-sdk", "package.json"),
      );
      const { getGlobalPluginRegistry } = await import(
        pathToFileURL(
          requirePackage.resolve("openclaw/plugin-sdk/plugin-runtime"),
        ).href
      );
      const registry = getGlobalPluginRegistry();
      if (registry) {
        const safe = {};
        for (const key of [
          "plugins",
          "providers",
          "typedHooks",
          "hooks",
          "tools",
          "channels",
          "agentToolResultMiddlewares",
          "runtimeLifecycles",
        ]) {
          safe[key] = registry[key]?.map((row) => ({
            keys: Object.keys(row).sort(),
            id: row.id,
            pluginId: row.pluginId,
            source: row.source,
            rootDir: row.rootDir,
            status: row.status,
            runtimes: row.runtimes,
            hookName: row.hookName,
            priority: row.priority,
            handlerType: typeof row.handler,
            rawHandlerType: typeof row.rawHandler,
          }));
        }
        await writeFile(
          path.join(input.root, "composition-registry.json"),
          JSON.stringify(safe),
          { mode: 0o600 },
        );
      }
    } catch {
      /* private diagnostics are best effort */
    }
  }
  process.stderr.write(`product_composition_probe_failed:${stage}\n`);
  process.exitCode = 1;
}
