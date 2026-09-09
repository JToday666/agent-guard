import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import type { FrozenProductProfile } from "../../product-runtime/profile.mjs";
import { restrictedDigest } from "./canonical.js";
import {
  productBytesDigest,
  readProductFile,
} from "./product-protected-file.js";

// This is deliberately a pinned Host internal dependency, not a public SDK
// compatibility claim. The actual agent loop uses this same startup function.
const HOST_VERSION = "2026.7.1-2";
const ENTRY = "dist/runtime-plugins-ICju_gEw.js";
const FILES = Object.freeze({
  "package.json":
    "sha256:695b6ee36df7fc69606dc390cf97bb2ca809114337b18c573707637cd2a4e3db",
  [ENTRY]:
    "sha256:0d9fb15e82a04c1d6eed76f4b9b75d01a55aaf5dc03a8640f4b1f6594c51230b",
  "dist/standalone-runtime-registry-loader-DHlUPKIt.js":
    "sha256:a46a6acf013b5d92949d09484e4930545d655619e5cb3800de3622b98a2bb515",
});
type Startup = (params: {
  config: FrozenProductProfile["config"];
  workspaceDir: string;
}) => void;
type Binding = { root: string; identity: string; startup: Startup };
let binding: Binding | undefined;
let loading: Promise<Binding> | undefined;

function fail(): never {
  throw new Error("product_host_loader_invalid");
}
function material(): { root: string; identity: string } {
  try {
    // Resolve from the installed adapter, never a caller-supplied Host path.
    const sdk = realpathSync(
      createRequire(import.meta.url).resolve(
        "openclaw/plugin-sdk/agent-harness",
      ),
    );
    const root = dirname(dirname(dirname(sdk)));
    if (sdk !== join(root, "dist/plugin-sdk/agent-harness.js")) fail();
    const fingerprints: [string, string][] = [];
    for (const [relative, digest] of Object.entries(FILES)) {
      const path = join(root, relative);
      if (realpathSync(path) !== path) fail();
      const actual = readProductFile(path, 1024 * 1024, false);
      if (productBytesDigest(actual.bytes) !== digest) fail();
      if (relative === "package.json") {
        const metadata = JSON.parse(actual.bytes.toString("utf8"));
        if (metadata.name !== "openclaw" || metadata.version !== HOST_VERSION)
          fail();
      }
      fingerprints.push([relative, actual.fingerprint]);
    }
    return { root, identity: restrictedDigest(fingerprints) };
  } catch {
    return fail();
  }
}

/** Recheck the precise installed Host startup code at every Product boundary. */
export function assertPinnedOpenClawHostLoader(): void {
  const current = material();
  if (
    !binding ||
    current.root !== binding.root ||
    current.identity !== binding.identity
  )
    fail();
}

/** Load the same complete registry as the real pinned agent loop, before ACK. */
export async function loadPinnedOpenClawHostRegistry(
  profile: FrozenProductProfile,
): Promise<void> {
  try {
    loading ??= (async () => {
      const before = material();
      const module: Record<string, unknown> = await import(
        pathToFileURL(join(before.root, ENTRY)).href
      );
      const after = material();
      if (
        before.root !== after.root ||
        before.identity !== after.identity ||
        Object.keys(module).join("|") !== "t" ||
        typeof module.t !== "function"
      )
        fail();
      return { ...after, startup: module.t as Startup };
    })();
    binding = await loading;
    assertPinnedOpenClawHostLoader();
    binding.startup({
      config: profile.config,
      workspaceDir: profile.workspaceDir,
    });
    assertPinnedOpenClawHostLoader();
  } catch {
    fail();
  }
}
