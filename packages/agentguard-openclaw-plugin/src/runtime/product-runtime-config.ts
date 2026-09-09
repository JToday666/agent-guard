import {
  clearRuntimeConfigSnapshot,
  getRuntimeConfigSnapshot,
  getRuntimeConfigSourceSnapshot,
  setRuntimeConfigSnapshot,
} from "openclaw/plugin-sdk/runtime-config-snapshot";
import {
  resolveSecretRefValues,
  type SecretRef,
} from "openclaw/plugin-sdk/secret-ref-runtime";
import {
  assertProductRuntimeAssets,
  type FrozenProductProfile,
} from "../../product-runtime/profile.mjs";
import { restrictedDigest } from "./canonical.js";

/** Local-only secret preparation for the public embedded Host entry. */
export async function prepareProductRuntimeConfig(
  profile: FrozenProductProfile,
  signal: AbortSignal,
): Promise<Readonly<{ assertCurrent(): void; close(): void }>> {
  try {
    if (signal.aborted) throw new Error();
    assertProductRuntimeAssets(profile);
    const source = structuredClone(profile.config);
    const runtime = structuredClone(source);
    const provider = runtime.models?.providers?.[profile.providerId];
    const gateway = runtime.gateway?.auth;
    if (!provider || !gateway) throw new Error();
    const providerRefDigest = restrictedDigest(provider.apiKey);
    const gatewayRefDigest = restrictedDigest(gateway.token);
    const resolve = async (value: unknown): Promise<string> => {
      if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error();
      const ref = value as SecretRef;
      if (
        Object.keys(ref).sort().join("|") !== "id|provider|source" ||
        ref.source !== "env" ||
        ref.provider !== "default" ||
        !/^[A-Z][A-Z0-9_]{0,127}$/u.test(ref.id)
      )
        throw new Error();
      const values = await resolveSecretRefValues([ref], {
        config: source,
        env: process.env,
      });
      const result = values.values().next().value;
      if (values.size !== 1 || typeof result !== "string" || !result)
        throw new Error();
      return result;
    };
    provider.apiKey = await resolve(provider.apiKey);
    gateway.token = await resolve(gateway.token);
    assertProductRuntimeAssets(profile);
    const digest = restrictedDigest(runtime);
    // No await may separate this cancellation check from snapshot publication.
    if (signal.aborted) throw new Error();
    setRuntimeConfigSnapshot(runtime, source);
    let closed = false;
    return Object.freeze({
      assertCurrent() {
        try {
          const currentSource = getRuntimeConfigSourceSnapshot();
          if (
            closed ||
            signal.aborted ||
            getRuntimeConfigSnapshot() !== runtime ||
            restrictedDigest(runtime) !== digest ||
            restrictedDigest(
              currentSource?.models?.providers?.[profile.providerId]?.apiKey,
            ) !== providerRefDigest ||
            restrictedDigest(currentSource?.gateway?.auth?.token) !==
              gatewayRefDigest
          )
            throw new Error();
        } catch {
          throw new Error("product_runtime_configuration_changed");
        }
      },
      close() {
        if (closed) return;
        closed = true;
        // Do not clear an unrelated caller's subsequently installed snapshot.
        if (getRuntimeConfigSnapshot() === runtime)
          clearRuntimeConfigSnapshot();
      },
    });
  } catch {
    throw new Error("product_local_credentials_unavailable");
  }
}
