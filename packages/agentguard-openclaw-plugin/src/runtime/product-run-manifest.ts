import type { SecretRef } from "openclaw/plugin-sdk/secret-ref-runtime";
import {
  productAbsolutePath,
  productCompositionError,
  readProductCanonicalFile,
} from "./product-protected-file.js";

export type ProductRunManifest = Readonly<{
  schemaVersion: 1;
  activationManifestPath: string;
  candidateTgzPath: string;
  profileConfigPath: string;
  guardApiBaseUrl: string;
  adapterTokenRef: SecretRef;
  taskId: string;
  scopeDigest: string;
  taskText: string;
  traceId: string;
  productReceiptDirectory: string;
  productReceiptKeyPath: string;
}>;
const KEYS = [
  "schemaVersion",
  "activationManifestPath",
  "candidateTgzPath",
  "profileConfigPath",
  "guardApiBaseUrl",
  "adapterTokenRef",
  "taskId",
  "scopeDigest",
  "taskText",
  "traceId",
  "productReceiptDirectory",
  "productReceiptKeyPath",
];
export function readProductRunManifest(path: string): {
  data: ProductRunManifest;
  assertCurrent(): void;
} {
  try {
    const initial = readProductCanonicalFile(path),
      d = initial.data;
    if (
      Object.keys(d).length !== KEYS.length ||
      KEYS.some((k) => !Object.hasOwn(d, k)) ||
      d.schemaVersion !== 1
    )
      productCompositionError();
    for (const k of [
      "activationManifestPath",
      "candidateTgzPath",
      "profileConfigPath",
      "productReceiptDirectory",
      "productReceiptKeyPath",
    ])
      productAbsolutePath(d[k]);
    for (const k of ["taskId", "traceId"])
      if (
        typeof d[k] !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(d[k])
      )
        productCompositionError();
    if (
      typeof d.scopeDigest !== "string" ||
      !/^(?:hmac-sha256|sha256):[0-9a-f]{64}$/u.test(d.scopeDigest) ||
      typeof d.taskText !== "string" ||
      !d.taskText.trim() ||
      Buffer.byteLength(d.taskText) > 64 * 1024
    )
      productCompositionError();
    const ref = d.adapterTokenRef as Record<string, unknown>;
    if (
      !ref ||
      typeof ref !== "object" ||
      Array.isArray(ref) ||
      Object.keys(ref).sort().join(",") !== "id,provider,source" ||
      ref.source !== "env" ||
      ref.provider !== "default" ||
      typeof ref.id !== "string" ||
      !/^[A-Z][A-Z0-9_]{0,127}$/u.test(ref.id)
    )
      productCompositionError();
    if (typeof d.guardApiBaseUrl !== "string") productCompositionError();
    const url = new URL(d.guardApiBaseUrl);
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      !["http:", "https:"].includes(url.protocol)
    )
      productCompositionError();
    Object.freeze(ref);
    Object.freeze(d);
    return Object.freeze({
      data: d as ProductRunManifest,
      assertCurrent() {
        if (readProductCanonicalFile(path).fingerprint !== initial.fingerprint)
          productCompositionError("product_run_manifest_changed");
      },
    });
  } catch {
    productCompositionError("product_run_manifest_invalid");
  }
}
