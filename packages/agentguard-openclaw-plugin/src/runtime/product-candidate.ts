import { gunzipSync } from "node:zlib";
import { readdirSync, lstatSync, realpathSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { restrictedDigest } from "./canonical.js";
import {
  productAbsolutePath,
  productBytesDigest,
  productCompositionError,
  readProductFile,
} from "./product-protected-file.js";

const OWN_ROOT = realpathSync(
  fileURLToPath(new URL("../../", import.meta.url)),
);
const NAME = "@agentguard-ai/openclaw-plugin";
const VERSION = "0.1.0-rc.1";
const MAX_ARCHIVE = 32 * 1024 * 1024;
const MAX_TREE = 128 * 1024 * 1024;
const CONSTRUCTION_KEY = Symbol("installed-product-candidate");
type Material = {
  artifactDigest: string;
  installedTreeDigest: string;
  archiveFingerprint: string;
  treeFingerprint: string;
  hostVersion: string;
};
function fail(): never {
  return productCompositionError("product_candidate_invalid");
}
function archiveFiles(archive: Buffer): Map<string, Buffer> {
  const tar = gunzipSync(archive, { maxOutputLength: MAX_TREE });
  if (tar.length % 512 !== 0) fail();
  const files = new Map<string, Buffer>();
  const paths = new Set<string>();
  let offset = 0,
    ended = false;
  const text = (b: Buffer) => {
    const nul = b.indexOf(0);
    if (nul >= 0 && b.subarray(nul).some((v) => v !== 0)) fail();
    return new TextDecoder("utf-8", { fatal: true }).decode(
      nul < 0 ? b : b.subarray(0, nul),
    );
  };
  const octal = (b: Buffer) => {
    const s = b.toString("ascii").replace(/\0.*$/u, "").trim();
    if (!/^[0-7]+$/u.test(s)) fail();
    const n = Number.parseInt(s, 8);
    if (!Number.isSafeInteger(n) || n < 0) fail();
    return n;
  };
  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512);
    offset += 512;
    if (h.every((v) => v === 0)) {
      if (
        offset + 512 > tar.length ||
        tar.subarray(offset).some((v) => v !== 0)
      )
        fail();
      ended = true;
      break;
    }
    if (
      paths.size >= 8192 ||
      h.subarray(257, 262).toString("ascii") !== "ustar"
    )
      fail();
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : h[i]!;
    if (octal(h.subarray(148, 156)) !== checksum) fail();
    const name = text(h.subarray(0, 100)),
      prefix = text(h.subarray(345, 500));
    const entry = prefix ? `${prefix}/${name}` : name;
    const type = h[156];
    const directory = type === 53;
    const normalized =
      directory && entry.endsWith("/") ? entry.slice(0, -1) : entry;
    if (
      !normalized.startsWith("package/") ||
      normalized.includes("\\") ||
      normalized.includes("\0") ||
      normalized.split("/").some((p) => p === "" || p === "." || p === "..") ||
      paths.has(normalized) ||
      ![0, 48, 53].includes(type!)
    )
      fail();
    paths.add(normalized);
    const size = octal(h.subarray(124, 136));
    if (
      size > 8 * 1024 * 1024 ||
      offset + size > tar.length ||
      (directory && size !== 0) ||
      text(h.subarray(157, 257))
    )
      fail();
    if (!directory)
      files.set(
        normalized.slice(8),
        Buffer.from(tar.subarray(offset, offset + size)),
      );
    const padded = Math.ceil(size / 512) * 512;
    if (tar.subarray(offset + size, offset + padded).some((v) => v !== 0))
      fail();
    offset += padded;
  }
  if (!ended || !files.size) fail();
  return files;
}
function hostVersion(): string {
  let cursor = dirname(
    realpathSync(
      createRequire(import.meta.url).resolve(
        "openclaw/plugin-sdk/agent-harness",
      ),
    ),
  );
  for (;;) {
    try {
      const p = JSON.parse(
        readProductFile(
          join(cursor, "package.json"),
          1024 * 1024,
          false,
        ).bytes.toString("utf8"),
      );
      if (p.name === "openclaw") {
        if (p.version !== "2026.7.1-2") fail();
        return p.version;
      }
    } catch {
      /* Resolve the actual SDK package, never an expected version string. */
    }
    const parent = dirname(cursor);
    if (parent === cursor) fail();
    cursor = parent;
  }
}
function material(candidateTgzPath: string): Material {
  try {
    const archive = readProductFile(candidateTgzPath, MAX_ARCHIVE);
    const files = archiveFiles(archive.bytes);
    const metadata = JSON.parse(
      files.get("package.json")?.toString("utf8") ?? "null",
    );
    if (
      metadata?.name !== NAME ||
      metadata.version !== VERSION ||
      !files.has("dist/runtime/product-composition.js") ||
      !files.has("product-runtime/product/index.mjs") ||
      !files.has("product-runtime/product/openclaw.plugin.json") ||
      !files.has("dist/index.js")
    )
      fail();
    for (const name of [
      "product-runtime/product/package.json",
      "product-runtime/product/openclaw.plugin.json",
    ])
      if (
        JSON.parse(files.get(name)?.toString("utf8") ?? "null")?.version !==
        VERSION
      )
        fail();
    const actualNames: string[] = [];
    let visited = 0;
    function walk(dir: string, depth = 0) {
      if (depth > 32) fail();
      const stat = lstatSync(dir);
      if (
        !stat.isDirectory() ||
        stat.isSymbolicLink() ||
        (stat.mode & 0o022) !== 0
      )
        fail();
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (dir === OWN_ROOT && entry.name === "node_modules") continue;
        const path = join(dir, entry.name),
          rel = relative(OWN_ROOT, path).split(sep).join("/");
        if (++visited > 8192 || entry.isSymbolicLink()) fail();
        if (entry.isDirectory()) {
          if (![...files.keys()].some((n) => n.startsWith(`${rel}/`))) fail();
          walk(path, depth + 1);
        } else if (entry.isFile()) actualNames.push(rel);
        else fail();
      }
    }
    walk(OWN_ROOT);
    if (
      actualNames.length !== files.size ||
      actualNames.some((n) => !files.has(n))
    )
      fail();
    const rows: [string, string][] = [],
      states: [string, string][] = [];
    for (const name of [...files.keys()].sort()) {
      const installedPath = join(OWN_ROOT, name);
      const installedStat = lstatSync(installedPath);
      if (
        realpathSync(installedPath) !== installedPath ||
        !installedStat.isFile() ||
        (installedStat.mode & 0o022) !== 0
      )
        fail();
      const current = readProductFile(installedPath, 8 * 1024 * 1024, false);
      if (
        (current.mode & 0o022) !== 0 ||
        !current.bytes.equals(files.get(name)!)
      )
        fail();
      rows.push([name, productBytesDigest(current.bytes)]);
      states.push([name, current.fingerprint]);
    }
    return {
      artifactDigest: productBytesDigest(archive.bytes),
      installedTreeDigest: restrictedDigest(rows),
      archiveFingerprint: archive.fingerprint,
      treeFingerprint: restrictedDigest(states),
      hostVersion: hostVersion(),
    };
  } catch {
    fail();
  }
}
/** Immutable evidence of actual archive and installed bytes; no version or root override. */
export class VerifiedInstalledOpenClawCandidate {
  readonly packageVersion = VERSION;
  readonly artifactDigest: string;
  readonly installedTreeDigest: string;
  readonly runtimeVersion: string;
  #path: string;
  #material: Material;
  constructor(key: symbol, path: string, value: Material) {
    if (key !== CONSTRUCTION_KEY) fail();
    this.#path = path;
    this.#material = value;
    this.artifactDigest = value.artifactDigest;
    this.installedTreeDigest = value.installedTreeDigest;
    this.runtimeVersion = value.hostVersion;
    Object.freeze(this);
  }
  assertCurrent(): void {
    if (
      restrictedDigest(material(this.#path)) !==
      restrictedDigest(this.#material)
    )
      fail();
  }
}
export async function verifyInstalledOpenClawCandidate(
  candidateTgzPath: string,
): Promise<VerifiedInstalledOpenClawCandidate> {
  const path = productAbsolutePath(candidateTgzPath);
  return new VerifiedInstalledOpenClawCandidate(
    CONSTRUCTION_KEY,
    path,
    material(path),
  );
}
