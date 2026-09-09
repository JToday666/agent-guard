import {
  constants,
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, normalize } from "node:path";
import { restrictedCanonicalJson } from "./canonical.js";

export function productCompositionError(
  code = "product_composition_invalid",
): never {
  throw new Error(code);
}
export function productAbsolutePath(value: unknown): string {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    normalize(value) !== value
  )
    productCompositionError();
  return value;
}
export function productBytesDigest(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
/** Open a bounded regular file without following the final component or blocking on FIFOs. */
export function readProductFile(
  path: string,
  maximum: number,
  privateFile = true,
): { bytes: Buffer; fingerprint: string; mode: number } {
  productAbsolutePath(path);
  let fd: number | undefined;
  try {
    if (privateFile) {
      const parent = lstatSync(dirname(path));
      if (
        !parent.isDirectory() ||
        parent.isSymbolicLink() ||
        realpathSync(dirname(path)) !== dirname(path) ||
        (parent.mode & 0o777) !== 0o700 ||
        (process.getuid && parent.uid !== process.getuid())
      )
        productCompositionError();
    }
    fd = openSync(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = fstatSync(fd, { bigint: true });
    if (
      !before.isFile() ||
      before.size < 1n ||
      before.size > BigInt(maximum) ||
      (privateFile &&
        (before.nlink !== 1n ||
          (before.mode & 0o777n) !== 0o600n ||
          (process.getuid && before.uid !== BigInt(process.getuid()))))
    )
      productCompositionError();
    // Read at most the admitted size plus one sentinel byte even if a writer
    // grows the file after fstat. The identity check below still rejects races.
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = readSync(fd, buffer, used, buffer.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used !== Number(before.size)) productCompositionError();
    const bytes = buffer.subarray(0, used);
    const after = fstatSync(fd, { bigint: true });
    const named = lstatSync(path, { bigint: true });
    const identity = (s: typeof before) =>
      [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].join(
        ":",
      );
    if (
      named.isSymbolicLink() ||
      identity(before) !== identity(after) ||
      identity(after) !== identity(named) ||
      BigInt(bytes.length) !== before.size
    )
      productCompositionError();
    return {
      bytes,
      fingerprint: `${identity(after)}:${productBytesDigest(bytes)}`,
      mode: Number(after.mode & 0o777n),
    };
  } catch {
    return productCompositionError("product_protected_file_invalid");
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
export function readProductCanonicalFile(path: string): {
  data: Record<string, unknown>;
  fingerprint: string;
} {
  try {
    const { bytes, fingerprint } = readProductFile(path, 128 * 1024);
    const raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const data = JSON.parse(raw);
    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data) ||
      (restrictedCanonicalJson(data) !== raw &&
        `${restrictedCanonicalJson(data)}\n` !== raw)
    )
      productCompositionError();
    return { data, fingerprint };
  } catch {
    productCompositionError("product_run_manifest_invalid");
  }
}
