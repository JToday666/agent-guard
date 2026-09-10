#!/usr/bin/env node
/** One explicitly selected historical receipt. Credentials never appear in argv or reports. */
import * as fs from "node:fs";
import { basename, dirname, isAbsolute, join, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";

function args(values) {
  const result = {};
  const allowed = new Set([
    "--package-root",
    "--config",
    "--audit-id",
    "--expected-wire-digest",
    "--report",
  ]);
  for (let i = 0; i < values.length; i += 2) {
    if (
      !allowed.has(values[i]) ||
      Object.hasOwn(result, values[i]) ||
      !values[i + 1]
    )
      throw new Error();
    result[values[i]] = values[i + 1];
  }
  if (
    Object.keys(result).length !== allowed.size ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(result["--audit-id"]) ||
    !/^[a-f0-9]{64}$/u.test(result["--expected-wire-digest"])
  )
    throw new Error();
  return result;
}
function parent(path) {
  if (
    !isAbsolute(path) ||
    path.split(sep).some((part) => part === "." || part === "..")
  )
    throw new Error();
  let fd = fs.openSync("/", fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    for (const part of dirname(path).split(sep).filter(Boolean)) {
      const next = fs.openSync(
        `/proc/self/fd/${fd}/${part}`,
        fs.constants.O_RDONLY |
          fs.constants.O_DIRECTORY |
          fs.constants.O_NOFOLLOW,
      );
      fs.closeSync(fd);
      fd = next;
    }
    const metadata = fs.fstatSync(fd);
    if (metadata.uid !== process.geteuid() || (metadata.mode & 0o777) !== 0o700)
      throw new Error();
    return fd;
  } catch {
    fs.closeSync(fd);
    throw new Error();
  }
}
function readConfig(path) {
  const directory = parent(path);
  let fd;
  try {
    fd = fs.openSync(
      `/proc/self/fd/${directory}/${basename(path)}`,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
    const stat = fs.fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o600 ||
      stat.size > 64 * 1024
    )
      throw new Error();
    const bytes = fs.readFileSync(fd);
    const input = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    rejectDuplicateKeys(bytes.toString("utf8"));
    const after = fs.fstatSync(fd);
    const current = fs.lstatSync(
      `/proc/self/fd/${directory}/${basename(path)}`,
    );
    if (
      [after, current].some((value) =>
        [
          "dev",
          "ino",
          "size",
          "mtimeMs",
          "ctimeMs",
          "uid",
          "mode",
          "nlink",
        ].some((key) => value[key] !== stat[key]),
      ) ||
      !fs.readFileSync(`/proc/self/fd/${fd}`).equals(bytes)
    )
      throw new Error();
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.hasOwn(input, "adapterToken") ||
      typeof input.adapterTokenEnv !== "string" ||
      !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(input.adapterTokenEnv)
    )
      throw new Error();
    const { adapterTokenEnv, ...config } = input;
    const adapterToken = process.env[adapterTokenEnv];
    if (!adapterToken) throw new Error();
    return { ...config, adapterToken };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.closeSync(directory);
  }
}
function rejectDuplicateKeys(text) {
  // JSON.parse has already checked grammar. Walk its tokens to reject duplicate decoded names.
  let cursor = 0;
  const spaces = () => {
    while (/\s/u.test(text[cursor] ?? "") && cursor < text.length) cursor++;
  };
  const string = () => {
    const start = cursor++;
    while (cursor < text.length) {
      const character = text[cursor++];
      if (character === "\\") cursor++;
      else if (character === '"') return JSON.parse(text.slice(start, cursor));
    }
    throw new Error();
  };
  const value = (depth = 0) => {
    if (depth > 32) throw new Error();
    spaces();
    if (text[cursor] === '"') {
      string();
      return;
    }
    if (text[cursor] === "{") {
      cursor++;
      spaces();
      const names = new Set();
      if (text[cursor] === "}") {
        cursor++;
        return;
      }
      while (true) {
        spaces();
        const key = string();
        if (names.has(key)) throw new Error();
        names.add(key);
        spaces();
        cursor++;
        value(depth + 1);
        spaces();
        if (text[cursor++] === "}") return;
      }
    }
    if (text[cursor] === "[") {
      cursor++;
      spaces();
      if (text[cursor] === "]") {
        cursor++;
        return;
      }
      while (true) {
        value(depth + 1);
        spaces();
        if (text[cursor++] === "]") return;
      }
    }
    while (cursor < text.length && !/[\s,}\]]/u.test(text[cursor])) cursor++;
  };
  value();
  spaces();
  if (cursor !== text.length) throw new Error();
}

const DETERMINISTIC = new Set([
  "receipt_reconciliation_invalid",
  "receipt_reconciliation_not_eligible",
  "receipt_reconciliation_limit",
  "receipt_reconciliation_worker_required",
  "receipt_transport_binding_missing",
  "receipt_transport_binding_mismatch",
]);
function exitCode(delivery, close) {
  if (close.status !== "closed") return 2;
  if (delivery.status === "recorded") return 0;
  return delivery.status === "permanent_rejected" ||
    DETERMINISTIC.has(delivery.errorCode)
    ? 1
    : 2;
}
function writeReport(path, report) {
  const directory = parent(path);
  const temporary = `.reconcile-${randomBytes(16).toString("hex")}.tmp`;
  const at = (name) => `/proc/self/fd/${directory}/${name}`;
  let fd;
  try {
    try {
      fs.lstatSync(at(basename(path)));
      throw new Error("report_exists");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    fd = fs.openSync(
      at(temporary),
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.writeFileSync(fd, `${JSON.stringify(report, null, 2)}\n`);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    // Atomic no-replace publication: a concurrent report writer must win or fail,
    // never overwrite the other's evidence after the earlier lstat check.
    fs.linkSync(at(temporary), at(basename(path)));
    fs.unlinkSync(at(temporary));
    fs.fsyncSync(directory);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try {
      fs.unlinkSync(at(temporary));
    } catch {
      /* Atomic report already installed or preparation failed. */
    }
    fs.closeSync(directory);
  }
}

let recovery;
let options;
let report = {
  schema_version: "1.0",
  scope: "single_receipt",
  product_active_enabled: false,
  external_provider_requests: 0,
  selected_confirmed: false,
  exit_code: 2,
};
try {
  options = args(process.argv.slice(2));
  if (!isAbsolute(options["--package-root"])) throw new Error();
  const config = readConfig(options["--config"]);
  const { openOpenClawProductReceiptRecovery } = await import(
    pathToFileURL(
      join(options["--package-root"], "product-runtime/receipt-recovery.mjs"),
    ).href
  );
  recovery = await openOpenClawProductReceiptRecovery(config);
  const selection = {
    auditId: options["--audit-id"],
    expectedWireDigest: options["--expected-wire-digest"],
  };
  const delivery = await recovery.reconcileRejectedReceipt(selection);
  const snapshot = recovery.status();
  const close = await recovery.closeWithin(1_000);
  report = {
    ...report,
    selection,
    delivery,
    snapshot,
    close,
    selected_confirmed: delivery.status === "recorded",
    exit_code: exitCode(delivery, close),
  };
} catch (error) {
  report = {
    ...report,
    error_code: "receipt_reconciliation_unavailable",
    exit_code: DETERMINISTIC.has(error?.code) ? 1 : 2,
  };
} finally {
  if (options) {
    try {
      writeReport(options["--report"], report);
    } catch {
      report = {
        ...report,
        exit_code: 2,
        error_code: "receipt_reconciliation_report_failed",
      };
    }
  }
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = report.exit_code;
  if (recovery) {
    // Do not release the process/owner while close explicitly reports pending.
    const alive = setInterval(() => undefined, 1_000);
    try {
      await recovery.close();
    } finally {
      clearInterval(alive);
    }
  }
}
