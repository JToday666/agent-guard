// 跨平台工具命令解析：Windows 下 .cmd shim 无法被无 shell 的 spawnSync
// 直接执行，这里解析 shim 指向的 JS 入口并改用 node 直接执行。
// 禁止 shell:true。

import { spawnSync as nodeSpawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// 兼容 npm 风格 `%dp0%\...` 与 pnpm store shim 的 `%~dp0\...` 变体
// （含 `%~dp0%\...` 写法）；引号变体由捕获组的 [^"'\s] 边界天然支持。
const JS_SHIM_ENTRY_PATTERN = /%~?dp0%?\\([^"'\s]+?\.(?:mjs|cjs|js))/gi;

// 原生可执行文件（Windows/POSIX 均可直接 spawn）。
const NATIVE_TOOLS = new Set(["uv", "node"]);

/**
 * 从 Windows .cmd shim 文本中提取 JS 入口相对路径（相对 shim 所在目录，
 * 即 shim 内的 %dp0% / %~dp0）。取最后一个匹配，因为真正的启动行在 shim 末尾。
 * 相对路径可包含 `..\`（如 pnpm store shim），由调用方 path.resolve 归一化。
 */
export function parseWindowsShimEntry(shimText) {
  let last = null;
  for (const match of String(shimText).matchAll(JS_SHIM_ENTRY_PATTERN)) {
    last = match[1];
  }
  return last;
}

/**
 * 在给定 env 的 PATH 中查找文件，返回绝对路径或 null。
 */
export function findOnPath(fileName, { env = process.env, platform = process.platform, fileExists = fs.existsSync } = {}) {
  const rawPath = env.PATH ?? env.Path ?? "";
  const delimiter = platform === "win32" ? ";" : path.delimiter;
  for (const dir of rawPath.split(delimiter)) {
    const trimmed = dir.trim().replace(/^"|"$/g, "");
    if (!trimmed) {
      continue;
    }
    const candidate = path.join(trimmed, fileName);
    if (fileExists(candidate)) {
      return candidate;
    }
  }
  return null;
}

/**
 * 解析工具命令为可直接 spawn 的 command + 前置参数。
 *
 * - uv / node：原生可执行，直接执行；
 * - Windows 上的 pnpm / openclaw 等 JS 工具：定位 .cmd shim，解析其
 *   JS 入口，返回 `{ command: node, prependArgs: [entryJs], kind: "node-shim" }`；
 * - POSIX：返回解析出的可执行文件路径。
 *
 * 可注入依赖（用于测试）：platform、env、execPath、readFile、fileExists。
 */
export function resolveToolCommand(name, options = {}) {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const fileExists = options.fileExists ?? fs.existsSync;
  const lookup = { env, platform, fileExists };

  if (NATIVE_TOOLS.has(name)) {
    const extension = platform === "win32" ? ".exe" : "";
    const found =
      findOnPath(`${name}${extension}`, lookup) ?? findOnPath(name, lookup);
    return {
      command: found ?? name,
      prependArgs: [],
      kind: "native",
    };
  }

  if (platform === "win32") {
    const shimPath = findOnPath(`${name}.cmd`, lookup);
    if (!shimPath) {
      throw new Error(
        `无法在 PATH 中找到 ${name}.cmd；请确认 ${name} 已全局安装。`,
      );
    }
    const readFile = options.readFile ?? fs.readFileSync;
    const shimText = readFile(shimPath, "utf8");
    // shim 内的相对路径使用 Windows 分隔符；测试会注入 platform: "win32"
    // 在 POSIX 主机上运行，此时 path.resolve 不识别反斜杠，须先归一化为 /。
    const relativeEntry = parseWindowsShimEntry(shimText)?.split("\\").join("/");
    if (!relativeEntry) {
      throw new Error(
        `无法从 Windows shim ${shimPath} 中解析出 JS 入口路径。`,
      );
    }
    const entryJs = path.resolve(path.dirname(shimPath), relativeEntry);
    if (!fileExists(entryJs)) {
      throw new Error(
        `Windows shim ${shimPath} 指向的 JS 入口不存在：${entryJs}`,
      );
    }
    return {
      command: options.execPath ?? process.execPath,
      prependArgs: [entryJs],
      kind: "node-shim",
      shimPath,
      entryJs,
    };
  }

  const executable = findOnPath(name, lookup);
  if (!executable) {
    throw new Error(`无法在 PATH 中找到可执行文件 ${name}。`);
  }
  return { command: executable, prependArgs: [], kind: "posix-path" };
}

/**
 * 执行工具命令的执行辅助：先解析命令，再 spawnSync（shell:false）。
 * options 额外支持 capture/allowFailure/spawnSync/secrets（脱敏用）。
 */
export function runTool(name, args, options = {}) {
  const {
    capture = false,
    allowFailure = false,
    spawnSync = nodeSpawnSync,
    secrets = [],
    redact = defaultRedact,
    ...spawnOptions
  } = options;
  const resolved = resolveToolCommand(name, options);
  const finalArgs = [...resolved.prependArgs, ...args];
  const result = spawnSync(resolved.command, finalArgs, {
    encoding: "utf8",
    ...spawnOptions,
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (!allowFailure && result.status !== 0) {
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    throw new Error(
      redact(
        `Command failed: ${name} ${args.join(" ")}\n${output}`,
        secrets,
      ),
    );
  }
  return result;
}

function defaultRedact(text, secrets) {
  let out = String(text);
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length >= 4) {
      out = out.split(secret).join("[REDACTED]");
    }
  }
  return out;
}
