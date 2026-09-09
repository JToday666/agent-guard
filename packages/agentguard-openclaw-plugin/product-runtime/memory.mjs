/** Real SQLite storage restricted to one private acceptance directory. */
import {
  constants,
  closeSync,
  lstatSync,
  openSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { types } from "node:util";

export class FixtureError extends Error {
  constructor(code) {
    super(`Product runtime fixture: ${code}`);
    this.name = "FixtureError";
    this.code = code;
  }
}

export function requireAcceptanceRoot(value) {
  try {
    if (
      typeof value !== "string" ||
      !isAbsolute(value) ||
      resolve(value) !== value
    ) {
      throw new Error();
    }
    const stat = lstatSync(value);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      realpathSync(value) !== value ||
      (stat.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" && stat.uid !== process.getuid())
    ) {
      throw new Error();
    }
    return value;
  } catch {
    throw new FixtureError("invalid_acceptance_root");
  }
}

export function withFixtureDatabase(acceptanceRoot, name, callback) {
  if (!["memory.sqlite", "inbox.sqlite"].includes(name)) {
    throw new FixtureError("invalid_database_name");
  }
  const root = requireAcceptanceRoot(acceptanceRoot);
  const filename = join(root, name);
  let database;
  try {
    try {
      const fd = openSync(
        filename,
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          constants.O_NOFOLLOW,
        0o600,
      );
      closeSync(fd);
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    for (const suffix of ["", "-journal", "-wal", "-shm"]) {
      try {
        const stat = lstatSync(filename + suffix);
        if (
          !stat.isFile() ||
          stat.isSymbolicLink() ||
          stat.nlink !== 1 ||
          (stat.mode & 0o077) !== 0 ||
          (typeof process.getuid === "function" &&
            stat.uid !== process.getuid())
        ) {
          throw new FixtureError("unsafe_database_file");
        }
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
    database = new DatabaseSync(filename);
    database.exec("PRAGMA busy_timeout=2000; PRAGMA journal_mode=DELETE;");
    return callback(database);
  } catch (error) {
    if (error instanceof FixtureError) throw error;
    throw new FixtureError("storage_unavailable");
  } finally {
    database?.close();
  }
}

function validateParameters(value, fields) {
  if (
    value === null ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    throw new FixtureError("invalid_memory_parameters");
  }
  const copy = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      !fields.includes(key) ||
      !descriptor?.enumerable ||
      !("value" in descriptor)
    )
      throw new FixtureError("invalid_memory_parameters");
    copy[key] = descriptor.value;
  }
  if (
    fields.some((key) => !Object.hasOwn(copy, key)) ||
    typeof copy.key !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(copy.key)
  )
    throw new FixtureError("invalid_memory_parameters");
  return copy;
}

export function createFixtureMemory(
  acceptanceRoot,
  { productMode = false } = {},
) {
  const root = requireAcceptanceRoot(acceptanceRoot);
  const transact = (callback) =>
    withFixtureDatabase(root, "memory.sqlite", (db) => {
      db.exec(
        "CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
      );
      return callback(db);
    });
  return Object.freeze({
    read(parameters) {
      parameters = validateParameters(parameters, ["key"]);
      return transact((db) => {
        const row = db
          .prepare("SELECT value FROM memory WHERE key = ?")
          .get(parameters.key);
        if (productMode) {
          if (!row) throw new FixtureError("memory_key_missing");
          return { key: parameters.key, value: row.value };
        }
        return {
          key: parameters.key,
          found: row !== undefined,
          value: row?.value ?? null,
        };
      });
    },
    write(parameters) {
      parameters = validateParameters(parameters, ["key", "value"]);
      if (
        typeof parameters.value !== "string" ||
        Buffer.byteLength(parameters.value) > 32768
      ) {
        throw new FixtureError("invalid_memory_value");
      }
      return transact((db) => {
        db.exec("BEGIN IMMEDIATE");
        try {
          if (
            productMode &&
            db.prepare("SELECT 1 FROM memory WHERE key = ?").get(parameters.key)
          )
            throw new FixtureError("memory_key_exists");
          if (
            db.prepare("SELECT count(*) AS count FROM memory").get().count >=
              1024 &&
            !db
              .prepare("SELECT 1 FROM memory WHERE key = ?")
              .get(parameters.key)
          ) {
            throw new FixtureError("memory_capacity_exceeded");
          }
          db.prepare(
            productMode
              ? "INSERT INTO memory(key,value) VALUES (?,?)"
              : "INSERT INTO memory(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
          ).run(parameters.key, parameters.value);
          db.exec("COMMIT");
          return { key: parameters.key, written: true };
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      });
    },
  });
}
