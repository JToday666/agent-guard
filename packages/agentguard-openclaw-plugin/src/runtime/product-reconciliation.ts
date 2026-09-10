import { types } from "node:util";

export const PRODUCT_RECONCILIATION_LIMIT = 32;
export type ReconciliationAttempt = {
  attemptId: string;
  startedAt: number;
  finishedAt: number | null;
  status:
    | "inflight"
    | "unknown"
    | "recorded"
    | "retryable"
    | "permanent_rejected"
    | "failed";
  httpStatus: number | null;
  errorCode: string | null;
};
export type Reconciliation = {
  originalRejection: {
    httpStatus: number;
    errorCode: "receipt_permanently_rejected";
  };
  attempts: ReconciliationAttempt[];
};
export function permanentHttpStatus(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 300 &&
    value < 500 &&
    value !== 408 &&
    value !== 429
  );
}
export function exactDataObject(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error("invalid_reconciliation");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).length !== keys.length ||
    keys.some((key) => !descriptors[key] || !("value" in descriptors[key]))
  )
    throw new Error("invalid_reconciliation");
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}
export function readReconciliation(
  value: unknown,
  completed: boolean,
): Reconciliation | null {
  if (value === null) return null;
  const data = exactDataObject(value, ["originalRejection", "attempts"]);
  const original = exactDataObject(data.originalRejection, [
    "httpStatus",
    "errorCode",
  ]);
  if (
    !permanentHttpStatus(original.httpStatus) ||
    original.errorCode !== "receipt_permanently_rejected" ||
    !Array.isArray(data.attempts) ||
    data.attempts.length < 1 ||
    data.attempts.length > PRODUCT_RECONCILIATION_LIMIT
  )
    throw new Error("invalid_reconciliation");
  const seen = new Set<string>();
  let previousAt = 0;
  const rows = data.attempts;
  const attempts = rows.map((value, index) => {
    const row = exactDataObject(value, [
      "attemptId",
      "startedAt",
      "finishedAt",
      "status",
      "httpStatus",
      "errorCode",
    ]);
    if (
      typeof row.attemptId !== "string" ||
      !/^[a-f0-9]{32}$/u.test(row.attemptId) ||
      seen.has(row.attemptId) ||
      !clock(row.startedAt) ||
      row.startedAt < previousAt ||
      ![
        "inflight",
        "unknown",
        "recorded",
        "retryable",
        "permanent_rejected",
        "failed",
      ].includes(row.status as string)
    )
      throw new Error("invalid_reconciliation");
    seen.add(row.attemptId);
    previousAt = row.startedAt;
    if (row.status === "inflight" || row.status === "unknown") {
      if (
        row.finishedAt !== null ||
        row.httpStatus !== null ||
        row.errorCode !== null ||
        (row.status === "inflight" && index !== rows.length - 1)
      )
        throw new Error("invalid_reconciliation");
    } else {
      if (
        !clock(row.finishedAt) ||
        row.finishedAt < row.startedAt ||
        (row.httpStatus !== null &&
          (!Number.isInteger(row.httpStatus) ||
            (row.httpStatus as number) < 100 ||
            (row.httpStatus as number) > 599))
      )
        throw new Error("invalid_reconciliation");
      previousAt = row.finishedAt;
      if (row.status === "recorded") {
        if (
          index !== rows.length - 1 ||
          !completed ||
          typeof row.httpStatus !== "number" ||
          row.httpStatus < 200 ||
          row.httpStatus >= 300 ||
          row.errorCode !== null
        )
          throw new Error("invalid_reconciliation");
      } else if (
        !(
          [
            "receipt_retry_pending",
            "receipt_permanently_rejected",
            "receipt_transport_failed",
            "receipt_transport_invalid",
            "receipt_acknowledgement_invalid",
          ] as unknown[]
        ).includes(row.errorCode)
      )
        throw new Error("invalid_reconciliation");
      if (
        row.status === "permanent_rejected" &&
        (!permanentHttpStatus(row.httpStatus) ||
          row.errorCode !== "receipt_permanently_rejected")
      )
        throw new Error("invalid_reconciliation");
      if (
        row.status === "retryable" &&
        row.errorCode !== "receipt_retry_pending"
      )
        throw new Error("invalid_reconciliation");
    }
    return row as ReconciliationAttempt;
  });
  if (completed && attempts.at(-1)?.status !== "recorded")
    throw new Error("invalid_reconciliation");
  return {
    originalRejection: original as Reconciliation["originalRejection"],
    attempts,
  };
}
function clock(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
