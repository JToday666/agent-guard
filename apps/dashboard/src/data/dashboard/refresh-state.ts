import type { DataStatus } from "../../types/dashboard.ts";

export function shouldEnterInitialLoading(status: DataStatus): boolean {
  return status === "idle";
}

export function getRefreshFailureStatus(
  hasCompletedInitialLoad: boolean,
): Extract<DataStatus, "error" | "stale"> {
  return hasCompletedInitialLoad ? "stale" : "error";
}
