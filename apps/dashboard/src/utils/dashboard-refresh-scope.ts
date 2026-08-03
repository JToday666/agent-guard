export type DashboardRefreshScope =
  "overview" | "investigations" | "approvals" | "evidence" | "evaluation" | "system";

export type DashboardRefreshResource =
  | "adapter"
  | "aggregateMetrics"
  | "approvals"
  | "auditWindow"
  | "auditIntegrity"
  | "configAudit"
  | "evaluationRun"
  | "health"
  | "policy"
  | "policyHistory";

const commonResources: DashboardRefreshResource[] = ["health", "approvals"];

const resourcesByScope: Record<DashboardRefreshScope, DashboardRefreshResource[]> = {
  approvals: [...commonResources, "auditWindow"],
  evaluation: [...commonResources, "auditWindow", "evaluationRun"],
  evidence: [...commonResources, "auditWindow", "auditIntegrity"],
  investigations: [...commonResources, "auditWindow"],
  overview: [...commonResources, "auditWindow", "auditIntegrity"],
  system: [
    ...commonResources,
    "policy",
    "policyHistory",
    "auditIntegrity",
    "configAudit",
    "adapter",
  ],
};

export function getDashboardRefreshScope(
  routeName: string | symbol | null | undefined,
): DashboardRefreshScope {
  if (routeName === "investigations") return "investigations";
  if (routeName === "approvals") return "approvals";
  if (routeName === "evidence" || routeName === "evidence-detail") return "evidence";
  if (routeName === "evaluation") return "evaluation";
  if (routeName === "system") return "system";
  return "overview";
}

export function getDashboardRefreshResources(
  scope: DashboardRefreshScope,
): ReadonlySet<DashboardRefreshResource> {
  return new Set(resourcesByScope[scope]);
}
