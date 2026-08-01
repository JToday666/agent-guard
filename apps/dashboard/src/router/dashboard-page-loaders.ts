const pageLoaders = {
  approvals: () => import("../pages/ApprovalsPage.vue"),
  evaluation: () => import("../pages/EvaluationPage.vue"),
  evidence: () => import("../pages/EvidencePage.vue"),
  evidenceDetail: () => import("../pages/EvidenceDetailPage.vue"),
  investigations: () => import("../pages/InvestigationsPage.vue"),
  overview: () => import("../pages/OverviewPage.vue"),
  system: () => import("../pages/SystemPage.vue"),
} as const;

const primaryRouteLoaders = new Map<string, () => Promise<unknown>>([
  ["/overview", pageLoaders.overview],
  ["/investigations", pageLoaders.investigations],
  ["/approvals", pageLoaders.approvals],
  ["/evidence", pageLoaders.evidence],
  ["/evaluation", pageLoaders.evaluation],
  ["/system", pageLoaders.system],
]);

export function getDashboardPageLoader(name: keyof typeof pageLoaders) {
  return pageLoaders[name];
}

export function preloadDashboardRoute(path: string): void {
  const normalizedPath = `/${path.split("/").filter(Boolean)[0] ?? "overview"}`;
  void primaryRouteLoaders.get(normalizedPath)?.();
}

export function schedulePrimaryRoutePreload(): () => void {
  let cancelled = false;
  const idleWindow = window as unknown as {
    cancelIdleCallback?: (handle: number) => void;
    requestIdleCallback?: (callback: IdleRequestCallback, options?: IdleRequestOptions) => number;
  };
  const preload = () => {
    if (cancelled) return;
    void Promise.allSettled([...primaryRouteLoaders.values()].map((load) => load()));
  };

  if (idleWindow.requestIdleCallback) {
    const idleId = idleWindow.requestIdleCallback(preload, { timeout: 2_500 });
    return () => {
      cancelled = true;
      idleWindow.cancelIdleCallback?.(idleId);
    };
  }

  const timerId = window.setTimeout(preload, 800);
  return () => {
    cancelled = true;
    window.clearTimeout(timerId);
  };
}
