import {
  createRouter,
  createWebHistory,
  type RouteRecordRaw,
} from "vue-router";

import AdvancedPage from "../pages/AdvancedPage.vue";
import ApprovalsPage from "../pages/ApprovalsPage.vue";
import EvaluationPage from "../pages/EvaluationPage.vue";
import EventsPage from "../pages/EventsPage.vue";
import OverviewPage from "../pages/OverviewPage.vue";
import SystemPage from "../pages/SystemPage.vue";
import TraceDetailPage from "../pages/TraceDetailPage.vue";
import TracesPage from "../pages/TracesPage.vue";

export type DashboardRouteGroup = "monitor" | "evaluation" | "operations";
export type DashboardRouteRole = "viewer" | "approver" | "operator";

declare module "vue-router" {
  interface RouteMeta {
    group?: DashboardRouteGroup;
    keepAlive?: boolean;
    label?: string;
    requiredRole?: DashboardRouteRole;
    requiresAuth?: boolean;
  }
}

export const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: "/events",
  },
  {
    path: "/events",
    name: "events",
    component: EventsPage,
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "事件",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/overview",
    name: "overview",
    component: OverviewPage,
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "总览",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/approvals",
    name: "approvals",
    component: ApprovalsPage,
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "审批",
      requiredRole: "approver",
      requiresAuth: false,
    },
  },
  {
    path: "/approvals/:approval_id",
    name: "approval-detail",
    component: ApprovalsPage,
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "审批详情",
      requiredRole: "approver",
      requiresAuth: false,
    },
  },
  {
    path: "/traces",
    name: "traces",
    component: TracesPage,
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "链路",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/traces/:trace_id",
    name: "trace-detail",
    component: TraceDetailPage,
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "链路详情",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/evaluation",
    name: "evaluation",
    component: EvaluationPage,
    meta: {
      group: "evaluation",
      keepAlive: true,
      label: "评测",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/system",
    name: "system",
    component: SystemPage,
    meta: {
      group: "operations",
      keepAlive: true,
      label: "系统",
      requiredRole: "operator",
      requiresAuth: false,
    },
  },
  {
    path: "/advanced",
    name: "advanced",
    component: AdvancedPage,
    meta: {
      group: "operations",
      keepAlive: true,
      label: "高级",
      requiredRole: "operator",
      requiresAuth: false,
    },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to) => {
  void to.meta.requiresAuth;
  void to.meta.requiredRole;
  return true;
});
