import {
  createRouter,
  createWebHistory,
  type RouteRecordRaw,
} from "vue-router";

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
    redirect: "/overview",
  },
  {
    path: "/overview",
    name: "overview",
    component: () => import("../pages/OverviewPage.vue"),
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "总览",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/approvals/:approval_id?",
    name: "approvals",
    component: () => import("../pages/ApprovalsPage.vue"),
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "审批",
      requiredRole: "approver",
      requiresAuth: false,
    },
  },
  {
    path: "/investigations",
    name: "investigations",
    component: () => import("../pages/InvestigationsPage.vue"),
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "调查",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/investigations/:trace_id",
    name: "investigation-detail",
    component: () => import("../pages/InvestigationDetailPage.vue"),
    meta: {
      group: "monitor",
      keepAlive: true,
      label: "调查详情",
      requiredRole: "viewer",
      requiresAuth: false,
    },
  },
  {
    path: "/evaluation",
    name: "evaluation",
    component: () => import("../pages/EvaluationPage.vue"),
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
    component: () => import("../pages/SystemPage.vue"),
    meta: {
      group: "operations",
      keepAlive: true,
      label: "系统",
      requiredRole: "operator",
      requiresAuth: false,
    },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
