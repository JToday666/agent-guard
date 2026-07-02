import {
  createRouter,
  createWebHistory,
  type RouteRecordRaw,
} from "vue-router";

declare module "vue-router" {
  interface RouteMeta {
    keepAlive?: boolean;
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
      keepAlive: true,
    },
  },
  {
    path: "/approvals/:approval_id?",
    name: "approvals",
    component: () => import("../pages/ApprovalsPage.vue"),
    meta: {
      keepAlive: true,
    },
  },
  {
    path: "/investigations",
    name: "investigations",
    component: () => import("../pages/InvestigationsPage.vue"),
    meta: {
      keepAlive: true,
    },
  },
  {
    path: "/evidence",
    name: "evidence",
    component: () => import("../pages/EvidencePage.vue"),
    meta: {
      keepAlive: true,
    },
  },
  {
    path: "/evidence/:trace_id",
    name: "evidence-detail",
    component: () => import("../pages/EvidenceDetailPage.vue"),
    meta: {
      keepAlive: true,
    },
  },
  {
    path: "/evaluation",
    name: "evaluation",
    component: () => import("../pages/EvaluationPage.vue"),
    meta: {
      keepAlive: true,
    },
  },
  {
    path: "/system",
    name: "system",
    component: () => import("../pages/SystemPage.vue"),
    meta: {
      keepAlive: true,
    },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
