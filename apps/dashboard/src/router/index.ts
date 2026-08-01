import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";

import { getDashboardPageLoader } from "./dashboard-page-loaders";

declare module "vue-router" {
  interface RouteMeta {
    keepAlive?: boolean;
    title?: string;
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
    component: getDashboardPageLoader("overview"),
    meta: {
      keepAlive: true,
      title: "安全总览",
    },
  },
  {
    path: "/approvals/:approval_id?",
    name: "approvals",
    component: getDashboardPageLoader("approvals"),
    meta: {
      keepAlive: true,
      title: "人工审批",
    },
  },
  {
    path: "/investigations",
    name: "investigations",
    component: getDashboardPageLoader("investigations"),
    meta: {
      keepAlive: true,
      title: "事件调查",
    },
  },
  {
    path: "/evidence",
    name: "evidence",
    component: getDashboardPageLoader("evidence"),
    meta: {
      keepAlive: true,
      title: "证据链",
    },
  },
  {
    path: "/evidence/:trace_id",
    name: "evidence-detail",
    component: getDashboardPageLoader("evidenceDetail"),
    meta: {
      keepAlive: true,
      title: "证据链详情",
    },
  },
  {
    path: "/evaluation",
    name: "evaluation",
    component: getDashboardPageLoader("evaluation"),
    meta: {
      keepAlive: true,
      title: "安全评测",
    },
  },
  {
    path: "/system",
    name: "system",
    component: getDashboardPageLoader("system"),
    meta: {
      keepAlive: true,
      title: "系统状态",
    },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) return savedPosition;
    if (to.hash) {
      const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      return { behavior: reduceMotion ? "auto" : "smooth", el: to.hash, top: 76 };
    }
    if (to.path !== from.path) return { top: 0 };
    return false;
  },
});

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} · AgentGuard` : "AgentGuard";
});
