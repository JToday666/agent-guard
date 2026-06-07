import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";

import AdvancedPage from "../pages/AdvancedPage.vue";
import ApprovalDetailPage from "../pages/ApprovalDetailPage.vue";
import ApprovalsPage from "../pages/ApprovalsPage.vue";
import EvaluationPage from "../pages/EvaluationPage.vue";
import EventsPage from "../pages/EventsPage.vue";
import OverviewPage from "../pages/OverviewPage.vue";
import SystemPage from "../pages/SystemPage.vue";
import TraceDetailPage from "../pages/TraceDetailPage.vue";
import TracesPage from "../pages/TracesPage.vue";

export const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: "/events",
  },
  {
    path: "/events",
    name: "events",
    component: EventsPage,
    meta: { label: "Events", group: "Monitor" },
  },
  {
    path: "/overview",
    name: "overview",
    component: OverviewPage,
    meta: { label: "Overview", group: "Monitor" },
  },
  {
    path: "/approvals",
    name: "approvals",
    component: ApprovalsPage,
    meta: { label: "Approvals", group: "Monitor" },
  },
  {
    path: "/approvals/:approval_id",
    name: "approval-detail",
    component: ApprovalDetailPage,
    meta: { label: "Approval Detail", group: "Monitor" },
  },
  {
    path: "/traces",
    name: "traces",
    component: TracesPage,
    meta: { label: "Traces", group: "Monitor" },
  },
  {
    path: "/traces/:trace_id",
    name: "trace-detail",
    component: TraceDetailPage,
    meta: { label: "Trace Detail", group: "Monitor" },
  },
  {
    path: "/evaluation",
    name: "evaluation",
    component: EvaluationPage,
    meta: { label: "Evaluation", group: "Evaluation" },
  },
  {
    path: "/system",
    name: "system",
    component: SystemPage,
    meta: { label: "System", group: "Operations" },
  },
  {
    path: "/advanced",
    name: "advanced",
    component: AdvancedPage,
    meta: { label: "Advanced", group: "Operations" },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
