import { defineStore } from "pinia";

type DashboardSection = {
  id: string;
  label: string;
  status: string;
};

export const useDashboardStore = defineStore("dashboard", {
  state: () => ({
    sections: [
      { id: "overview", label: "总览", status: "待接入" },
      { id: "events", label: "实时事件", status: "待接入" },
      { id: "approvals", label: "审批中心", status: "待接入" },
      { id: "metrics", label: "指标", status: "待接入" },
    ] satisfies DashboardSection[],
  }),
});
