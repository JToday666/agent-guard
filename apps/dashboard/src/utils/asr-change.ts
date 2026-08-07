export type AsrChangeDirection = "decrease" | "increase" | "unchanged" | "unknown";

export interface AsrChange {
  direction: AsrChangeDirection;
  label: string;
  text: string;
  value: string;
}

const CHANGE_TOLERANCE = 1e-9;

export function describeAsrChange(before: number | null, after: number | null): AsrChange {
  if (before === null || after === null || !Number.isFinite(before) || !Number.isFinite(after)) {
    return {
      direction: "unknown",
      label: "变化数据不足",
      text: "数据不足",
      value: "—",
    };
  }

  const delta = after - before;
  const value = `${(Math.abs(delta) * 100).toFixed(1)}pp`;
  if (Math.abs(delta) <= CHANGE_TOLERANCE) {
    return {
      direction: "unchanged",
      label: "攻击成功率持平",
      text: `持平 ${value}`,
      value,
    };
  }
  if (delta < 0) {
    return {
      direction: "decrease",
      label: "攻击成功率下降",
      text: `下降 ${value}`,
      value,
    };
  }
  return {
    direction: "increase",
    label: "攻击成功率上升",
    text: `上升 ${value}`,
    value,
  };
}
