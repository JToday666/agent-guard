import type { ExecutionStepViewModel } from "../../types/dashboard";

export type ExecutionFlowOrientation = "horizontal" | "vertical";
export type ExecutionFlowLaneId = "agent" | "controlled" | "outcome";
export type ExecutionTraceLayout = "graph" | "list";
export type ExecutionStepFilter = "all" | "unconfirmed" | "approval" | "risk" | "failed";

export interface ExecutionFlowLane {
  id: ExecutionFlowLaneId;
  label: string;
  description: string;
  count: number;
  headerHeight: number;
  position: { x: number; y: number };
  width: number;
  height: number;
}

export interface ExecutionFlowStepNode {
  id: string;
  laneId: ExecutionFlowLaneId;
  order: number;
  position: { x: number; y: number };
  step: ExecutionStepViewModel;
}

export interface ExecutionFlowOrderEdge {
  id: string;
  source: string;
  target: string;
  label: "随后记录";
  relation: "audit_order";
}

export interface ExecutionFlowLayout {
  width: number;
  height: number;
  lanes: ExecutionFlowLane[];
  nodes: ExecutionFlowStepNode[];
  edges: ExecutionFlowOrderEdge[];
}

const LANE_DEFINITIONS: ReadonlyArray<Pick<ExecutionFlowLane, "id" | "label" | "description">> = [
  {
    id: "agent",
    label: "智能体处理",
    description: "上下文、模型输入与模型输出的安全检查",
  },
  {
    id: "controlled",
    label: "受控动作",
    description: "工具、记忆、消息及其他外部动作",
  },
  {
    id: "outcome",
    label: "检查与结果",
    description: "工具结果、安全检查及运行回执",
  },
];

export const EXECUTION_FLOW_NODE_WIDTH = 276;
export const EXECUTION_FLOW_NODE_HEIGHT = 206;
export const EXECUTION_FLOW_LANE_HEADER_HEIGHT = 64;
export const EXECUTION_FLOW_COMPACT_WIDTH = 920;
const HORIZONTAL_COLUMN_GAP = 52;
const HORIZONTAL_LANE_GAP = 26;
const HORIZONTAL_CONTENT_START_X = 72;
const HORIZONTAL_CONTENT_END_PADDING = 24;
const HORIZONTAL_LANE_BOTTOM_PADDING = 22;
const VERTICAL_ROW_GAP = 38;
const VERTICAL_LANE_GAP = 24;
const VERTICAL_LANE_INLINE_PADDING = 17;
const VERTICAL_LANE_BOTTOM_PADDING = 32;

export function getExecutionFlowLane(step: ExecutionStepViewModel): ExecutionFlowLaneId {
  if (
    step.category === "context" ||
    step.category === "model_input" ||
    step.category === "model_output"
  ) {
    return "agent";
  }
  if (
    step.category === "tool" ||
    step.category === "memory" ||
    step.category === "message" ||
    (step.category === "unknown" && step.kind === "action")
  ) {
    return "controlled";
  }
  return "outcome";
}

export function buildExecutionFlowLayout(
  steps: readonly ExecutionStepViewModel[],
  orientation: ExecutionFlowOrientation,
): ExecutionFlowLayout {
  const laneCounts = new Map<ExecutionFlowLaneId, number>();
  const laneByStepId = new Map<string, ExecutionFlowLaneId>();
  for (const step of steps) {
    const laneId = getExecutionFlowLane(step);
    laneByStepId.set(step.stepId, laneId);
    laneCounts.set(laneId, (laneCounts.get(laneId) ?? 0) + 1);
  }

  const horizontalLaneHeight =
    EXECUTION_FLOW_LANE_HEADER_HEIGHT + EXECUTION_FLOW_NODE_HEIGHT + HORIZONTAL_LANE_BOTTOM_PADDING;
  const verticalLaneWidth = EXECUTION_FLOW_NODE_WIDTH + VERTICAL_LANE_INLINE_PADDING * 2;
  const contentWidth = Math.max(
    44 * 16,
    HORIZONTAL_CONTENT_START_X +
      Math.max(0, steps.length - 1) * (EXECUTION_FLOW_NODE_WIDTH + HORIZONTAL_COLUMN_GAP) +
      EXECUTION_FLOW_NODE_WIDTH +
      HORIZONTAL_CONTENT_END_PADDING,
  );
  const contentHeight = Math.max(
    31 * 16,
    EXECUTION_FLOW_LANE_HEADER_HEIGHT +
      Math.max(0, steps.length - 1) * (EXECUTION_FLOW_NODE_HEIGHT + VERTICAL_ROW_GAP) +
      EXECUTION_FLOW_NODE_HEIGHT +
      VERTICAL_LANE_BOTTOM_PADDING,
  );

  const lanes = LANE_DEFINITIONS.filter((lane) => (laneCounts.get(lane.id) ?? 0) > 0).map(
    (lane) => {
      const laneIndex = LANE_DEFINITIONS.findIndex((candidate) => candidate.id === lane.id);
      return {
        ...lane,
        count: laneCounts.get(lane.id) ?? 0,
        headerHeight: EXECUTION_FLOW_LANE_HEADER_HEIGHT,
        height: orientation === "horizontal" ? horizontalLaneHeight : contentHeight,
        position:
          orientation === "horizontal"
            ? { x: 0, y: laneIndex * (horizontalLaneHeight + HORIZONTAL_LANE_GAP) }
            : { x: laneIndex * (verticalLaneWidth + VERTICAL_LANE_GAP), y: 0 },
        width: orientation === "horizontal" ? contentWidth : verticalLaneWidth,
      };
    },
  );

  const nodes = steps.map((step, order) => {
    const laneId = laneByStepId.get(step.stepId) ?? "outcome";
    const laneIndex = LANE_DEFINITIONS.findIndex((lane) => lane.id === laneId);
    return {
      id: step.stepId,
      laneId,
      order,
      position:
        orientation === "horizontal"
          ? {
              x:
                HORIZONTAL_CONTENT_START_X +
                order * (EXECUTION_FLOW_NODE_WIDTH + HORIZONTAL_COLUMN_GAP),
              y:
                laneIndex * (horizontalLaneHeight + HORIZONTAL_LANE_GAP) +
                EXECUTION_FLOW_LANE_HEADER_HEIGHT,
            }
          : {
              x: laneIndex * (verticalLaneWidth + VERTICAL_LANE_GAP) + VERTICAL_LANE_INLINE_PADDING,
              y:
                EXECUTION_FLOW_LANE_HEADER_HEIGHT +
                order * (EXECUTION_FLOW_NODE_HEIGHT + VERTICAL_ROW_GAP),
            },
      step,
    };
  });

  const edges = nodes.slice(1).map((node, index) => {
    const previous = nodes[index]!;
    return {
      id: `audit-order:${previous.id}:${node.id}`,
      label: "随后记录" as const,
      relation: "audit_order" as const,
      source: previous.id,
      target: node.id,
    };
  });

  return {
    edges,
    height:
      orientation === "horizontal"
        ? LANE_DEFINITIONS.length * horizontalLaneHeight +
          (LANE_DEFINITIONS.length - 1) * HORIZONTAL_LANE_GAP
        : contentHeight,
    lanes,
    nodes,
    width:
      orientation === "horizontal"
        ? contentWidth
        : LANE_DEFINITIONS.length * verticalLaneWidth +
          (LANE_DEFINITIONS.length - 1) * VERTICAL_LANE_GAP,
  };
}
