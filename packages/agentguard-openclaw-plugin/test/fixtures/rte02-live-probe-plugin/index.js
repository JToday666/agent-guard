// RTE-02 live probe plugin entry.
//
// One-shot evidence probe: registers three deterministic tools and records
// ordered observations of before_tool_call / after_tool_call /
// tool_result_persist to a JSONL file pointed to by AGENTGUARD_SPIKE_EVIDENCE.
//
// Evidence discipline: handlers only OBSERVE and RECORD. The single
// enforcement action is the deny scenario (block:true for rte_probe_deny).
// tool_result_persist must stay synchronous, so recording uses appendFileSync.

import fs from "node:fs";
import path from "node:path";

const EVIDENCE_PATH = process.env.AGENTGUARD_SPIKE_EVIDENCE;

function record(kind, detail) {
  if (!EVIDENCE_PATH) return;
  try {
    const line = JSON.stringify({
      at: new Date().toISOString(),
      kind,
      ...detail,
    });
    fs.mkdirSync(path.dirname(EVIDENCE_PATH), { recursive: true });
    fs.appendFileSync(EVIDENCE_PATH, `${line}\n`, "utf8");
  } catch {
    // Evidence recording must never break the host tool loop.
  }
}

function paramKeys(params) {
  return params && typeof params === "object" ? Object.keys(params) : [];
}

export default {
  id: "rte02-live-probe",
  name: "RTE-02 Live Probe",
  description: "Records tool hook observations for PR-RTE-02 live forensics.",
  register(api) {
    api.registerTool({
      name: "rte_probe_ok",
      description:
        "RTE-02 probe tool that always succeeds. Call this tool with any parameters when asked to run the allow scenario.",
      parameters: {
        type: "object",
        properties: {
          marker: { type: "string", description: "Free-form marker value." },
        },
      },
      async execute(toolCallId, params) {
        record("tool_executed", { tool: "rte_probe_ok", toolCallId });
        return {
          content: [
            {
              type: "text",
              text: `rte_probe_ok succeeded with params ${JSON.stringify(paramKeys(params ?? {}))}`,
            },
          ],
        };
      },
    });

    api.registerTool({
      name: "rte_probe_fail",
      description:
        "RTE-02 probe tool that always fails. Call this tool when asked to run the error scenario.",
      parameters: {
        type: "object",
        properties: {
          marker: { type: "string", description: "Free-form marker value." },
        },
      },
      async execute(toolCallId) {
        record("tool_executed", { tool: "rte_probe_fail", toolCallId });
        throw new Error("rte02 spike: deliberate tool failure");
      },
    });

    api.registerTool({
      name: "rte_probe_deny",
      description:
        "RTE-02 probe tool used for the deny scenario. Call this tool when asked to run the deny scenario.",
      parameters: {
        type: "object",
        properties: {
          marker: { type: "string", description: "Free-form marker value." },
        },
      },
      async execute(toolCallId) {
        // If this ever runs, the deny scenario failed to block.
        record("tool_executed", { tool: "rte_probe_deny", toolCallId });
        return {
          content: [
            { type: "text", text: "rte_probe_deny executed (deny failed!)" },
          ],
        };
      },
    });

    api.on("before_tool_call", (event, ctx) => {
      record("before_tool_call", {
        toolCallId: event.toolCallId ?? null,
        ctxToolCallId: ctx?.toolCallId ?? null,
        toolName: event.toolName,
        paramKeys: paramKeys(event.params),
      });
      if (event.toolName === "rte_probe_deny") {
        return { block: true, blockReason: "rte02 spike deny" };
      }
      return undefined;
    });

    api.on("after_tool_call", (event, ctx) => {
      record("after_tool_call", {
        toolCallId: event.toolCallId ?? null,
        ctxToolCallId: ctx?.toolCallId ?? null,
        toolName: event.toolName,
        paramKeys: paramKeys(event.params),
        resultPresent: event.result !== undefined,
        resultType: event.result === undefined ? "absent" : typeof event.result,
        errorPresent: event.error !== undefined,
        errorIsString: typeof event.error === "string",
        durationMsType: typeof event.durationMs,
      });
    });

    api.on("tool_result_persist", (event, ctx) => {
      // Synchronous hook: record synchronously and never return a Promise.
      record("tool_result_persist", {
        toolCallId: event.toolCallId ?? ctx?.toolCallId ?? null,
        toolName: event.toolName ?? ctx?.toolName ?? null,
      });
      return undefined;
    });
  },
};
