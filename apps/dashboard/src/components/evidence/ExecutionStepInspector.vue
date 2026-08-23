<template>
  <aside class="execution-inspector" aria-label="运行步骤详情">
    <template v-if="step">
      <header class="execution-inspector__header">
        <div>
          <span>第 {{ stepNumber }} 步 · {{ getExecutionCategoryLabel(step.category) }}</span>
          <h4>{{ step.displayName }}</h4>
          <code v-if="step.actionName" translate="no">{{ step.actionName }}</code>
        </div>
        <StatusBadge
          :label="getDecisionLabel(step.supervision.officialDecision.decision)"
          :tone="getDecisionTone(step.supervision.officialDecision.decision)"
        />
      </header>

      <div class="execution-inspector__state">
        <strong>{{ displayStatus(step) }}</strong>
        <span>{{ getSemanticsSummary(step.supervision.semantics) }}</span>
      </div>

      <ExecutionSupervisionCapsules v-if="step.kind === 'action'" :step="step" />

      <dl class="execution-inspector__facts">
        <div>
          <dt>动作 / 资源</dt>
          <dd>{{ step.resourceSummary ?? "未记录资源目标" }}</dd>
        </div>
        <div>
          <dt>风险</dt>
          <dd>{{ step.riskScore ?? "未记录" }} · {{ getRiskSeverityLabel(step.severity) }}</dd>
        </div>
        <div>
          <dt>安全判断</dt>
          <dd>{{ step.policyChecks.length }} 次</dd>
        </div>
        <div>
          <dt>最近更新</dt>
          <dd>
            <time :datetime="step.lastUpdatedAt">{{ formatTime(step.lastUpdatedAt) }}</time>
          </dd>
        </div>
      </dl>

      <section class="execution-inspector__section">
        <h5>正式决策 / {{ getV21RailLabel(step.supervision.v21Assessment) }}</h5>
        <div class="execution-inspector__comparison">
          <article>
            <span>OFFICIAL</span>
            <strong>{{ getDecisionLabel(step.supervision.officialDecision.decision) }}</strong>
            <p>{{ step.supervision.officialDecision.reason ?? "未记录判定原因" }}</p>
            <small>
              {{ getAvailabilityLabel(step.supervision.officialDecision.availability) }} ·
              {{ step.supervision.officialDecision.ruleIds.length }} 条规则
            </small>
          </article>
          <article class="is-shadow">
            <span>{{ getV21RailLabel(step.supervision.v21Assessment).toUpperCase() }}</span>
            <strong>{{ v21Disposition(step) }}</strong>
            <p>{{ getV21Summary(step.supervision.v21Assessment) }}</p>
            <small>
              {{ getAuthorityLabel(step.supervision.v21Assessment.decisionAuthority) }} ·
              {{ getAvailabilityLabel(step.supervision.v21Assessment.availability) }}
            </small>
          </article>
        </div>
        <dl
          v-if="step.supervision.v21Assessment.competitionAuthority"
          class="execution-inspector__detail-grid competition-authority"
          data-testid="competition-authority"
        >
          <div>
            <dt>Profile</dt>
            <dd>
              <code translate="no">{{
                step.supervision.v21Assessment.competitionAuthority.profileId
              }}</code>
            </dd>
          </div>
          <div>
            <dt>Authority</dt>
            <dd>{{ step.supervision.v21Assessment.competitionAuthority.source }}</dd>
          </div>
          <div>
            <dt>Mode / Scope</dt>
            <dd>
              {{ step.supervision.v21Assessment.competitionAuthority.mode }} /
              {{ step.supervision.v21Assessment.competitionAuthority.selectionBasis }}
            </dd>
          </div>
          <div>
            <dt>Legacy floor</dt>
            <dd>
              {{
                step.supervision.v21Assessment.competitionAuthority.legacyFloorApplied
                  ? "applied"
                  : "not applied"
              }}
            </dd>
          </div>
          <div>
            <dt>ASK release</dt>
            <dd>{{ step.supervision.v21Assessment.competitionAuthority.approvalRelease }}</dd>
          </div>
          <div class="is-wide">
            <dt>Matched paths</dt>
            <dd>
              <code
                v-if="step.supervision.v21Assessment.competitionAuthority.matchedPathIds.length"
                translate="no"
                >{{
                  step.supervision.v21Assessment.competitionAuthority.matchedPathIds.join(" · ")
                }}</code
              >
              <span v-else>none</span>
            </dd>
          </div>
          <div class="is-wide">
            <dt>Activation ref</dt>
            <dd>
              <code translate="no">{{
                step.supervision.v21Assessment.competitionAuthority.activationRefDigest
              }}</code>
            </dd>
          </div>
        </dl>
      </section>

      <section
        v-if="step.category === 'context'"
        class="execution-inspector__section context-manifest"
        data-testid="context-manifest-panel"
      >
        <header class="context-manifest__header">
          <div>
            <h5>Context Manifest</h5>
            <p>仅展示同一 Trace 中按 GuardEvent ID 精确关联的持久化清单。</p>
          </div>
          <StatusBadge
            :label="manifestStatusLabel(contextManifest)"
            :tone="manifestTone(contextManifest)"
          />
        </header>

        <p v-if="!contextManifest" class="context-manifest__notice">
          {{ manifestAbsentPrefix }}；不会从原始 Prompt、内容入口或 Provenance 推断。
        </p>
        <template v-else>
          <p v-if="contextManifest.missingReasons.length" class="context-manifest__notice">
            {{ contextManifest.missingReasons.join(" · ") }}
          </p>
          <dl class="execution-inspector__detail-grid context-manifest__identity">
            <div>
              <dt>证据状态</dt>
              <dd>{{ getAvailabilityLabel(contextManifest.availability) }}</dd>
            </div>
            <div>
              <dt>GuardEvent ID</dt>
              <dd>
                <code translate="no">{{ contextManifest.eventId }}</code>
              </dd>
            </div>
            <div>
              <dt>Plan ID</dt>
              <dd>
                <code translate="no">{{ contextManifest.planId ?? "未记录" }}</code>
              </dd>
            </div>
            <div>
              <dt>Context Ref</dt>
              <dd>
                <code translate="no">{{ contextManifest.contextRef ?? "未记录" }}</code>
              </dd>
            </div>
            <div class="is-wide">
              <dt>Plan Digest</dt>
              <dd>
                <code translate="no">{{ contextManifest.planDigest ?? "未记录" }}</code>
              </dd>
            </div>
            <div class="is-wide">
              <dt>Manifest Digest</dt>
              <dd>
                <code translate="no">{{ contextManifest.manifestDigest ?? "未记录" }}</code>
              </dd>
            </div>
          </dl>

          <dl
            v-if="contextManifest.counts"
            class="context-manifest__counts"
            aria-label="上下文清单统计"
          >
            <div>
              <dt>总计</dt>
              <dd>{{ contextManifest.counts.total }}</dd>
            </div>
            <div>
              <dt>已返回</dt>
              <dd>{{ contextManifest.counts.returned }}</dd>
            </div>
            <div>
              <dt>纳入</dt>
              <dd>{{ contextManifest.counts.included }}</dd>
            </div>
            <div>
              <dt>隔离</dt>
              <dd>{{ contextManifest.counts.quarantined }}</dd>
            </div>
            <div>
              <dt>排除</dt>
              <dd>{{ contextManifest.counts.excluded }}</dd>
            </div>
            <div>
              <dt>不可信</dt>
              <dd>{{ contextManifest.counts.untrusted }}</dd>
            </div>
          </dl>

          <div v-if="contextManifest.counts" class="context-manifest__source-counts">
            <span>来源分布</span>
            <code
              v-for="[sourceType, count] in Object.entries(contextManifest.counts.bySourceType)"
              :key="sourceType"
              translate="no"
              >{{ sourceType }} {{ count }}</code
            >
          </div>

          <ol v-if="contextManifest.chunks.length" class="context-manifest__chunks">
            <li v-for="chunk in contextManifest.chunks" :key="chunk.chunkId">
              <header>
                <div>
                  <strong>{{ chunk.sourceType }}</strong>
                  <code translate="no">{{ chunk.sourceRef }}</code>
                </div>
                <StatusBadge
                  :label="manifestDispositionLabel(chunk.disposition)"
                  :tone="manifestDispositionTone(chunk.disposition)"
                />
              </header>
              <dl>
                <div>
                  <dt>Compartment</dt>
                  <dd>{{ chunk.compartment }}</dd>
                </div>
                <div>
                  <dt>Trust / Authority</dt>
                  <dd>{{ chunk.trust }} / {{ chunk.factAuthority }}</dd>
                </div>
                <div>
                  <dt>Taints</dt>
                  <dd>{{ listOrUnavailable(chunk.taints) }}</dd>
                </div>
                <div>
                  <dt>Transform</dt>
                  <dd>{{ manifestTransformLabel(chunk) }}</dd>
                </div>
                <div v-if="chunk.contentDigest" class="is-wide">
                  <dt>Content Digest</dt>
                  <dd>
                    <code translate="no">{{ chunk.contentDigest }}</code>
                  </dd>
                </div>
                <div class="is-wide">
                  <dt>安全 Preview</dt>
                  <dd>{{ chunk.safePreview ?? "不展示" }}</dd>
                </div>
                <div v-if="chunk.reasonCodes.length" class="is-wide">
                  <dt>原因</dt>
                  <dd>{{ chunk.reasonCodes.join(" · ") }}</dd>
                </div>
              </dl>
            </li>
          </ol>
          <p
            v-else-if="contextManifest.state === 'budget_dropped'"
            class="context-manifest__notice"
          >
            清单因审计证据预算降级为完整制品摘要；不从其他载荷回填 chunk。
          </p>
          <p
            v-else-if="contextManifest.availability !== 'recorded'"
            class="context-manifest__notice"
          >
            当前没有可安全展示的 chunk。
          </p>
        </template>
      </section>

      <section class="execution-inspector__section">
        <h5>Approval Basis</h5>
        <p v-if="isApprovalNotApplicable(step, approvalBasis)" class="execution-inspector__notice">
          无需审批（该步骤未触发 ask 决策），本步骤不产生审批依据。
        </p>
        <dl v-else class="execution-inspector__detail-grid">
          <div>
            <dt>审批状态</dt>
            <dd>{{ layerValue(step, "approval") }}</dd>
          </div>
          <div>
            <dt>审批 ID</dt>
            <dd>{{ step.supervision.approval.approvalId ?? "未记录" }}</dd>
          </div>
          <div>
            <dt>依据完整性</dt>
            <dd>
              {{
                approvalBasis
                  ? getAvailabilityLabel(approvalBasis.completeness)
                  : approvalMissingReasons(approvalBasis)
              }}
            </dd>
          </div>
          <div>
            <dt>正式审计 / GuardEvent</dt>
            <dd>
              {{ approvalBasis?.officialDecision.policyAuditId ?? "未记录" }} /
              {{ approvalBasis?.sourceContext.eventId ?? "未记录" }}
            </dd>
          </div>
          <div class="is-wide">
            <dt>结构化依据</dt>
            <dd>{{ approvalBasisSummary(approvalBasis) }}</dd>
          </div>
          <div class="is-wide">
            <dt>请求上下文</dt>
            <dd>{{ approvalFieldValue(approvalBasis?.sourceContext.taskPreview) }}</dd>
          </div>
          <div>
            <dt>来源类型</dt>
            <dd>{{ listOrUnavailable(approvalBasis?.sourceContext.rawSourceTypes ?? []) }}</dd>
          </div>
          <div>
            <dt>来源信任</dt>
            <dd>{{ listOrUnavailable(approvalBasis?.sourceContext.sourceTrust ?? []) }}</dd>
          </div>
          <div class="is-wide">
            <dt>缺失原因</dt>
            <dd>{{ approvalMissingReasons(approvalBasis) }}</dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>Approval Resolution</h5>
        <p v-if="isApprovalNotApplicable(step, approvalBasis)" class="execution-inspector__notice">
          无需审批（该步骤未触发 ask 决策），未产生审批决议。
        </p>
        <dl v-else class="execution-inspector__detail-grid">
          <div>
            <dt>终态</dt>
            <dd>{{ approvalFieldValue(approvalBasis?.resolution.status) }}</dd>
          </div>
          <div>
            <dt>决议</dt>
            <dd>{{ approvalResolutionDecision(approvalBasis) }}</dd>
          </div>
          <div>
            <dt>来源 / 操作者</dt>
            <dd>{{ approvalResolutionActor(approvalBasis) }}</dd>
          </div>
          <div>
            <dt>决议时间</dt>
            <dd>{{ formatOptionalTime(approvalBasis?.resolution.resolvedAt ?? null) }}</dd>
          </div>
          <div class="is-wide">
            <dt>决议原因</dt>
            <dd>{{ approvalFieldValue(approvalBasis?.resolution.resolutionReason) }}</dd>
          </div>
        </dl>
      </section>

      <!-- RTE-05 强绑定未具备事件级下发资格，面板常驻空态易误读；
           置 SHOW_ENFORCEMENT_PANEL=true 可恢复（见 runtime-supervision-display.ts） -->
      <section v-if="SHOW_ENFORCEMENT_PANEL" class="execution-inspector__section">
        <h5>Enforcement</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>门控状态</dt>
            <dd>{{ enforcementGateLabel(step) }}</dd>
          </div>
          <div>
            <dt>绑定校验</dt>
            <dd>{{ enforcementBindingLabel(step) }}</dd>
          </div>
          <div>
            <dt>租约消费</dt>
            <dd>{{ enforcementConsumeLabel(step) }}</dd>
          </div>
          <div>
            <dt>证据可用性</dt>
            <dd>{{ getAvailabilityLabel(step.supervision.enforcement.availability) }}</dd>
          </div>
          <div>
            <dt>Lease ID</dt>
            <dd>
              <code translate="no">{{ step.supervision.enforcement.leaseId ?? "未产生" }}</code>
            </dd>
          </div>
          <div>
            <dt>Consumption ID</dt>
            <dd>
              <code translate="no">{{
                step.supervision.enforcement.consumptionId ?? "未产生"
              }}</code>
            </dd>
          </div>
          <div class="is-wide">
            <dt>受控原因</dt>
            <dd>
              {{
                step.supervision.enforcement.availability === "unavailable"
                  ? "强绑定门控证据尚未随 Trace 返回；不能由 DENY 推断 BLOCKED。"
                  : step.supervision.enforcement.reasonCodes.join(" · ") || "已记录"
              }}
            </dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>Runtime Outcome</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>执行结果</dt>
            <dd>{{ layerValue(step, "execution") }}</dd>
          </div>
          <div>
            <dt>运行时收据</dt>
            <dd>{{ step.supervision.execution.receiptRecorded ? "已唯一关联" : "未确认" }}</dd>
          </div>
          <div>
            <dt>调用时间</dt>
            <dd>{{ formatOptionalTime(step.supervision.execution.invokedAt) }}</dd>
          </div>
          <div>
            <dt>完成时间</dt>
            <dd>{{ formatOptionalTime(step.supervision.execution.completedAt) }}</dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>来源、权威与完整性</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>Source</dt>
            <dd>{{ getSourceModeLabel(step.supervision.semantics.elementSourceMode) }}</dd>
          </div>
          <div>
            <dt>Authority</dt>
            <dd>{{ getAuthorityLabel(step.supervision.semantics.decisionAuthority) }}</dd>
          </div>
          <div>
            <dt>Certainty</dt>
            <dd>{{ getCertaintyLabel(step.supervision.semantics.certainty) }}</dd>
          </div>
          <div>
            <dt>Availability</dt>
            <dd>{{ getAvailabilityLabel(step.supervision.semantics.availability) }}</dd>
          </div>
          <div class="is-wide">
            <dt>Control Integrity</dt>
            <dd>
              {{ getControlIntegrityLabel(step.supervision.controlIntegrity.status)
              }}<template v-if="step.supervision.controlIntegrity.reasonCodes.length">
                · {{ step.supervision.controlIntegrity.reasonCodes.join(" · ") }}</template
              ><template v-else-if="step.supervision.controlIntegrity.status !== 'not_applicable'">
                · 未发现违例原因</template
              >
            </dd>
          </div>
        </dl>
      </section>

      <section class="execution-inspector__section">
        <h5>内容进入上下文</h5>
        <dl class="execution-inspector__detail-grid">
          <div>
            <dt>原始渠道</dt>
            <dd>{{ listOrUnavailable(step.supervision.contentIngressSummary.rawSourceTypes) }}</dd>
          </div>
          <div>
            <dt>信任标签</dt>
            <dd>{{ listOrUnavailable(step.supervision.contentIngressSummary.trustLabels) }}</dd>
          </div>
          <div>
            <dt>Taints</dt>
            <dd>{{ listOrUnavailable(step.supervision.contentIngressSummary.taints) }}</dd>
          </div>
          <div>
            <dt>稳定 SourceRef</dt>
            <dd>
              {{ listOrUnavailable(step.supervision.contentIngressSummary.stableSourceRefs) }}
            </dd>
          </div>
          <div class="is-wide">
            <dt>CT 归一化</dt>
            <dd>
              {{
                step.supervision.contentIngressSummary.ctNormalizationAvailability === "unavailable"
                  ? contentIngressUnavailable(step)
                  : listOrUnavailable(
                      step.supervision.contentIngressSummary.normalizedCtSourceTypes,
                    )
              }}
            </dd>
          </div>
        </dl>
      </section>

      <section v-if="step.events.length" class="execution-inspector__section">
        <h5>审计记录</h5>
        <ol class="execution-inspector__events">
          <li v-for="event in step.events" :key="event.auditId">
            <time :datetime="event.occurredAt">{{ formatTime(event.occurredAt) }}</time>
            <span>{{ event.label }}</span>
            <small>{{ recordTypeLabel(event.recordType) }}</small>
          </li>
        </ol>
      </section>

      <details v-if="step.policyChecks.length > 1" class="execution-inspector__checks">
        <summary>全部 {{ step.policyChecks.length }} 次安全判断</summary>
        <ol>
          <li v-for="check in step.policyChecks" :key="check.auditId">
            <div>
              <StatusBadge
                :label="getDecisionLabel(check.decision)"
                :tone="getDecisionTone(check.decision)"
              />
              <time :datetime="check.occurredAt">{{ formatTime(check.occurredAt) }}</time>
            </div>
            <p>{{ check.reason ?? "未记录判定原因" }}</p>
          </li>
        </ol>
      </details>

      <footer class="execution-inspector__actions">
        <RouterLink
          v-if="step.approvalId"
          class="execution-inspector__approval"
          :to="approvalRoute(step)"
        >
          {{ isMockStep(step) ? "查看审批依据（只读）" : "查看审批依据" }}
        </RouterLink>
        <button type="button" @click="emit('show-provenance', step)">查看溯源关系</button>
        <button
          v-if="step.primaryAuditId"
          type="button"
          @click="emit('select-event', step.primaryAuditId)"
        >
          查看审计记录
        </button>
      </footer>
    </template>

    <div v-else class="execution-inspector__empty">
      <MousePointer2 :size="22" aria-hidden="true" />
      <strong>选择一个运行步骤</strong>
      <p>查看正式决策、审批、门控、运行时收据与关联证据。</p>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { MousePointer2 } from "@lucide/vue";

import {
  getAvailabilityLabel,
  getAuthorityLabel,
  getCertaintyLabel,
  getControlIntegrityLabel,
  getSemanticsSummary,
  getSourceModeLabel,
  getSupervisionLayerDisplays,
  getV21RailLabel,
  getV21Summary,
  SHOW_ENFORCEMENT_PANEL,
  type SupervisionLayerKey,
} from "../../data/evidence/runtime-supervision-display.ts";
import { getExecutionCategoryLabel } from "../../data/evidence/execution-trace";
import type {
  AuditRecordType,
  ExecutionStepViewModel,
  TraceLifecycleState,
} from "../../types/dashboard";
import type {
  ApprovalBasisViewModel,
  ContextManifestChunkPresentation,
  ContextManifestViewModel,
} from "../../types/runtime-supervision";
import {
  formatDashboardDateTime,
  getDecisionLabel,
  getDecisionTone,
  getRiskSeverityLabel,
} from "../../utils/dashboard-formatters";
import StatusBadge from "../common/StatusBadge.vue";
import ExecutionSupervisionCapsules from "./ExecutionSupervisionCapsules.vue";

defineOptions({ name: "ExecutionStepInspector" });

const props = defineProps<{
  approvalBasis?: ApprovalBasisViewModel;
  contextManifest?: ContextManifestViewModel;
  lifecycleState: TraceLifecycleState;
  step?: ExecutionStepViewModel;
  stepNumber?: number;
}>();

const emit = defineEmits<{
  "select-event": [auditId: string];
  "show-provenance": [step: ExecutionStepViewModel];
}>();

function displayStatus(step: ExecutionStepViewModel): string {
  const isTerminal = ["completed", "failed", "cancelled"].includes(props.lifecycleState);
  if (!isTerminal || step.settled) return step.statusLabel;
  if (step.approval === "pending") return "运行已结束，审批结果未确认";
  if (step.receiptExpectation === "required") return "运行已结束，执行结果未确认";
  return step.statusLabel;
}

function recordTypeLabel(recordType: AuditRecordType): string {
  const labels: Record<AuditRecordType, string> = {
    config_audit: "配置审计",
    policy_evaluation: "安全判断",
    runtime_observation: "运行观察",
    runtime_outcome: "运行结果",
    unknown: "审计记录",
  };
  return labels[recordType];
}

function formatTime(value: string): string {
  return formatDashboardDateTime(value) || "未记录";
}

function formatOptionalTime(value: string | null): string {
  return value ? formatTime(value) : "未记录";
}

function listOrUnavailable(values: readonly string[]): string {
  return values.length ? values.join(" · ") : "不可用";
}

// ③未启用/未生成：上下文构建功能未启用或本步骤无上下文组装（非 context 步骤不渲染本面板，
// 天然即「无需 Context Manifest」）。
const manifestAbsentPrefix = "上下文清单未生成（上下文构建功能未启用，或本步骤无上下文组装）";

function manifestStatusLabel(manifest: ContextManifestViewModel | undefined): string {
  if (!manifest) return "未生成";
  const labels: Record<ContextManifestViewModel["state"], string> = {
    budget_dropped: "预算降级",
    correlation_conflict: "关联冲突",
    invalid: "契约无效",
    missing: "未记录",
    recorded: manifest.availability === "recorded" ? "已记录" : "部分记录",
    window_truncated: "窗口截断",
  };
  return labels[manifest.state];
}

function manifestTone(
  manifest: ContextManifestViewModel | undefined,
): "neutral" | "success" | "warning" | "danger" {
  if (!manifest || manifest.availability === "unavailable") return "neutral";
  if (manifest.state === "correlation_conflict" || manifest.state === "invalid") return "danger";
  return manifest.availability === "recorded" ? "success" : "warning";
}

function manifestDispositionLabel(
  disposition: ContextManifestChunkPresentation["disposition"],
): string {
  return { excluded: "已排除", included: "已纳入", quarantined: "已隔离" }[disposition];
}

function manifestDispositionTone(
  disposition: ContextManifestChunkPresentation["disposition"],
): "success" | "warning" | "danger" {
  return { excluded: "danger", included: "success", quarantined: "warning" }[disposition] as
    "success" | "warning" | "danger";
}

function manifestTransformLabel(chunk: ContextManifestChunkPresentation): string {
  if (!chunk.transformationAction) return "preserved";
  return `${chunk.transformState} / ${chunk.transformationAction}`;
}

function approvalBasisSummary(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "结构化审批依据不可用，不从判定原因、关键词或 Shadow 结果推导。";
  if (basis.completeness === "recorded") {
    return "已从当前执行步骤唯一选定的正式 ASK 与审批证据生成。";
  }
  if (basis.completeness === "unavailable") {
    return "关键身份或原始审批证据不可用；该依据仅供只读调查。";
  }
  return "当前证据窗口或请求事实不完整；该依据仅供只读调查。";
}

function isApprovalNotApplicable(
  step: ExecutionStepViewModel,
  basis: ApprovalBasisViewModel | undefined,
): boolean {
  // 真实错误优先：basis 存在但完整性校验失败且携带具体缺失原因时，仍需展示错误码。
  if (basis && basis.missingReasons.length > 0) return false;
  if (step.supervision.approval.availability === "not_applicable") return true;
  return !basis && !step.approvalId;
}

function approvalMissingReasons(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "APPROVAL_BASIS_UNAVAILABLE";
  return basis.missingReasons.length ? basis.missingReasons.join(" · ") : "无";
}

// 审批依据字段缺失：整体无 basis 时复用缺失原因码；有 basis 但字段为空才是「未记录」。
function approvalFieldValue(value: string | null | undefined): string {
  if (value) return value;
  return props.approvalBasis ? "未记录" : approvalMissingReasons(props.approvalBasis);
}

function approvalResolutionDecision(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "不可用";
  if (basis.resolution.decision === "allow_once") return "单次放行";
  if (basis.resolution.decision === "deny") return "拒绝";
  return "尚未决议";
}

function approvalResolutionActor(basis: ApprovalBasisViewModel | undefined): string {
  if (!basis) return "不可用";
  const source = basis.resolution.resolutionSource ?? "未记录来源";
  const actor = basis.resolution.resolvedBy ?? "未记录操作者";
  return `${source} / ${actor}`;
}

function layerValue(step: ExecutionStepViewModel, key: SupervisionLayerKey): string {
  return getSupervisionLayerDisplays(step).find((layer) => layer.key === key)?.value ?? "未返回";
}

function enforcementGateLabel(step: ExecutionStepViewModel): string {
  const labels = {
    evaluating: "校验中",
    allowed: "已放行",
    approval_pending: "等待审批",
    approval_released: "审批已单次放行",
    blocked: "已阻断",
    timed_out: "已超时",
    binding_failed: "绑定失败",
    unknown: "状态未知",
  } as const;
  return labels[step.supervision.enforcement.gateState];
}

function enforcementBindingLabel(step: ExecutionStepViewModel): string {
  const labels = {
    not_applicable: "不适用",
    not_performed: "未执行",
    passed: "已通过",
    failed: "失败",
    unknown: "未知",
  } as const;
  return labels[step.supervision.enforcement.bindingCheckStatus];
}

function enforcementConsumeLabel(step: ExecutionStepViewModel): string {
  const labels = {
    not_applicable: "不适用",
    not_attempted: "未尝试",
    consumed: "已消费",
    expired: "已过期",
    revoked: "已撤销",
    rejected: "已拒绝",
    unknown: "未知",
  } as const;
  return labels[step.supervision.enforcement.leaseConsumeOutcome];
}

function v21Disposition(step: ExecutionStepViewModel): string {
  return step.supervision.v21Assessment.fastDisposition ?? "不可用";
}

function isMockStep(step: ExecutionStepViewModel): boolean {
  return step.supervision.semantics.elementSourceMode === "mock";
}

function contentIngressUnavailable(step: ExecutionStepViewModel): string {
  return isMockStep(step)
    ? "CT 归一化不可用；溯源视图仅展示明确标记的 Mock 内容入口链。"
    : "CT 归一化不可用；Live 数据不会回退到 Fixture。";
}

function approvalRoute(step: ExecutionStepViewModel) {
  return {
    path: `/approvals/${step.approvalId}`,
    query: isMockStep(step) ? { readonly: "1" } : {},
  };
}
</script>

<style scoped lang="scss">
.execution-inspector {
  align-content: start;
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-2);
  display: grid;
  gap: var(--space-4);
  grid-auto-rows: max-content;
  max-height: 44rem;
  min-width: 0;
  overflow-y: auto;
  overscroll-behavior-y: contain;
  padding: var(--space-4);
  scrollbar-width: thin;
}

.execution-inspector__header {
  align-items: start;
  border-bottom: 1px solid var(--color-border);
  display: flex;
  gap: var(--space-3);
  justify-content: space-between;
  padding-bottom: var(--space-3);
}

.execution-inspector__header > div,
.execution-inspector__state {
  display: grid;
  gap: 0.2rem;
  min-width: 0;
}

.execution-inspector__header span,
.execution-inspector__header code,
.execution-inspector__state span,
.execution-inspector dt,
.execution-inspector__events :is(time, small),
.execution-inspector__checks time {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.execution-inspector__header h4,
.execution-inspector__header code,
.execution-inspector__state strong {
  margin: 0;
  overflow-wrap: anywhere;
}

.execution-inspector__header h4 {
  font-size: var(--font-size-16);
}

.execution-inspector__facts,
.execution-inspector__detail-grid {
  display: grid;
  gap: var(--space-2);
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
}

.execution-inspector__facts > div,
.execution-inspector__detail-grid > div {
  background: var(--color-surface-muted);
  border-radius: var(--radius-1);
  display: grid;
  gap: 0.2rem;
  min-width: 0;
  padding: var(--space-2);
}

.execution-inspector__detail-grid > .is-wide {
  grid-column: 1 / -1;
}

.execution-inspector dd {
  font-size: var(--font-size-12);
  margin: 0;
  overflow-wrap: anywhere;
}

.execution-inspector__section {
  display: grid;
  gap: var(--space-2);
}

.execution-inspector__section h5,
.execution-inspector__section p {
  margin: 0;
}

.execution-inspector__section h5 {
  color: var(--color-text-muted);
  font-size: var(--font-size-12);
  letter-spacing: 0.02em;
}

.execution-inspector__comparison {
  display: grid;
  gap: var(--space-2);
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.execution-inspector__comparison article {
  border: 1px solid var(--color-border);
  border-left: 3px solid var(--color-active);
  border-radius: var(--radius-1);
  display: grid;
  gap: 0.3rem;
  min-width: 0;
  padding: var(--space-2);
}

.execution-inspector__comparison article.is-shadow {
  border-left-color: var(--color-warning);
}

.execution-inspector__comparison span,
.execution-inspector__comparison small {
  color: var(--color-text-subtle);
  font-family: var(--font-family-mono);
  font-size: 0.58rem;
}

.execution-inspector__comparison strong {
  font-size: var(--font-size-12);
}

.execution-inspector__comparison p {
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  line-height: 1.45;
}

.context-manifest {
  border-block: 1px solid var(--color-border);
  padding-block: var(--space-3);
}

.context-manifest__header {
  align-items: start;
  display: flex;
  gap: var(--space-3);
  justify-content: space-between;
}

.context-manifest__header > div {
  display: grid;
  gap: var(--space-1);
  min-width: 0;
}

.context-manifest__header p,
.context-manifest__notice,
.execution-inspector__notice {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  line-height: 1.5;
}

.execution-inspector__notice {
  border-left-color: var(--color-border-strong);
  margin: 0;
}

.context-manifest__notice,
.execution-inspector__notice {
  background: var(--color-surface-muted);
  border-left: 2px solid var(--color-warning);
  padding: var(--space-2);
}

.context-manifest__counts {
  display: grid;
  gap: 1px;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin: 0;
  overflow: hidden;
}

.context-manifest__counts > div {
  background: var(--color-surface-muted);
  padding: var(--space-2);
}

.context-manifest__counts dd {
  font-size: var(--font-size-16);
  font-variant-numeric: tabular-nums;
  font-weight: var(--font-weight-semibold);
}

.context-manifest__source-counts {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.context-manifest__source-counts span,
.context-manifest__source-counts code {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
}

.context-manifest__source-counts code {
  background: var(--color-surface-muted);
  border-radius: var(--radius-1);
  padding: 0.2rem 0.35rem;
}

.context-manifest__chunks {
  display: grid;
  gap: var(--space-2);
  list-style: none;
  margin: 0;
  padding: 0;
}

.context-manifest__chunks > li {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-1);
  display: grid;
  gap: var(--space-2);
  min-width: 0;
  padding: var(--space-2);
}

.context-manifest__chunks header {
  align-items: start;
  display: flex;
  gap: var(--space-2);
  justify-content: space-between;
}

.context-manifest__chunks header > div {
  display: grid;
  min-width: 0;
}

.context-manifest__chunks header strong {
  font-size: var(--font-size-12);
}

.context-manifest__chunks header code {
  color: var(--color-text-subtle);
  font-size: var(--font-size-11);
  overflow-wrap: anywhere;
}

.context-manifest__chunks dl {
  display: grid;
  gap: var(--space-1);
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
}

.context-manifest__chunks dl > div {
  min-width: 0;
}

.context-manifest__chunks dl > .is-wide {
  grid-column: 1 / -1;
}

.execution-inspector__events,
.execution-inspector__checks ol {
  display: grid;
  gap: var(--space-2);
  list-style: none;
  margin: 0;
  padding: 0;
}

.execution-inspector__events li,
.execution-inspector__checks li {
  border-left: 2px solid var(--color-border-strong);
  display: grid;
  gap: 0.15rem;
  padding-left: var(--space-2);
}

.execution-inspector__checks summary {
  color: var(--color-text-muted);
  cursor: pointer;
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-semibold);
}

.execution-inspector__checks ol {
  margin-top: var(--space-2);
}

.execution-inspector__checks li > div {
  align-items: center;
  display: flex;
  gap: var(--space-2);
}

.execution-inspector__checks p {
  color: var(--color-text-muted);
  font-size: var(--font-size-11);
  margin: 0;
}

.execution-inspector__actions {
  border-top: 1px solid var(--color-border);
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  padding-top: var(--space-3);
}

.execution-inspector__actions :is(button, a) {
  align-items: center;
  background: transparent;
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-1);
  color: var(--color-text-muted);
  display: inline-flex;
  font-size: var(--font-size-11);
  justify-content: center;
  min-height: 2.375rem;
  padding: 0 var(--space-3);
  text-decoration: none;
}

.execution-inspector__actions .execution-inspector__approval {
  border-color: var(--color-warning-border);
  color: var(--color-warning-strong);
}

.execution-inspector__empty {
  align-content: center;
  color: var(--color-text-subtle);
  display: grid;
  gap: var(--space-2);
  justify-items: center;
  min-height: 18rem;
  text-align: center;
}

.execution-inspector__empty p {
  margin: 0;
  max-width: 16rem;
}

@media (max-width: 82rem) {
  .execution-inspector {
    max-height: none;
  }
}

@media (max-width: 30rem) {
  .execution-inspector__comparison,
  .execution-inspector__facts,
  .execution-inspector__detail-grid {
    grid-template-columns: 1fr;
  }

  .context-manifest__counts,
  .context-manifest__chunks dl {
    grid-template-columns: 1fr;
  }

  .context-manifest__chunks dl > .is-wide {
    grid-column: auto;
  }

  .execution-inspector__detail-grid > .is-wide {
    grid-column: auto;
  }
}
</style>
