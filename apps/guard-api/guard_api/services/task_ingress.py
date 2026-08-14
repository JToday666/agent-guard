"""V21-03 Task Ingress 服务：task:write 专用任务入口（01 §30, L1185-1229）。

服务端职责：

- ``task_id/revision/task_digest/scope_digest`` 一律服务端生成，请求体不得
  携带（``TaskCreateRequest`` extra="forbid" 结构性拒绝）；
- ``runtime_binding_id`` 服务端派生自已认证身份，请求体自报值仅作一致性
  校验（不一致即 RUNTIME_IDENTITY_MISMATCH，01 §4）；
- ``scope_digest`` / ``task_digest`` 统一走 core ``authority`` 受限 JCS
  digest 口径（01 §29）；
- 修订采用 ``(expected_revision, canonical request digest)`` 表驱动幂等：
  历史记录命中即返回原修订；锚点落后或同 revision 异内容由存储层 CAS
  拒绝（TaskRevisionConflictError → 409）。

本服务不触碰判定路径：不修改 evaluate / GuardEvent / SecurityContext。
"""

from __future__ import annotations

from dataclasses import dataclass

from agentguard_core import new_id, utc_now_iso
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.authority import (
    SecurityStateScope,
    TaskFact,
    canonical_constraints_projection,
    scope_digest_projection,
    task_digest_projection,
)

from guard_api.auth import ApiAuthError, AuthContext
from guard_api.models import (
    TaskCreateRequest,
    TaskIngressResponse,
    TaskReviseRequest,
)
from guard_api.settings import GuardApiSettings
from guard_api.storage.base import (
    ControlPlaneStore,
    TaskFactRecord,
    TaskRevisionConflictError,
)

__all__ = ["TaskIngressService"]

#: task_digest 白名单不含 task_digest 自身，占位值不进入摘要。
_PENDING_TASK_DIGEST = "sha256:pending-server-computation"


@dataclass(frozen=True, slots=True)
class TaskIngressService:
    """Authenticated Task Ingress（V21-03 第二阶段）。"""

    store: ControlPlaneStore
    settings: GuardApiSettings

    def create_task(
        self, request: TaskCreateRequest, auth_context: AuthContext
    ) -> TaskIngressResponse:
        binding_id = self._verify_runtime_binding(request, auth_context)
        scope = self._build_scope(request, auth_context, binding_id)
        scope_key_id = self.settings.task_scope_active_key_id
        assert scope_key_id is not None
        task_fact = self._build_task_fact(
            task_id=new_id("task"),
            revision=1,
            scope=scope,
            scope_key_id=scope_key_id,
            request=request,
        )
        record = TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest=_canonical_request_digest(request),
            expected_revision=0,
            created_at=utc_now_iso(),
        )
        self.store.create_task_fact(record)
        return _ingress_response(task_fact)

    def revise_task(
        self, task_id: str, request: TaskReviseRequest, auth_context: AuthContext
    ) -> TaskIngressResponse:
        history = self.store.list_task_fact_revisions(task_id)
        if not history:
            raise ApiAuthError("TASK_NOT_FOUND", status_code=404)
        head = history[-1]
        if head.task_fact.principal_id != auth_context.principal_id:
            # 防跨 principal 篡改：任务绑定 principal 与已认证身份不一致即拒绝。
            raise ApiAuthError("TASK_PRINCIPAL_MISMATCH", status_code=403)
        binding_id = self._verify_runtime_binding(request, auth_context)
        request_digest = _canonical_request_digest(request)
        # 表驱动幂等：历史中存在 (expected_revision, request_digest) 完全相同
        # 的记录即视为同一修订的重放，直接返回原修订。
        replay = _find_idempotent_replay(
            history,
            expected_revision=request.expected_revision,
            request_digest=request_digest,
        )
        if replay is not None:
            return _ingress_response(replay.task_fact)
        head_revision = head.task_fact.revision
        if request.expected_revision != head_revision:
            raise TaskRevisionConflictError(
                expected_revision=request.expected_revision,
                current_revision=head_revision,
            )
        scope = self._build_scope(request, auth_context, binding_id)
        scope_key_id = self.settings.task_scope_active_key_id
        assert scope_key_id is not None
        task_fact = self._build_task_fact(
            task_id=task_id,
            revision=head_revision + 1,
            scope=scope,
            scope_key_id=scope_key_id,
            request=request,
        )
        record = TaskFactRecord(
            task_fact=task_fact,
            canonical_payload=task_fact.model_dump(mode="json"),
            request_digest=request_digest,
            expected_revision=head_revision,
            created_at=utc_now_iso(),
        )
        try:
            self.store.create_task_fact(record)
        except TaskRevisionConflictError:
            # 两个相同 PUT 可同时通过锁外预读；CAS 失败后必须重读锁内
            # 已提交结果并按幂等键判定，等价重试返回原修订而不是 409。
            replay = _find_idempotent_replay(
                self.store.list_task_fact_revisions(task_id),
                expected_revision=request.expected_revision,
                request_digest=request_digest,
            )
            if replay is not None:
                return _ingress_response(replay.task_fact)
            raise
        return _ingress_response(task_fact)

    def _verify_runtime_binding(
        self, request: TaskCreateRequest, auth_context: AuthContext
    ) -> str:
        """服务端派生 runtime_binding_id；自报值仅作一致性校验（01 §4）。

        任何路径绝不采纳请求体自报的 ``runtime_binding_id``：冻结语义要求
        它必须来自 Guard API 已认证绑定，自报值只能与服务端派生值比对。

        - 携带已认证 runtime 身份的凭据：``request.runtime`` 必须与
          ``auth_context.runtime`` 一致（否则 403），binding 派生为
          ``binding:{principal_id}``；
        - control token（无已认证 runtime 身份）：``request.runtime``
          允许作为 scope 维度数据，binding 固定派生为
          ``binding:control:{principal_id}``。

        当前为过渡形态，runtime 维度尚无服务端绑定注册表，后续 runtime
        binding registry 落地后须替换为注册产生的 binding_id。
        """

        if auth_context.runtime is not None:
            if request.runtime != auth_context.runtime:
                # request.runtime 自报进 scope 稳定身份白名单，必须锚定
                # 已认证 runtime，不得为任意声称的 runtime 铸造 scope。
                raise ApiAuthError("RUNTIME_IDENTITY_MISMATCH", status_code=403)
            binding_id = f"binding:{auth_context.principal_id}"
        else:
            binding_id = f"binding:control:{auth_context.principal_id}"
        if (
            request.runtime_binding_id is not None
            and request.runtime_binding_id != binding_id
        ):
            raise ApiAuthError("RUNTIME_IDENTITY_MISMATCH", status_code=403)
        return binding_id

    def _build_scope(
        self,
        request: TaskCreateRequest,
        auth_context: AuthContext,
        binding_id: str,
    ) -> SecurityStateScope:
        partial = SecurityStateScope(
            principal_id=auth_context.principal_id,
            runtime=request.runtime,
            runtime_binding_id=binding_id,
            trace_id=request.trace_id,
            session_id=request.session_id,
            scope_digest="",
        )
        digest = scope_digest_projection(
            partial, server_key=self.settings.task_scope_signing_key()
        )
        return partial.model_copy(update={"scope_digest": digest})

    def _build_task_fact(
        self,
        *,
        task_id: str,
        revision: int,
        scope: SecurityStateScope,
        scope_key_id: str,
        request: TaskCreateRequest,
    ) -> TaskFact:
        pending = TaskFact(
            task_id=task_id,
            scope_digest=scope.scope_digest,
            scope_key_id=scope_key_id,
            principal_id=scope.principal_id,
            task_summary=request.task_text,
            task_digest=_PENDING_TASK_DIGEST,
            revision=revision,
            status="active",
            action_constraints=list(request.action_constraints),
            resource_constraints=list(request.resource_constraints),
            destination_constraints=list(request.destination_constraints),
            created_sequence=None,
            producer="guard_api_task_ingress",
            authority="authoritative",
            evidence_refs=[],
        )
        return pending.model_copy(
            update={"task_digest": task_digest_projection(pending)}
        )


def _canonical_request_digest(request: TaskCreateRequest) -> str:
    """入口请求内容字段的受限 JCS sha256（幂等重放键的一半）。

    ``expected_revision`` 不进入投影：它与本 digest 组成二元幂等键
    （01 §30）。约束及其成员是集合语义，先去重并稳定排序（01 §29）。
    """

    projection = {
        "task_text": request.task_text,
        "runtime": request.runtime,
        "runtime_binding_id": request.runtime_binding_id,
        "trace_id": request.trace_id,
        "session_id": request.session_id,
        **canonical_constraints_projection(
            action_constraints=request.action_constraints,
            resource_constraints=request.resource_constraints,
            destination_constraints=request.destination_constraints,
        ),
    }
    return canonical_sha256(projection)


def _find_idempotent_replay(
    history: list[TaskFactRecord],
    *,
    expected_revision: int,
    request_digest: str,
) -> TaskFactRecord | None:
    for record in history:
        if (
            record.expected_revision == expected_revision
            and record.request_digest == request_digest
        ):
            return record
    return None


def _ingress_response(task_fact: TaskFact) -> TaskIngressResponse:
    return TaskIngressResponse(
        task_id=task_fact.task_id,
        revision=task_fact.revision,
        task_digest=task_fact.task_digest,
        scope_digest=task_fact.scope_digest,
        status=task_fact.status,
    )
