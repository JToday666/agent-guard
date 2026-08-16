"""V21-06 lease store 契约测试：memory/postgres 双后端同语义（01 §31）。

参数化双后端覆盖（postgres 无环境时按 ``tests/support/postgres.py``
skip 惯例处理）：

- 消费成功 → ``remaining_uses`` 递减（行级 CAS，不碰 security_states）；
- allow_once double-spend → ``GrantUsesExhaustedError`` 拒绝；
- 同键重试 → 返回同一 token（``replayed=True``，不重复扣减）；
- 异 fingerprint 同键 → ``GrantConsumptionConflictError``（双花告警语义）；
- lease ``token_digest`` 落库、明文 token 永不落库（01 §15）；
- 失败路径结构化异常：未注册 / scope 不一致 / 过期 / 撤销 / 指纹不符；
- lease 终态转换（expired/revoked 幂等；非法 reason 拒绝）；
- 并发双花（memory 后端 8 线程抢 remaining_uses=1，轻量方式）。

C4 分层：原子性由存储层单事务（postgres）/ 单锁（memory）保证；
本测试不触 ``security_states.canonical_payload``（C5：lease 只存权威
lease store）。
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from agentguard_core.security_context.projection import (
    ConsumptionIntent,
    consumption_intent_digest,
)
from guard_api.security_state.lease_service import (
    ConsumptionIntentPayloadError,
    GrantConsumptionConflictError,
    GrantExpiredError,
    GrantFingerprintMismatchError,
    GrantNotRegisteredError,
    GrantRevokedError,
    GrantScopeMismatchError,
    GrantUsesExhaustedError,
    LeaseExpiredError,
    LeaseRevokedError,
    LeaseService,
    LeaseStoreError,
    LeaseTokenMismatchError,
    LeaseTransitionError,
    derive_lease_token_key,
    lease_token_digest,
)
from guard_api.storage.memory import MemoryControlPlaneStore
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import (
    get_test_database_url,
    reset_control_plane_schema,
)

SCOPE = "hmac-sha256:v21_06_lease_scope"
OTHER_SCOPE = "hmac-sha256:v21_06_lease_other"
GRANT_ID = "grant:v21_06_contract_fixture"
FINGERPRINT_A = "hmac-sha256:fp_a"
FINGERPRINT_B = "hmac-sha256:fp_b"
CONTROL_TOKEN = "test-control-token-v21-06"
LEASE_KEY = derive_lease_token_key(CONTROL_TOKEN)


@pytest.fixture(
    params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)]
)
def store(request):
    if request.param == "memory":
        return MemoryControlPlaneStore()
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    postgres_store = PostgresControlPlaneStore(database_url)
    postgres_store.initialize()
    return postgres_store


@pytest.fixture
def service(store) -> LeaseService:
    return LeaseService(store=store, lease_token_key=LEASE_KEY)


def seed_grant(
    store,
    *,
    grant_id: str = GRANT_ID,
    scope_digest: str = SCOPE,
    remaining_uses: int = 1,
    expires_at: str | None = None,
    fingerprint: str | None = FINGERPRINT_A,
    status: str = "active",
) -> None:
    store.seed_capability_grant_runtime(
        grant_id=grant_id,
        scope_digest=scope_digest,
        remaining_uses=remaining_uses,
        expires_at=expires_at,
        authorization_fingerprint=fingerprint,
        status=status,
    )


def make_intent(
    *,
    action_id: str = "action_1",
    fingerprint: str = FINGERPRINT_A,
    scope_digest: str = SCOPE,
    grant_id: str = GRANT_ID,
    approval_id: str = "approval:approval_1",
    runtime_binding_id: str = "binding_a",
) -> ConsumptionIntent:
    return ConsumptionIntent(
        grant_id=grant_id,
        scope_digest=scope_digest,
        action_id=action_id,
        authorization_fingerprint=fingerprint,
        approval_id=approval_id,
        runtime_binding_id=runtime_binding_id,
        intent_digest=consumption_intent_digest(
            grant_id=grant_id,
            action_id=action_id,
            authorization_fingerprint=fingerprint,
        ),
    )


def persisted_capability_text(store) -> str:
    """两后端落库内容的全量文本视图（明文 token 泄露扫描用）。"""
    if isinstance(store, MemoryControlPlaneStore):
        payload = {
            "consumptions": {
                key: value.model_dump(mode="json")
                for key, value in store.grant_consumption_records.items()
            },
            "leases": {
                key: value.model_dump(mode="json")
                for key, value in store.execution_lease_records.items()
            },
        }
        return json.dumps(payload)
    from sqlalchemy import select

    from guard_api.storage.postgres import (
        execution_leases,
        grant_consumptions,
    )

    with store._read_session() as session:  # pyright: ignore[reportPrivateUsage]
        lease_rows = session.execute(select(execution_leases)).all()
        consumption_rows = session.execute(select(grant_consumptions)).all()
    return repr(lease_rows) + repr(consumption_rows)


# ---------------------------------------------------------------------------
# 消费成功：remaining_uses 递减 + lease 签发
# ---------------------------------------------------------------------------


def test_consume_decrements_remaining_uses(store, service) -> None:
    seed_grant(store, remaining_uses=2)
    first = service.consume_grant_atomic(make_intent(action_id="action_1"))
    assert first.replayed is False
    assert first.consumption.grant_id == GRANT_ID
    assert first.lease.grant_id == GRANT_ID
    assert first.lease.status == "consumed"
    assert store.get_capability_grant_runtime(GRANT_ID)["remaining_uses"] == 1

    second = service.consume_grant_atomic(make_intent(action_id="action_2"))
    assert second.replayed is False
    assert second.consumption.consumption_id != first.consumption.consumption_id
    assert store.get_capability_grant_runtime(GRANT_ID)["remaining_uses"] == 0


def test_consume_is_scoped(store, service) -> None:
    seed_grant(store)
    result = service.consume_grant_atomic(make_intent())
    # lease 只对本 scope 可见（C5：权威 lease store 的 scope 绑定）。
    assert store.get_execution_lease(SCOPE, result.lease.lease_id) is not None
    assert store.get_execution_lease(OTHER_SCOPE, result.lease.lease_id) is None


# ---------------------------------------------------------------------------
# double-spend 拒绝（allow_once）
# ---------------------------------------------------------------------------


def test_double_spend_rejected(store, service) -> None:
    seed_grant(store, remaining_uses=1)
    service.consume_grant_atomic(make_intent(action_id="action_1"))
    with pytest.raises(GrantUsesExhaustedError) as excinfo:
        service.consume_grant_atomic(make_intent(action_id="action_2"))
    assert excinfo.value.reason_code == "v21-06:grant_uses_exhausted"
    # 拒绝路径不产生部分写入：用量仍为 0，且未落库第二个 consumption。
    assert store.get_capability_grant_runtime(GRANT_ID)["remaining_uses"] == 0
    assert "action_2" not in persisted_capability_text(store)


# ---------------------------------------------------------------------------
# 同键重试：同一 token（replayed=True）
# ---------------------------------------------------------------------------


def test_same_key_retry_returns_same_token(store, service) -> None:
    seed_grant(store, remaining_uses=1)
    first = service.consume_grant_atomic(make_intent(action_id="action_1"))
    retry = service.consume_grant_atomic(make_intent(action_id="action_1"))
    assert retry.replayed is True
    assert retry.lease_token == first.lease_token
    assert retry.consumption.consumption_id == first.consumption.consumption_id
    assert retry.lease.lease_id == first.lease.lease_id
    # 重试不重复扣减。
    assert store.get_capability_grant_runtime(GRANT_ID)["remaining_uses"] == 0


def test_same_key_retry_after_lease_expiry_rejected(store) -> None:
    seed_grant(store, remaining_uses=1)
    expired_payload = {
        **make_intent().model_dump(mode="json"),
        "issued_at": "2020-01-01T00:00:00+00:00",
        "expires_at": "2020-01-01T00:05:00+00:00",
        "lease_token": "lease-v1:fixture_expired",
    }
    store.consume_grant(SCOPE, expired_payload)
    retry_payload = {
        **expired_payload,
        "issued_at": "2020-01-02T00:00:00+00:00",
        "expires_at": "2020-01-02T00:05:00+00:00",
    }
    with pytest.raises(LeaseExpiredError) as excinfo:
        store.consume_grant(SCOPE, retry_payload)
    assert excinfo.value.reason_code == "v21-06:execution_lease_expired"


# ---------------------------------------------------------------------------
# F1：revoked/expired 终态 lease 的同键重试必须拒绝（撤销绕过修复）
# ---------------------------------------------------------------------------


def test_replay_rejects_revoked_lease(store, service) -> None:
    seed_grant(store, remaining_uses=1)
    first = service.consume_grant_atomic(make_intent(action_id="action_1"))
    # lease 被推进到 revoked 终态后，同三元身份重试不得重放。
    store.expire_or_revoke_lease(
        SCOPE, first.lease.lease_id, "revoked"
    )
    with pytest.raises(LeaseRevokedError) as excinfo:
        service.consume_grant_atomic(make_intent(action_id="action_1"))
    assert excinfo.value.reason_code == "v21-06:execution_lease_revoked"


def test_replay_rejects_expired_status_lease(store, service) -> None:
    seed_grant(store, remaining_uses=1)
    first = service.consume_grant_atomic(make_intent(action_id="action_1"))
    # status=expired 优先于 expires_at 时间戳判定（TTL 内同样拒绝）。
    store.expire_or_revoke_lease(
        SCOPE, first.lease.lease_id, "expired"
    )
    with pytest.raises(LeaseExpiredError) as excinfo:
        service.consume_grant_atomic(make_intent(action_id="action_1"))
    assert excinfo.value.reason_code == "v21-06:execution_lease_expired"


# ---------------------------------------------------------------------------
# F3：重放分支校验调用方 token 与存储 token_digest（伪造拒绝）
# ---------------------------------------------------------------------------


def test_replay_rejects_forged_lease_token(store, service) -> None:
    seed_grant(store, remaining_uses=1)
    first = service.consume_grant_atomic(make_intent(action_id="action_1"))
    forged_payload = {
        **make_intent(action_id="action_1").model_dump(mode="json"),
        "issued_at": "2026-08-15T00:00:00+00:00",
        "expires_at": "2026-08-15T00:05:00+00:00",
        "lease_token": "lease-v1:forged_token",
    }
    with pytest.raises(LeaseTokenMismatchError) as excinfo:
        store.consume_grant(SCOPE, forged_payload)
    assert excinfo.value.reason_code == "v21-06:lease_token_mismatch"
    # 伪造尝试不污染既有 lease：合法重试仍返回原 token。
    retry = service.consume_grant_atomic(make_intent(action_id="action_1"))
    assert retry.replayed is True
    assert retry.lease_token == first.lease_token


# ---------------------------------------------------------------------------
# 异 fingerprint 同键：双花告警语义
# ---------------------------------------------------------------------------


def test_different_fingerprint_same_key_conflict(store, service) -> None:
    seed_grant(store, remaining_uses=1)
    service.consume_grant_atomic(make_intent(action_id="action_1"))
    forged = make_intent(action_id="action_1", fingerprint=FINGERPRINT_B)
    with pytest.raises(GrantConsumptionConflictError) as excinfo:
        service.consume_grant_atomic(forged)
    assert excinfo.value.reason_code == "v21-06:consumption_conflict"
    # 冲突路径不扣减、不产生新 consumption。
    assert store.get_capability_grant_runtime(GRANT_ID)["remaining_uses"] == 0


# ---------------------------------------------------------------------------
# token 纪律：token_digest 落库，明文不落库
# ---------------------------------------------------------------------------


def test_lease_token_digest_stored_plaintext_not_persisted(
    store, service
) -> None:
    seed_grant(store, remaining_uses=1)
    result = service.consume_grant_atomic(make_intent())
    assert result.lease_token.startswith("lease-v1:")
    # 落库唯一形态是 token_digest（01 §15）。
    assert result.lease.token_digest == lease_token_digest(result.lease_token)
    persisted = persisted_capability_text(store)
    assert result.lease.token_digest in persisted
    assert result.lease_token not in persisted


# ---------------------------------------------------------------------------
# 失败路径结构化异常（fail-closed，不吞错、不部分提交）
# ---------------------------------------------------------------------------


def test_unregistered_grant_rejected(store, service) -> None:
    with pytest.raises(GrantNotRegisteredError) as excinfo:
        service.consume_grant_atomic(make_intent())
    assert excinfo.value.reason_code == "v21-06:grant_not_registered"


def test_scope_mismatch_rejected(store, service) -> None:
    seed_grant(store, scope_digest=OTHER_SCOPE)
    with pytest.raises(GrantScopeMismatchError) as excinfo:
        service.consume_grant_atomic(make_intent())
    assert excinfo.value.reason_code == "v21-06:grant_scope_mismatch"


def test_expired_grant_rejected_by_status_and_timestamp(
    store, service
) -> None:
    seed_grant(store, status="expired")
    with pytest.raises(GrantExpiredError):
        service.consume_grant_atomic(make_intent())
    seed_grant(
        store,
        grant_id=f"{GRANT_ID}:2",
        expires_at="2020-01-01T00:00:00Z",
    )
    with pytest.raises(GrantExpiredError) as excinfo:
        service.consume_grant_atomic(make_intent(grant_id=f"{GRANT_ID}:2"))
    assert excinfo.value.reason_code == "v21-06:grant_expired"


def test_revoked_grant_rejected(store, service) -> None:
    seed_grant(store, status="revoked")
    with pytest.raises(GrantRevokedError) as excinfo:
        service.consume_grant_atomic(make_intent())
    assert excinfo.value.reason_code == "v21-06:grant_revoked"


def test_fingerprint_mismatch_rejected(store, service) -> None:
    seed_grant(store, fingerprint=FINGERPRINT_A)
    forged = make_intent(action_id="action_1", fingerprint=FINGERPRINT_B)
    with pytest.raises(GrantFingerprintMismatchError) as excinfo:
        service.consume_grant_atomic(forged)
    assert excinfo.value.reason_code == "v21-06:grant_fingerprint_mismatch"
    # 拒绝路径不扣减。
    assert store.get_capability_grant_runtime(GRANT_ID)["remaining_uses"] == 1


def test_invalid_intent_payload_fails_closed(store) -> None:
    seed_grant(store)
    payload = make_intent().model_dump(mode="json")
    payload.pop("authorization_fingerprint")
    with pytest.raises(ConsumptionIntentPayloadError) as excinfo:
        store.consume_grant(SCOPE, payload)
    assert excinfo.value.reason_code == "v21-06:invalid_intent_payload"


# ---------------------------------------------------------------------------
# lease 读取与终态转换
# ---------------------------------------------------------------------------


def test_get_execution_lease_by_id_and_token_digest(store, service) -> None:
    seed_grant(store)
    result = service.consume_grant_atomic(make_intent())
    by_id = store.get_execution_lease(SCOPE, result.lease.lease_id)
    by_digest = store.get_execution_lease(
        SCOPE, lease_token_digest(result.lease_token)
    )
    assert by_id is not None and by_digest is not None
    assert by_id.lease_id == by_digest.lease_id == result.lease.lease_id
    assert store.get_execution_lease(SCOPE, "lease:missing") is None


def test_expire_or_revoke_lease_transitions(store, service) -> None:
    seed_grant(store, grant_id=f"{GRANT_ID}:expire")
    expired_result = service.consume_grant_atomic(
        make_intent(grant_id=f"{GRANT_ID}:expire", action_id="action_e")
    )
    updated = store.expire_or_revoke_lease(
        SCOPE, expired_result.lease.lease_id, "expired"
    )
    assert updated.status == "expired"
    # 幂等：重复推进同一终态返回既有记录。
    again = store.expire_or_revoke_lease(
        SCOPE, expired_result.lease.lease_id, "expired"
    )
    assert again.status == "expired"

    seed_grant(store, grant_id=f"{GRANT_ID}:revoke")
    revoked_result = service.consume_grant_atomic(
        make_intent(grant_id=f"{GRANT_ID}:revoke", action_id="action_r")
    )
    revoked = store.expire_or_revoke_lease(
        SCOPE, revoked_result.lease.lease_id, "revoked"
    )
    assert revoked.status == "revoked"


def test_expire_or_revoke_lease_invalid_inputs(store, service) -> None:
    seed_grant(store)
    result = service.consume_grant_atomic(make_intent())
    with pytest.raises(LeaseTransitionError) as excinfo:
        store.expire_or_revoke_lease(SCOPE, result.lease.lease_id, "drained")
    assert (
        excinfo.value.reason_code == "v21-06:unsupported_lease_transition"
    )
    with pytest.raises(KeyError):
        store.expire_or_revoke_lease(SCOPE, "lease:missing", "expired")
    # 异 scope 视同不存在。
    with pytest.raises(KeyError):
        store.expire_or_revoke_lease(
            OTHER_SCOPE, result.lease.lease_id, "expired"
        )


def test_invalid_reason_precedes_terminal_state_lookup(store) -> None:
    # F9：双后端错误优先级统一 —— 先验 reason 合法性再查终态，
    # 非法 reason + 不存在的 lease 仍报 LeaseTransitionError（非 KeyError）。
    with pytest.raises(LeaseTransitionError) as excinfo:
        store.expire_or_revoke_lease(SCOPE, "lease:missing", "drained")
    assert (
        excinfo.value.reason_code == "v21-06:unsupported_lease_transition"
    )


def test_lease_errors_are_structured() -> None:
    # 结构化异常层次：全部携带 v21-06: reason_code 前缀。
    error = LeaseStoreError("v21-06:fixture", "fixture message")
    assert isinstance(error, Exception)
    assert error.reason_code.startswith("v21-06:")


# ---------------------------------------------------------------------------
# 并发双花（memory 后端，轻量 8 线程；不做大规模压测）
# ---------------------------------------------------------------------------


def test_concurrent_double_spend_single_winner_memory() -> None:
    store = MemoryControlPlaneStore()
    seed_grant(store, remaining_uses=1)
    service = LeaseService(store=store, lease_token_key=LEASE_KEY)
    intents = [
        make_intent(action_id=f"action_race_{index}") for index in range(8)
    ]

    def attempt(intent: ConsumptionIntent):
        try:
            return service.consume_grant_atomic(intent)
        except LeaseStoreError as error:
            return error

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, intents))

    successes = [item for item in outcomes if not isinstance(item, Exception)]
    failures = [item for item in outcomes if isinstance(item, Exception)]
    assert len(successes) == 1
    assert len(failures) == 7
    assert all(
        isinstance(item, GrantUsesExhaustedError) for item in failures
    )
    assert store.get_capability_grant_runtime(GRANT_ID)["remaining_uses"] == 0
    assert len(store.grant_consumption_records) == 1
