"""unique policy evaluation audit per event id

Revision ID: 0007_policy_eval_unique_event
Revises: 0006_terminal_registry
Create Date: 2026-08-08

契约依据：evidence_trace_api_contract.md §10（policy_evaluation 仅由
POST /v1/guard/evaluate 内部唯一写入）与 §11.4 请求级幂等语义。
evaluation.py 的历史注释也指出多 worker 部署前必须为策略评估建立
event_id 唯一索引；本迁移把该约束落到 PostgreSQL 存储层。
revision ID 受 alembic_version.version_num VARCHAR(32) 约束，
故缩写为 policy_eval。
"""

from __future__ import annotations

from alembic import op
from sqlalchemy import text

revision = "0007_policy_eval_unique_event"
down_revision = "0006_terminal_registry"
branch_labels = None
depends_on = None

INDEX_NAME = "ux_audit_policy_evaluation_event_id"

# 与部分唯一索引谓词完全一致的诊断查询：提前发现存量重复，
# 避免 CREATE UNIQUE INDEX 以难以定位的方式失败。
_DUPLICATE_DIAGNOSIS = text(
    """
    SELECT payload_json->'links'->>'event_id' AS event_id,
           COUNT(*) AS record_count
    FROM audit_events
    WHERE payload_json->>'record_type' = 'policy_evaluation'
      AND payload_json->'links'->>'event_id' IS NOT NULL
    GROUP BY payload_json->'links'->>'event_id'
    HAVING COUNT(*) > 1
    ORDER BY event_id
    """
)


def upgrade() -> None:
    bind = op.get_bind()
    duplicates = bind.execute(_DUPLICATE_DIAGNOSIS).all()
    if duplicates:
        listing = ", ".join(
            f"{row.event_id} (x{row.record_count})" for row in duplicates
        )
        # 存量重复必须由人工裁决：删行会破坏审计哈希链，绝不自动清理。
        # 事务回滚后不留任何半态（索引未创建）。
        raise RuntimeError(
            "migration 0007 aborted: duplicate policy_evaluation records "
            f"share the same links.event_id: {listing}"
        )
    op.execute(
        text(
            f"""
            CREATE UNIQUE INDEX {INDEX_NAME}
            ON audit_events ((payload_json->'links'->>'event_id'))
            WHERE payload_json->>'record_type' = 'policy_evaluation'
              AND payload_json->'links'->>'event_id' IS NOT NULL
            """
        )
    )


def downgrade() -> None:
    op.execute(text(f"DROP INDEX IF EXISTS {INDEX_NAME}"))
