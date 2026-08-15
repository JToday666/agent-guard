"""V2.1 semantic judgment models (07 §2 target layout).

Core 侧只承载冻结模型与 binding 校验纯函数（V21-09）；provider /
prompt / LLM 调用属 V21-13 职责，Core 不引入任何网络 IO。
"""

from .models import SemanticJudgment

__all__ = ["SemanticJudgment"]
