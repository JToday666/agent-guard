"""随包分发的契约数据（package data）。

当前仅含 ``fusion_matrix.yaml``：冻结 fusion 矩阵的包内副本，与仓库
``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/fusion_matrix.yaml``
冻结真值逐字节一致（一致性测试防漂移），保证 wheel 安装（如 Dockerfile
部署，不含仓库 docs 目录）下 ``load_fusion_matrix()`` 可用。
"""
