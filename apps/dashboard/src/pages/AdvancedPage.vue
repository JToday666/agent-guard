<template>
  <section class="advanced-page workspace-panel" aria-labelledby="advanced-title">
    <header class="page-header">
      <div>
        <p>运维</p>
        <h1 id="advanced-title">高级</h1>
      </div>
      <StatusBadge label="部分数据" tone="neutral" />
    </header>

    <div class="advanced-grid">
      <section class="content-section">
        <h2>OpenClaw Hook</h2>
        <p>before_tool_call 已连接。</p>
        <RouterLink to="/events?runtime=openclaw">OpenClaw 事件</RouterLink>
      </section>

      <section class="content-section">
        <h2>Memory Guard</h2>
        <p>长期记忆写入需要按风险状态确认。</p>
        <RouterLink to="/traces?event_type=memory_write">记忆风险</RouterLink>
      </section>

      <section class="content-section">
        <h2>配置审计</h2>
        <p>适配器异常会进入事件流并保留关联链路。</p>
        <RouterLink to="/events?type=adapter_error">查看适配器事件</RouterLink>
      </section>

      <section class="content-section">
        <h2>审计完整性</h2>
        <p>系统状态展示审计写入、审批队列和最近事件时间。</p>
        <RouterLink to="/system">查看系统状态</RouterLink>
      </section>
    </div>
  </section>
</template>

<script setup lang="ts">
import StatusBadge from "../components/StatusBadge.vue";

defineOptions({
  name: "AdvancedPage",
});
</script>

<style scoped lang="scss">
.advanced-page {
  display: grid;
  gap: var(--space-5);
}

.advanced-grid {
  display: grid;
  gap: var(--space-4);
  grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));
}

.content-section {
  align-content: start;
  min-height: 11rem;

  p {
    color: var(--color-text-muted);
    margin: 0;
    overflow-wrap: anywhere;
  }
}
</style>
