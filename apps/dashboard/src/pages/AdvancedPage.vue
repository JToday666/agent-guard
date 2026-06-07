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
        <p>当前配置存在部分待检查项。</p>
        <button type="button">查看配置风险</button>
      </section>

      <section class="content-section">
        <h2>审计完整性</h2>
        <p>审计链状态为 partial。</p>
        <button type="button">查看完整性状态</button>
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
