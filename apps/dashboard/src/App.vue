<script setup lang="ts">
import { useDashboardStore } from "@/stores/dashboard";

const dashboard = useDashboardStore();
</script>

<template>
  <main class="dashboard-shell" aria-labelledby="dashboard-title">
    <header class="dashboard-header">
      <p class="dashboard-kicker">AgentGuard</p>
      <h1 id="dashboard-title">Dashboard</h1>
    </header>

    <section class="section-grid" aria-label="Dashboard sections">
      <article
        v-for="section in dashboard.sections"
        :key="section.id"
        class="section-card"
      >
        <h2>{{ section.label }}</h2>
        <p>{{ section.status }}</p>
      </article>
    </section>
  </main>
</template>
