<script setup>
import { computed, provide, reactive } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { LayoutDashboard, ListTodo, Plus, RadioTower } from '@lucide/vue';
import { autofuzzKey } from './appContext';
import { useAutofuzzController } from './composables/useAutofuzz';
import CreateTaskModal from './components/CreateTaskModal.vue';

const route = useRoute();
const router = useRouter();
const ui = reactive(useAutofuzzController());
provide(autofuzzKey, ui);

const activeView = computed(() => {
  if (route.name === 'task-detail' || route.name === 'driver-coverage' || route.name === 'driver-coverage-latest') return 'detail';
  return route.name || 'dashboard';
});

function navigate(name) {
  if (name === 'detail' && ui.detail.id) {
    router.push({name: 'task-detail', params: {taskId: ui.detail.id, tab: ui.detail.activeTab || 'overview'}});
    return;
  }
  router.push({name});
}
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar" aria-label="主导航">
      <div class="side-brand">
        <div class="logo">AF</div>
        <div class="brand-copy"><strong>Autofuzz</strong><span>Fuzz orchestration</span></div>
      </div>
      <nav class="side-nav">
        <button class="nav-item" :class="{active: activeView === 'dashboard'}" type="button" @click="navigate('dashboard')">
          <LayoutDashboard :size="18" aria-hidden="true" />
          <span>运行看板</span>
        </button>
        <button class="nav-item" :class="{active: activeView === 'tasks'}" type="button" @click="navigate('tasks')">
          <ListTodo :size="18" aria-hidden="true" />
          <span>任务</span>
          <span class="nav-count">{{ ui.taskCounts.total }}</span>
        </button>
        <button v-if="ui.hasTaskDetail" class="nav-item" :class="{active: activeView === 'detail'}" type="button" @click="navigate('detail')">
          <RadioTower :size="18" aria-hidden="true" />
          <span>任务详情</span>
        </button>
      </nav>
      <div class="side-footer"><strong>{{ ui.runningSidebarLabel }}</strong><span>本地任务运行状态</span></div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <div>
          <h1>{{ ui.topbarTitle }}</h1>
          <p>{{ ui.topbarSubtitle }}</p>
        </div>
        <button class="primary command-button" type="button" @click="ui.openCreateModal">
          <Plus :size="17" aria-hidden="true" />
          <span>创建 Task</span>
        </button>
      </header>
      <RouterView />
    </main>
  </div>

  <CreateTaskModal />
</template>
