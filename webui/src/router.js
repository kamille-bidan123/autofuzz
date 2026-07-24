import { createRouter, createWebHashHistory } from 'vue-router';

const routes = [
  {path: '/', redirect: '/dashboard'},
  {
    path: '/dashboard',
    name: 'dashboard',
    component: () => import('./views/DashboardView.vue')
  },
  {
    path: '/tasks',
    name: 'tasks',
    component: () => import('./views/TasksView.vue')
  },
  {
    path: '/tasks/:taskId/coverage/drivers/:driverId(\\d+)/versions/:seq(\\d+)',
    name: 'driver-coverage',
    component: () => import('./views/TaskDetailView.vue'),
    props: true
  },
  {
    path: '/tasks/:taskId/coverage/drivers/:driverId(\\d+)',
    name: 'driver-coverage-latest',
    component: () => import('./views/TaskDetailView.vue'),
    props: true
  },
  {
    path: '/tasks/:taskId/:tab(overview|coverage|crashes|snapshots|codex|logs)?',
    name: 'task-detail',
    component: () => import('./views/TaskDetailView.vue'),
    props: true
  },
  {path: '/:pathMatch(.*)*', redirect: '/dashboard'}
];

export default createRouter({
  history: createWebHashHistory(),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) return savedPosition;
    if (to.fullPath !== from.fullPath) return {top: 0};
    return undefined;
  }
});
