import { inject } from 'vue';

export const autofuzzKey = Symbol('autofuzz');

export function useAutofuzz() {
  const controller = inject(autofuzzKey);
  if (!controller) throw new Error('Autofuzz controller is unavailable');
  return controller;
}
