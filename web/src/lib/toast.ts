import { writable } from 'svelte/store';

export type ToastVariant = 'success' | 'error' | 'info';

export type Toast = {
  id: number;
  message: string;
  variant: ToastVariant;
  duration: number;
};

let nextId = 1;

export const toasts = writable<Toast[]>([]);

export function pushToast(message: string, variant: ToastVariant = 'info', duration = 3200) {
  if (!message) return;
  const id = nextId++;
  toasts.update((items) => [...items, { id, message, variant, duration }]);
  if (duration > 0) {
    setTimeout(() => dismissToast(id), duration);
  }
  return id;
}

export function dismissToast(id: number) {
  toasts.update((items) => items.filter((item) => item.id !== id));
}

export const toast = {
  success: (message: string, duration?: number) => pushToast(message, 'success', duration),
  error: (message: string, duration?: number) => pushToast(message, 'error', duration ?? 4500),
  info: (message: string, duration?: number) => pushToast(message, 'info', duration)
};
