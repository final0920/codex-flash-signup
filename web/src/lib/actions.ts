export function overflowDetect(node: HTMLElement) {
  const parent = node.closest('.log-item') as HTMLElement | null;
  if (!parent) return;

  function check() {
    if (node.scrollWidth > node.clientWidth) {
      parent!.setAttribute('data-overflow', '');
    } else {
      parent!.removeAttribute('data-overflow');
    }
  }

  const observer = new ResizeObserver(check);
  observer.observe(node);
  check();

  return {
    destroy() {
      observer.disconnect();
    }
  };
}
