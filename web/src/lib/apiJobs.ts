type ApiJobStatus<T> = {
  ok: number;
  job_id?: string;
  state?: 'running' | 'done';
  result?: T | null;
  error?: string;
};

const delay = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

export async function waitApiJob<T = Record<string, unknown>>(
  jobId: string,
  options: { intervalMs?: number; timeoutMs?: number } = {}
): Promise<T> {
  const intervalMs = options.intervalMs ?? 900;
  const timeoutMs = options.timeoutMs ?? 180000;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() <= deadline) {
    const response = await fetch(`/api/jobs?id=${encodeURIComponent(jobId)}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const status = (await response.json()) as ApiJobStatus<T>;
    if (!status.ok) throw new Error(status.error || '后台任务不存在');
    if (status.state === 'done') {
      if (status.result == null) throw new Error('后台任务没有返回结果');
      return status.result;
    }
    await delay(intervalMs);
  }

  throw new Error('后台任务执行超时');
}
