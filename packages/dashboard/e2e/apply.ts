import type { APIRequestContext } from '@playwright/test';

/**
 * `POST /v1/apply` for a spec. Two things can stand between the request and the change's own answer, and this handles both:
 *
 * - A change that stops a running box (pause, resize, upgrade, destroy) first gets the box ready on the server, which
 *   answers `202 { quiescing: true }` until that is done; the change is made on a later ask. This asks again, as the
 *   dashboard's client does.
 * - A change to a box runs as a job on the server (`202 { job_id }`), so this follows the job to its end and answers like
 *   the change did: `ok()` is true when it was applied, and `status()` is what it would have answered.
 *
 * A refused request (a stale plan, a missing confirmation) answers at once with its own status.
 */
export async function applyPlan(
  request: APIRequestContext,
  origin: string,
  headers: Record<string, string>,
  data: Record<string, unknown>,
): Promise<{ ok: () => boolean; status: () => number }> {
  let status = 0;
  let jobId: string | undefined;
  for (let i = 0; i < 600; i++) {
    const r = await request.post(`${origin}/v1/apply`, { headers, data });
    status = r.status();
    if (status !== 202) break;
    const body = (await r.json().catch(() => ({}))) as { quiescing?: boolean; job_id?: string };
    if (body.quiescing === true) {
      await new Promise((res) => setTimeout(res, 100));
      continue;
    }
    jobId = body.job_id;
    break;
  }
  if (status === 202 && jobId) {
    status = 0;
    for (let i = 0; i < 600 && status === 0; i++) {
      const job = (await (await request.get(`${origin}/v1/jobs/${jobId}`, { headers })).json()) as { state: string; status?: number };
      if (job.state === 'done') status = 200;
      else if (job.state === 'failed') status = job.status ?? 502;
      else await new Promise((r) => setTimeout(r, 100));
    }
    if (status === 0) status = 504;
  }
  const ok = status >= 200 && status < 300;
  return { ok: () => ok, status: () => status };
}
