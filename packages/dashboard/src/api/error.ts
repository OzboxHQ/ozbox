export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** What to do about it, when the server says. */
  readonly fix: string | null;
  /** Every field of the server's error body, for the few screens that say a refusal in their own words. */
  readonly details: Readonly<Record<string, unknown>>;
  constructor(status: number, code: string, message: string, fix: string | null = null, details: Readonly<Record<string, unknown>> = {}) {
    super(message);
    this.fix = fix;
    this.details = details;
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export async function errorFrom(res: Response): Promise<ApiError> {
  let code = 'error';
  let fix: string | null = null;
  let message = `The request failed (HTTP ${res.status}).`;
  let details: Record<string, unknown> = {};
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object') {
      // `{error:{code,message}}` (the approval routes' contract) is read like the flat shape the other routes send
      const nested = (body as Record<string, unknown>)['error'];
      const b = nested && typeof nested === 'object' ? { ...(body as Record<string, unknown>), ...(nested as Record<string, unknown>), error: undefined } : (body as Record<string, unknown>);
      if (typeof b['error'] === 'string') message = b['error'];
      if (typeof b['message'] === 'string') message = b['message'];
      if (typeof b['code'] === 'string') code = b['code'];
      if (typeof b['fix'] === 'string') fix = b['fix'];
      details = b;
    }
  } catch {
    // keep the generic message
  }
  return new ApiError(res.status, code, message, fix, details);
}
