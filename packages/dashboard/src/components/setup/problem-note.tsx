import { Alert, AlertDescription } from '@/components/ui/alert';
import { ApiError } from '../../api/error';
import type { Problem } from '../../lib/setup-flow';
import { t } from '../../lib/i18n';

export function toProblem(e: unknown): Problem {
  if (e instanceof ApiError) return { code: e.code, message: e.message, fix: e.fix };
  return { code: 'error', message: t('setup.failed'), fix: null };
}

/** A refusal or failure: what happened, and what to do. The code is stable; the sentence is for a person. */
export function ProblemNote({ problem }: { problem: Problem }) {
  return (
    <Alert variant="destructive" data-testid="problem" data-code={problem.code}>
      <AlertDescription className="space-y-1">
        <p>{problem.message}</p>
        {problem.fix ? <p className="font-medium">{t('flow.fix', { fix: problem.fix })}</p> : null}
      </AlertDescription>
    </Alert>
  );
}
