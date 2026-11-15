import { useEffect, useReducer, useState } from 'react';

import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import type { CheckKind, SetupProvider, SetupTarget } from '../../api/setup';
import { useApp } from '../../App';
import { openFlow } from '../../lib/flows';
import { t, type MessageKey } from '../../lib/i18n';
import { canContinue, fromCheck, initialState, setupReducer, stepNumber, type SetupState, type StepId } from '../../lib/setup-flow';
import { useAsync } from '../../lib/use-async';
import { ProblemNote, toProblem } from './problem-note';
import { GuardrailsStep, LocaleStep, PermissionsStep, PlanStep, ProviderStep, RegionStep, SecurityStep, SignInStep } from './setup-steps';

const TITLES: Record<StepId, MessageKey> = {
  provider: 'setup.step_provider',
  sign_in: 'setup.step_sign_in',
  permissions: 'setup.step_permissions',
  region: 'setup.step_region',
  bucket: 'setup.step_bucket',
  network: 'setup.step_network',
  guardrails: 'setup.step_guardrails',
  locale: 'setup.step_locale',
  security: 'setup.step_security',
  done: 'setup.done_title',
};

function targetOf(s: SetupState): SetupTarget {
  return { provider: s.provider ?? 'fake', profile: s.profile.trim() === '' ? null : s.profile.trim(), region: s.region === '' ? null : s.region };
}

/** "Set up your fleet": the same steps as `ozbox init`. Every step that changes something shows its plan first. */
export function SetupSheet({ open, initialProvider, onClose }: { open: boolean; initialProvider: SetupProvider | null; onClose: () => void }) {
  const { client } = useApp();
  const [s, dispatch] = useReducer(setupReducer, initialState);
  const [locations, setLocations] = useState<string[]>([]);
  const [restart, setRestart] = useState(false);
  const status = useAsync((sig) => client.setup.status(sig), [client, open], undefined);

  useEffect(() => {
    if (open) {
      dispatch({ type: 'reset' });
      if (initialProvider) dispatch({ type: 'provider', provider: initialProvider });
    }
  }, [open, initialProvider]);

  async function check(kind: CheckKind) {
    dispatch({ type: 'busy' });
    try {
      const r = await client.setup.check(kind, targetOf(s));
      if (kind === 'sign_in' && r.locations) setLocations(r.locations);
      dispatch(fromCheck(kind, r));
    } catch (e) {
      dispatch({ type: 'failed', problem: toProblem(e) });
    }
  }
  async function plan(which: 'bucket' | 'network') {
    dispatch({ type: 'planning', which });
    try {
      dispatch({ type: 'planned', which, plan: await client.setup.plan(which === 'bucket' ? 'state_bucket' : 'network', targetOf(s)) });
    } catch (e) {
      dispatch({ type: 'failed', problem: toProblem(e) });
    }
  }
  async function apply(which: 'bucket' | 'network') {
    const phase = s[which];
    if (phase.phase !== 'review') return;
    dispatch({ type: 'apply', which });
    try {
      await client.setup.apply(phase.plan.plan_id);
      dispatch({ type: 'applied', which });
    } catch (e) {
      dispatch({ type: 'failed', problem: toProblem(e) });
    }
  }
  async function finish() {
    dispatch({ type: 'busy' });
    try {
      const r = s.provider === 'fake' ? await client.setup.sandbox() : await client.setup.finish(targetOf(s), s.mfaAck);
      setRestart(r.restart_required);
      dispatch({ type: 'finished' });
      window.dispatchEvent(new Event('ozbox:changed'));
    } catch (e) {
      dispatch({ type: 'failed', problem: toProblem(e) });
    }
  }

  const { n, of } = stepNumber(s);
  const last = s.step !== 'done' && (s.provider === 'fake' ? s.step === 'locale' : s.step === 'security');
  const body = (() => {
    switch (s.step) {
      case 'provider':
        return <ProviderStep s={s} dispatch={dispatch} />;
      case 'sign_in':
        return <SignInStep s={s} dispatch={dispatch} onCheck={() => check('sign_in')} hcloudToken={status.data?.hcloud_token_present === true} />;
      case 'permissions':
        return <PermissionsStep s={s} onCheck={() => check('permissions')} />;
      case 'region':
        return <RegionStep s={s} dispatch={dispatch} onMeasure={() => check('regions')} locations={locations} />;
      case 'bucket':
        return <PlanStep which="bucket" phase={s.bucket} how={t('setup.bucket_how')} onPlan={() => plan('bucket')} onApply={() => apply('bucket')} />;
      case 'network':
        return <PlanStep which="network" phase={s.network} how={t('setup.network_how')} onPlan={() => plan('network')} onApply={() => apply('network')} />;
      case 'guardrails':
        return <GuardrailsStep dispatch={dispatch} />;
      case 'locale':
        return <LocaleStep dispatch={dispatch} />;
      case 'security':
        return <SecurityStep s={s} dispatch={dispatch} onRun={() => check('security')} />;
      case 'done':
        return (
          <div className="space-y-3" data-testid="setup-done">
            <p className="text-sm">{s.provider === 'fake' ? t('setup.done_fake') : t('setup.done_real')}</p>
            {restart && (
              <p role="status" className="text-sm font-medium">
                {t('setup.done_restart')}
              </p>
            )}
          </div>
        );
    }
  })();

  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && !s.busy && onClose()}>
      <PanelSheetContent size="wide" data-testid="setup-sheet" onEscapeKeyDown={(e) => s.busy && e.preventDefault()} onInteractOutside={(e) => e.preventDefault()}>
        <PanelSheetHeader>
          <PanelSheetTitle>{t('setup.title')}</PanelSheetTitle>
          <PanelSheetDescription>{s.step === 'provider' ? t('setup.desc') : s.step === 'done' ? ' ' : t('flow.step_of', { n, of })}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          <h2 className="text-base font-semibold" data-testid="setup-step-title">
            {t(TITLES[s.step])}
          </h2>
          {body}
          {s.problem && <ProblemNote problem={s.problem} />}
        </PanelSheetBody>
        <PanelSheetFooter>
          {s.step === 'done' ? (
            <>
              <Button type="button" variant="outline" onClick={onClose}>
                {t('setup.done_close')}
              </Button>
              <Button
                type="button"
                onClick={() => {
                  onClose();
                  openFlow('create');
                }}
              >
                {t('setup.done_create')}
              </Button>
            </>
          ) : (
            <>
              <Button type="button" variant="outline" disabled={s.busy || s.step === 'provider'} onClick={() => dispatch({ type: 'back' })}>
                {t('flow.back')}
              </Button>
              {last ? (
                <Button type="button" disabled={!canContinue(s) || s.busy} onClick={finish} data-testid="setup-finish">
                  {s.busy ? t('setup.finishing') : t('setup.finish')}
                </Button>
              ) : (
                <Button type="button" disabled={!canContinue(s)} onClick={() => dispatch({ type: 'next' })} data-testid="setup-continue">
                  {t('flow.continue')}
                </Button>
              )}
            </>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
