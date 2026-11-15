import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import type { Info } from '../api/types';
import { fleetNotConnected, isDemo, showsFleetNotice } from '../lib/fleet';
import { t } from '../lib/i18n';
import type { Route } from '../lib/router';

/** Every page of a dashboard that runs on the simulated provider carries this, so demo data is never taken for real. One line at any width (a longer line is cut, its full text is the tooltip), so it never pushes a page's main action below the fold. */
export function DemoBanner() {
  return (
    <div role="status" data-testid="demo-banner" title={`${t('fleetnote.demo_title')}. ${t('fleetnote.demo_body')}`} className="truncate rounded-md border border-amber-600/50 bg-amber-50 px-3 py-1.5 text-xs text-amber-950 dark:border-amber-400/50 dark:bg-amber-950/40 dark:text-amber-100">
      <span className="font-semibold">{t('fleetnote.demo_title')}</span>
      <span className="ml-2">{t('fleetnote.demo_body')}</span>
    </div>
  );
}

/** What a box's own dashboard says where a fleet would appear: honest, and what to do. */
export function FleetNotConnectedNotice({ info }: { info: Info | null }) {
  const docs = info?.fleet?.docs;
  return (
    <div role="status" data-testid="fleet-not-connected" className="rounded-md border bg-muted/50 px-3 py-2 text-sm">
      <p className="font-semibold">{t('fleetnote.nc_title')}</p>
      <p className="mt-0.5">{t('fleetnote.nc_body')}</p>
      {docs ? <p className="mt-0.5 text-muted-foreground">{t('fleetnote.nc_docs', { docs })}</p> : null}
    </div>
  );
}

/** Above every page: the demo banner when the data is made up, the not-connected notice on the pages that show a fleet. */
export function FleetBanners({ route, info }: { route: Route; info: Info | null }) {
  const demo = isDemo(info);
  const nc = fleetNotConnected(info) && showsFleetNotice(route);
  if (!demo && !nc) return null;
  return <div className="px-4 pt-2 sm:px-6 sm:pt-3 xl:px-8">{demo ? <DemoBanner /> : <FleetNotConnectedNotice info={info} />}</div>;
}

/** What opens instead of a flow that would change a fleet (create, pause, resize, clone, destroy). */
export function FleetNotConnectedSheet({ open, onClose, info }: { open: boolean; onClose: () => void; info: Info | null }) {
  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="fleet-not-connected-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('fleetnote.sheet_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('fleetnote.sheet_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody>
          <FleetNotConnectedNotice info={info} />
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button className="max-lg:h-11" onClick={onClose}>
            {t('common.close')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
