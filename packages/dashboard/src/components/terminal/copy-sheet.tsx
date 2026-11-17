import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Textarea } from '@/components/ui/textarea';
import { t } from '../../lib/i18n';

/**
 * The text on the terminal's screen, in a box the browser lets anyone select from: a phone or a tablet (press and hold), a
 * screen reader, or a mouse when the program on the box has the mouse. Opened by Copy when nothing is selected.
 */
export function CopySheet({ text, onCopyAll, onClose, returnFocus }: { text: string; onCopyAll: () => void; onClose: () => void; returnFocus: () => void }) {
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent
        size="compact"
        data-testid="copy-sheet"
        onCloseAutoFocus={(e) => {
          e.preventDefault();
          returnFocus();
        }}
      >
        <PanelSheetHeader>
          <PanelSheetTitle>{t('terminal.copy_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('terminal.copy_help')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody>
          <Textarea
            readOnly
            value={text}
            aria-label={t('terminal.copy_label')}
            className="min-h-60 font-mono text-xs"
            spellCheck={false}
            data-testid="copy-box"
          />
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" onClick={onClose}>
            {t('terminal.copy_close')}
          </Button>
          <Button className="max-lg:h-11" disabled={!text} onClick={onCopyAll} data-testid="copy-all">
            {t('terminal.copy_all')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
