import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Textarea } from '@/components/ui/textarea';
import { t } from '../../lib/i18n';

/**
 * The paste box for a browser that will not let the page read the clipboard. A keyboard paste (Ctrl or Cmd+V) or a
 * long-press Paste works into a text box in every browser, so the text is pasted here, then sent to the shell.
 */
export function PasteSheet({ onSend, onClose, returnFocus }: { onSend: (text: string) => void; onClose: () => void; returnFocus: () => void }) {
  const [text, setText] = useState('');
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent
        size="compact"
        data-testid="paste-sheet"
        onCloseAutoFocus={(e) => {
          // focus goes back to the terminal, where the person is typing, not to the Paste button
          e.preventDefault();
          returnFocus();
        }}
      >
        <PanelSheetHeader>
          <PanelSheetTitle>{t('terminal.paste_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('terminal.paste_help')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody>
          <Textarea
            autoFocus
            value={text}
            onChange={(e) => setText(e.target.value)}
            aria-label={t('terminal.paste_label')}
            className="min-h-40 font-mono text-xs"
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
            data-testid="paste-box"
          />
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" onClick={onClose}>
            {t('terminal.paste_cancel')}
          </Button>
          <Button className="max-lg:h-11" disabled={!text} onClick={() => onSend(text)} data-testid="paste-send">
            {t('terminal.paste_send')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
