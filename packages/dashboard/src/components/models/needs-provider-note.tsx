import { t } from '../../lib/i18n';

/** The id of the Models page's "Add provider" button, which the note's link moves to. */
export const ADD_PROVIDER_ID = 'models-add-provider';

/**
 * Why a card's Edit is unavailable, said next to it: nothing can be chosen until a provider is set up. The link moves focus
 * to the page's "Add provider" button (an in-page link, so it also works without script), 44px tall below `lg`.
 */
export function NeedsProviderNote({ id }: { id: string }) {
  return (
    <p id={id} className="text-xs text-muted-foreground" data-testid="needs-provider" role="note">
      {t('models.needs_provider')}{' '}
      <a
        href={`#${ADD_PROVIDER_ID}`}
        className="inline-flex min-h-11 items-center text-primary underline underline-offset-4 lg:min-h-0"
        onClick={(e) => {
          const target = document.getElementById(ADD_PROVIDER_ID);
          if (!target) return;
          e.preventDefault();
          target.scrollIntoView({ block: 'center' });
          target.focus();
        }}
      >
        {t('models.needs_provider_link')}
      </a>
    </p>
  );
}
