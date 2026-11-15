import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import type { RequestCard, ViewerRole } from '../../api/approval-requests';
import { decisionLine, isOpen, originText, readOnly, refusals, requesterFacts, ruleFor, ruleText, scopeName, shortDigest, sourceLabel, stateLabel, stateVariant, timeText } from '../../lib/approval-requests';
import { t } from '../../lib/i18n';

// Every string on a card was cleaned by the server and is drawn here as text: nothing below renders markup.
const WRAP = '[overflow-wrap:anywhere]';

export interface RequestCardProps {
  card: RequestCard;
  role: ViewerRole | null;
  now: number;
  /** The card a chat link pointed at. */
  highlighted?: boolean;
  busy?: boolean;
  onApprove: (card: RequestCard) => void;
  onDeny: (card: RequestCard) => void;
}

/** One change request: who asked, every row the service says it changes, how it ends, and what the viewer may do. */
export function ChangeRequestCard({ card, role, now, highlighted = false, busy = false, onApprove, onDeny }: RequestCardProps) {
  const scope = scopeName(card.scope);
  const facts = requesterFacts(card.requester);
  const rule = ruleText(ruleFor(card, role));
  const time = timeText(card, now);
  const decision = decisionLine(card);
  const refused = refusals(card);
  const canApprove = card.state === 'pending' && card.can.approve.allowed;
  const canDeny = isOpen(card.state) && card.can.deny.allowed;
  const read = isOpen(card.state) && readOnly(card);

  return (
    <Card
      id={`request-${card.id}`}
      data-testid="request-card"
      data-request-id={card.id}
      data-state={card.state}
      aria-label={t('areq.card_label', { scope })}
      className={`min-w-0 space-y-3 p-4 ${highlighted ? 'ring-2 ring-primary' : ''}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <h3 className={`text-sm font-semibold ${WRAP}`} data-testid="request-scope">
            {scope}
          </h3>
          <p className={`text-xs text-muted-foreground ${WRAP}`} data-testid="request-digest">
            {t('areq.digest', { digest: shortDigest(card.subject_digest) })} · {t('areq.origin')}: {originText(card.origin)}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant={stateVariant(card.state)} data-testid="request-state">
            {stateLabel(card.state)}
          </Badge>
          {rule ? (
            <Badge variant="outline" data-testid="request-rule">
              {rule}
            </Badge>
          ) : null}
          {read ? (
            <Badge variant="outline" data-testid="request-read-only">
              {t('areq.read_only')}
            </Badge>
          ) : null}
        </div>
      </div>

      {card.display.length > 0 ? (
        <dl className="space-y-2" aria-label={t('areq.rows')} data-testid="request-rows">
          {card.display.map((row, i) => (
            <div key={`${i}-${row.label}`} className="min-w-0" data-testid="request-row">
              <dt className={`text-xs text-muted-foreground ${WRAP}`}>{row.label}</dt>
              <dd className={`whitespace-pre-wrap text-sm font-medium ${WRAP}`}>{row.value}</dd>
              <dd className="text-xs text-muted-foreground" data-testid="request-row-source">
                {t('areq.row_source', { source: sourceLabel(row.source) })}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}

      {card.reason !== null && card.reason !== '' ? (
        <figure className="min-w-0 space-y-0.5" data-testid="request-reason">
          <figcaption className="text-xs text-muted-foreground">{t('areq.reason_label')}</figcaption>
          <blockquote className={`border-l-2 pl-3 text-sm ${WRAP}`}>{t('areq.reason_quote', { reason: card.reason })}</blockquote>
        </figure>
      ) : null}

      <div className="min-w-0" data-testid="request-requester">
        <p className="text-xs text-muted-foreground">{t('areq.requester')}</p>
        <dl className="mt-0.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-sm">
          {facts.map((f) => (
            <div key={f.key} className="contents" data-testid={`request-requester-${f.key}`}>
              <dt className="text-xs text-muted-foreground">{f.label}</dt>
              <dd className={`${WRAP} ${f.claimed ? 'italic' : 'font-medium'}`}>{f.value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {time ? (
        <p className="text-xs text-muted-foreground" data-testid="request-time">
          {time}
        </p>
      ) : null}
      {decision ? (
        <p className={`text-sm font-medium ${WRAP}`} data-testid="request-decision">
          {decision}
        </p>
      ) : null}
      {card.void_reason ? <p className={`text-xs text-muted-foreground ${WRAP}`}>{t('areq.void_reason', { reason: card.void_reason })}</p> : null}
      {card.replaces ? <p className={`text-xs text-muted-foreground ${WRAP}`}>{t('areq.replaces', { id: card.replaces })}</p> : null}
      {card.superseded_by ? <p className={`text-xs text-muted-foreground ${WRAP}`}>{t('areq.superseded_by', { id: card.superseded_by })}</p> : null}

      {refused.length > 0 ? (
        <ul className="space-y-1" data-testid="request-refusals">
          {refused.map((r) => (
            <li key={r} className={`text-sm text-muted-foreground ${WRAP}`} data-testid="request-refusal">
              {r}
            </li>
          ))}
        </ul>
      ) : null}

      {canApprove || canDeny ? (
        <div className="flex flex-col gap-2 sm:flex-row">
          {canApprove ? (
            <Button className="w-full max-lg:h-11 sm:w-auto" disabled={busy} onClick={() => onApprove(card)} data-testid="request-approve">
              {t('areq.approve')}
            </Button>
          ) : null}
          {canDeny ? (
            <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" disabled={busy} onClick={() => onDeny(card)} data-testid="request-deny">
              {card.state === 'approved' ? t('areq.revoke') : t('areq.deny')}
            </Button>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
