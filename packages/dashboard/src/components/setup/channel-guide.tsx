import type { MessageKey } from '../../lib/i18n';
import { t } from '../../lib/i18n';

export type GuideChannel =
  | 'email'
  | 'telegram'
  | 'slack'
  | 'webhook'
  | 'sign_in'
  | 'whatsapp'
  | 'discord'
  | 'teams'
  | 'push'
  | 'email_resend'
  | 'email_smtp'
  | 'email_ses'
  | 'email_postmark'
  | 'email_sendgrid'
  | 'sms_twilio'
  | 'sms_vonage'
  | 'sms_sns'
  | 'sms_africas_talking'
  | 'sms_telnyx';

const GUIDES: Record<GuideChannel, { title: MessageKey; steps: MessageKey[] }> = {
  email: { title: 'guide.email_title', steps: ['guide.email_1', 'guide.email_2', 'guide.email_3', 'guide.email_4'] },
  telegram: { title: 'guide.telegram_title', steps: ['guide.telegram_1', 'guide.telegram_2', 'guide.telegram_3', 'guide.telegram_4'] },
  slack: { title: 'guide.slack_title', steps: ['guide.slack_1', 'guide.slack_2', 'guide.slack_3', 'guide.slack_4'] },
  webhook: { title: 'guide.webhook_title', steps: ['guide.webhook_1', 'guide.webhook_2', 'guide.webhook_3'] },
  sign_in: { title: 'guide.sign_in_title', steps: ['guide.sign_in_1', 'guide.sign_in_2', 'guide.sign_in_3'] },
  whatsapp: { title: 'wa.guide_title', steps: ['wa.guide_1', 'wa.guide_2', 'wa.guide_3', 'wa.guide_4'] },
  discord: { title: 'discord.guide_title', steps: ['discord.guide_1', 'discord.guide_2'] },
  teams: { title: 'teams.guide_title', steps: ['teams.guide_1', 'teams.guide_2'] },
  push: { title: 'push.guide_title', steps: ['push.guide_1', 'push.guide_2', 'push.guide_3'] },
  email_resend: { title: 'em.guide_resend_title', steps: ['em.guide_resend_1', 'em.guide_resend_2', 'em.guide_resend_3'] },
  email_smtp: { title: 'em.guide_smtp_title', steps: ['em.guide_smtp_1', 'em.guide_smtp_2', 'em.guide_smtp_3'] },
  email_ses: { title: 'em.guide_ses_title', steps: ['em.guide_ses_1', 'em.guide_ses_2', 'em.guide_ses_3'] },
  email_postmark: { title: 'em.guide_postmark_title', steps: ['em.guide_postmark_1', 'em.guide_postmark_2', 'em.guide_postmark_3'] },
  email_sendgrid: { title: 'em.guide_sendgrid_title', steps: ['em.guide_sendgrid_1', 'em.guide_sendgrid_2'] },
  sms_twilio: { title: 'sms.guide_title', steps: ['sms.guide_twilio_1', 'sms.guide_twilio_2', 'sms.guide_twilio_3', 'sms.guide_twilio_4'] },
  sms_vonage: { title: 'sms.guide_title', steps: ['sms.guide_vonage_1', 'sms.guide_vonage_2', 'sms.guide_vonage_3'] },
  sms_sns: { title: 'sms.guide_title', steps: ['sms.guide_sns_1', 'sms.guide_sns_2', 'sms.guide_sns_3', 'sms.guide_sns_4'] },
  sms_africas_talking: { title: 'sms.guide_title', steps: ['sms.guide_africas_talking_1', 'sms.guide_africas_talking_2', 'sms.guide_africas_talking_3', 'sms.guide_africas_talking_4'] },
  sms_telnyx: { title: 'sms.guide_title', steps: ['sms.guide_telnyx_1', 'sms.guide_telnyx_2', 'sms.guide_telnyx_3'] },
};

/** Step by step, in plain words, how to create the thing yourself. Every integration is bring-your-own: Oz Box ships no
 * shared bot, app or account, and the credential you get goes into the secret store write-only. */
export function ChannelGuide({ channel }: { channel: GuideChannel }) {
  const g = GUIDES[channel];
  return (
    <details className="rounded-md border text-sm" data-testid={`guide-${channel.startsWith('email_') ? 'email' : channel.startsWith('sms_') ? 'sms' : channel}`}>
      <summary className="flex min-h-11 cursor-pointer items-center px-3 font-medium lg:min-h-9">
        <span className="sr-only">{t('guide.show')}: </span>
        {t(g.title)}
      </summary>
      <ol className="list-decimal space-y-1.5 px-3 pb-3 pl-8 text-muted-foreground">
        {g.steps.map((k) => (
          <li key={k}>{t(k)}</li>
        ))}
      </ol>
    </details>
  );
}
