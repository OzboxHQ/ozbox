/** The settings and status of the alert channels and of per-person routing. */

export type EmailProvider = 'resend' | 'smtp' | 'ses' | 'postmark' | 'sendgrid';
export type SmtpSecurity = 'tls' | 'starttls';
export type SmsProvider = 'twilio' | 'vonage' | 'sns' | 'africas_talking' | 'telnyx';

export interface SmtpConfig {
  host: string;
  port: number;
  security: SmtpSecurity;
  username: string;
}

export interface SmsConfig {
  enabled: boolean;
  provider: SmsProvider;
  from: string;
  region: string | null;
  sandbox: boolean;
}

export interface WhatsappConfig {
  enabled: boolean;
  phone_number_id: string;
  template: string;
  language: string;
}

export interface PushDevice {
  id: string;
  label: string;
  host: string;
}

export interface Route {
  channels: string[];
  bypass_quiet: boolean;
}

export interface DigestRoute {
  enabled: boolean;
  time: string;
  channels: string[];
}

export interface PersonRouting {
  time_zone: string | null;
  quiet_from: string | null;
  quiet_to: string | null;
  phone: string | null;
  whatsapp: string | null;
  emails: string[];
  push: PushDevice[];
  urgent: Route;
  normal: Route;
  digest: DigestRoute;
  /** A rule for one kind of alert (only `schedule` today): follow the urgent or normal route, or `off`. No entry = the alert's own severity. */
  kind_routes?: Record<string, 'urgent' | 'normal' | 'off'>;
}

export interface RoutingConfig {
  people: Record<string, PersonRouting>;
}

export interface ChannelStatus {
  enabled: boolean;
  configured: boolean;
}

export interface ChannelsStatus {
  sms: ChannelStatus & { provider: SmsProvider };
  whatsapp: ChannelStatus;
  discord: ChannelStatus;
  teams: ChannelStatus;
  push: ChannelStatus & { devices: number };
  people: { id: string; label: string }[];
}
